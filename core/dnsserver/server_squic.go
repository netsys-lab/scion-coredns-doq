package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/miekg/dns"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
)

/*
// maxQuicIdleTimeout - maximum QUIC idle timeout.
// Default value in quic-go is 30, but our internal tests show that
// a higher value works better for clients written with ngtcp2
const maxQuicIdleTimeout = 5 * time.Minute

const minDNSPacketSize = 12 + 5
*/

// Implemented according to https://tools.ietf.org/html/draft-huitema-dprive-dnsoquic-00
// ServerQUIC represents an instance of a DNS-over-QUIC server.
type ServerSQUIC struct {
	*Server
	tlsConfig  *tls.Config
	listen     quic.Listener
	listenAddr net.Addr
	// add *quic.Conf here
	bytesPool *sync.Pool
}

// NewServerQUIC returns a new CoreDNS QUIC server and compiles all plugin in to it.
func NewServerSQUIC(addr string, group []*Config) (*ServerSQUIC, error) {
	s, err := NewServer(addr, group)
	if err != nil {
		return nil, err
	}
	// The *tls* plugin must make sure that multiple conflicting
	// TLS configuration return an error: it can only be specified once.
	var tlsConfig *tls.Config
	for _, z := range s.zones {
		for _, conf := range z {
			// Should we error if some configs *don't* have TLS?
			tlsConfig = conf.TLSConfigQUIC
		}
	}

	bytesPool := sync.Pool{
		New: func() interface{} {
			return make([]byte, dns.MaxMsgSize)
		},
	}

	return &ServerSQUIC{Server: s, tlsConfig: tlsConfig, bytesPool: &bytesPool}, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &Server{}

// Serve implements caddy.TCPServer interface.
func (s *ServerSQUIC) Serve(_ net.Listener) error {
	return nil
}

// ServePacket implements caddy.UDPServer interface.
func (s *ServerSQUIC) ServePacket(p net.PacketConn) error {
	s.m.Lock()

	if s.tlsConfig == nil {
		return errors.New("cannot run a QUIC server without TLS config")
	}

	// l, err := quic.Listen(p, s.tlsConfig, &quic.Config{MaxIdleTimeout: maxQuicIdleTimeout})
	l, err := pan.ListenQUIC2(p, s.tlsConfig, &quic.Config{MaxIdleTimeout: maxQuicIdleTimeout})
	if err != nil {
		return err
	}
	s.listen = l
	s.listenAddr = l.Addr()
	s.m.Unlock()

	for {
		session, err := s.listen.Accept(context.Background())
		if err != nil {
			return err
		}

		go s.handleQUICSession(session)
	}
}

// Listen implements caddy.TCPServer interface.
func (s *ServerSQUIC) Listen() (net.Listener, error) { return nil, nil }

// ListenPacket implements caddy.UDPServer interface.
func (s *ServerSQUIC) ListenPacket() (net.PacketConn, error) {

	/*p, err := reuseport.ListenPacket("udp", s.Addr[len(transport.SQUIC+"://"):])
	     if err != nil {
			return nil, err
		 }

		  return p, nil
	*/
	//var ipport netaddr.IPPort
	//var parseerror error
	// s.Addr is something like "squic://:8853" if listening on localhost
	//ipport, parseerror := netaddr.ParseIPPort(s.Addr[len(transport.SQUIC+"://"):])
	ipport, parseerror := pan.ParseOptionalIPPort(s.Addr[len(transport.SQUIC+"://"):])
	if parseerror != nil {
		return nil, parseerror
	}

	pconn, e := pan.ListenUDP(context.Background(), ipport, pan.NewDefaultReplySelector())

	if e != nil {
		return nil, e
	}
	return pconn, nil
}

// Stop stops the server. It blocks until the server is totally stopped.
func (s *ServerSQUIC) Stop() error {
	s.m.Lock()
	defer s.m.Unlock()
	return s.listen.Close()
}

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming Quiet is false.
func (s *ServerSQUIC) OnStartupComplete() {
	if Quiet {
		return
	}

	out := startUpZones(transport.SQUIC+"://", s.Addr, s.zones)
	if out != "" {
		fmt.Print(out)
	}
}

func (s *ServerSQUIC) handleQUICSession(session quic.Connection) {
	for {
		// The stub to resolver DNS traffic follows a simple pattern in which
		// the client sends a query, and the server provides a response.  This
		// design specifies that for each subsequent query on a QUIC connection
		// the client MUST select the next available client-initiated
		// bidirectional stream
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Print("ERROR[session.AcceptStream]:" + err.Error())

			_ = session.CloseWithError(0, "")
			return
		}
		go func() {
			s.handleQUICStream(stream, session)
			_ = stream.Close()
		}()
	}
}

// handleQUICStream reads DNS queries from the stream, processes them,
// and writes back the responses
func (s *ServerSQUIC) handleQUICStream(stream quic.Stream, session quic.Connection) {
	// var b []byte
	var b []byte = s.bytesPool.Get().([]byte)
	defer s.bytesPool.Put(b)

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// FIN is indicated via error so we should simply ignore it and
	// check the size instead.
	n, _ := stream.Read(b)
	if n < minDNSPacketSize {
		// Invalid DNS query, this stream should be ignored
		return
	}

	msg := new(dns.Msg)
	msg_len := binary.BigEndian.Uint16(b[:2])
	if int(msg_len) != n-2 {
		panic(fmt.Sprintf("message size mismatch: %d vs %d", msg_len, n))
	}
	err := msg.Unpack(b[2:])
	if err != nil {
		fmt.Println(b[:n])
		// Invalid content
		fmt.Print("handleQUICStream encountered invalid content: " + err.Error())
		return
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				// Already closing the connection so we don't care about the error
				_ = session.CloseWithError(0, "")
			}
		}
	}

	// Consider renaming DoHWriter or creating a new struct for QUIC
	//dw := &DoHWriter{laddr: s.listenAddr, raddr: session.RemoteAddr(), proto: "squic"}
	//dw := &DoHWriter{laddr: s.listenAddr, raddr: session.RemoteAddr(), Writer: nonwriter.Writer{proto: "squic"}}
	dw := &DoHWriter{laddr: s.listenAddr, raddr: session.RemoteAddr()}

	// We just call the normal chain handler - all error handling is done there.
	// We should expect a packet to be returned that we can send to the client.
	ctx := context.WithValue(context.Background(), Key{}, s.Server)
	s.ServeDNS(ctx, dw, msg)

	if dw.Msg == nil {
		fmt.Println("message was nil -> stream closed!")
		_ = stream.Close()
		return
	}
	var response *dns.Msg = dw.Msg

	// Write the response
	buf, _ := response.Pack()
	/*
		testMsg := new(dns.Msg)
		unpackErr := testMsg.Unpack(buf)
		if unpackErr != nil {
			fmt.Printf("cant unpack our own response ->just about to reply shit to client\n")
		} else {
			fmt.Printf("deep equal: %v\n", reflect.DeepEqual(response.Answer, testMsg.Answer))
			fmt.Printf("nr of RRs in answer still equal: %v\n", len(response.Answer) == len(testMsg.Answer))
			var strEqual bool = true
			fmt.Print(response.Answer[0].String())
			for i := 0; i < len(response.Answer); i++ {
				strEqual = strEqual && response.Answer[i].String() == testMsg.Answer[i].String()
				strEqual = strEqual && strings.HasPrefix(response.Answer[i].String(), "dummy.luki.test.home.	604800	IN	A")
			}
			fmt.Printf("elementwise str-equal: %v\n", strEqual)
		}
	*/

	// fmt.Println("encoded response(without fst 2 bytes): ", buf)
	n, e := stream.Write(addPrefix(buf))
	fmt.Printf("wrote %d bytes to stream\n", len(buf)+2)

	if e != nil {
		fmt.Println(e.Error())

		if err, ok := e.(net.Error); ok {
			fmt.Printf("remote peer cancelled stream: %v\n", err.Error())
		}
		if err, ok := e.(*quic.StreamError); ok {
			fmt.Printf("remote peer cancelled stream: %v\n", err.Error())
		}
		if err, ok := e.(*quic.TransportError); ok {
			fmt.Printf("TransportError: %v\n", err.Error())
		}
		if err, ok := e.(*quic.ApplicationError); ok {
			fmt.Printf("ApplicationError: %v\n", err.Error())
		}

		if n != len(buf) {
			fmt.Printf("stream write failure! buffer had size %d but only %d was sent", len(buf), n)
			panic("EXIT FAILURE")

		}
	}
}

/*
// addPrefix adds a 2-byte prefix with the DNS message length.
func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}
*/
