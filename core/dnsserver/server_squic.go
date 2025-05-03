package dnsserver

import (
	"context"
	"fmt"
	"net"

	"github.com/netsec-ethz/scion-apps/pkg/pan"

	"github.com/coredns/coredns/plugin/pkg/transport"

	"github.com/quic-go/quic-go"
)

// ServerSQUIC represents an instance of a SCION DNS-over-QUIC server.
type ServerSQUIC struct {
	*ServerQUIC
	ql *pan.QUICListener // wrapper around quic.Listener which is only required for later cleanup
}

// NewServerQUIC returns a new CoreDNS QUIC server and compiles all plugin in to it.
func NewServerSQUIC(addr string, group []*Config) (*ServerSQUIC, error) {
	// delegating constructor (there's nothing SCION/IP specific happening on construction,
	// so impl. can be shared )
	if s, err := NewServerQUIC(addr, group); err != nil {
		return nil, err
	} else {
		return &ServerSQUIC{s, nil}, nil
	}
}

// ServePacket implements caddy.UDPServer interface.
func (s *ServerSQUIC) ServePacket(p net.PacketConn) error {

	//l, err := pan.ListenQUIC2(p, s.tlsConfig, s.quicConfig)
	listener, err := quic.Listen(p, s.tlsConfig, s.quicConfig)
	if err != nil {
		p.Close()
		return err
	}

	s.quicListener = listener
	s.ql = &pan.QUICListener{
		Listener: listener,
		Conn:     p,
	}

	// ultimately calls ServeQUIC
	return s.ServerQUIC.ServePacket(p)
}

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

	pconn, e := pan.ListenUDP(context.Background(), ipport)

	if e != nil {
		return nil, e
	}
	return pconn, nil
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

// Stop stops the server non-gracefully. It blocks until the server is totally stopped.
func (s *ServerSQUIC) Stop() error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.ql != nil {
		// closes the quic.Listener as well as the net.PacketConn
		return s.ql.Close()
	}

	return nil
}
