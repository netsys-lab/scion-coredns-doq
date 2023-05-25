// Package proxy implements a forwarding proxy. It caches an upstream net.Conn for some time, so if the same
// client returns the upstream's Conn will be precached. Depending on how you benchmark this looks to be
// 50% faster than just opening a new connection for every client. It works with UDP and TCP and uses
// inband healthchecking.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/netsec-ethz/scion-apps/pkg/pan"

	"github.com/miekg/dns"
)

// limitTimeout is a utility function to auto-tune timeout values
// average observed time is moved towards the last observed delay moderated by a weight
// next timeout to use will be the double of the computed average, limited by min and max frame.
func limitTimeout(currentAvg *int64, minValue time.Duration, maxValue time.Duration) time.Duration {
	rt := time.Duration(atomic.LoadInt64(currentAvg))
	if rt < minValue {
		return minValue
	}
	if rt < maxValue/2 {
		return 2 * rt
	}
	return maxValue
}

func averageTimeout(currentAvg *int64, observedDuration time.Duration, weight int64) {
	dt := time.Duration(atomic.LoadInt64(currentAvg))
	atomic.AddInt64(currentAvg, int64(observedDuration-dt)/weight)
}

func (t *Transport) dialTimeout() time.Duration {
	return limitTimeout(&t.avgDialTime, minDialTimeout, maxDialTimeout)
}

func (t *Transport) updateDialTimeout(newDialTime time.Duration) {
	averageTimeout(&t.avgDialTime, newDialTime, cumulativeAvgWeight)
}

// Dial dials the address configured in transport, potentially reusing a connection or creating a new one.
func (t *Transport) Dial(proto string) (*persistConn, bool, error) {
	// If tls has been configured; use it.
	if t.tlsConfig != nil {
		proto = "tcp-tls"
	}

	t.dial <- proto
	pc := <-t.ret

	if pc != nil {
		ConnCacheHitsCount.WithLabelValues(t.addr, proto).Add(1)
		return pc, true, nil
	}
	ConnCacheMissesCount.WithLabelValues(t.addr, proto).Add(1)

	reqTime := time.Now()
	timeout := t.dialTimeout()
	if proto == "tcp-tls" {
		conn, err := dns.DialTimeoutWithTLS("tcp", t.addr, t.tlsConfig, timeout)
		t.updateDialTimeout(time.Since(reqTime))
		return &persistConn{c: conn}, false, err
	}
	conn, err := dns.DialTimeout(proto, t.addr, timeout)
	t.updateDialTimeout(time.Since(reqTime))
	return &persistConn{c: conn}, false, err
}

// Connect selects an upstream, sends the request and waits for a response.
func (p *Proxy) Connect(ctx context.Context, state request.Request, opts Options) (*dns.Msg, error) {
	start := time.Now()

	proto := ""
	switch {
	case opts.ForceTCP: // TCP flag has precedence over UDP flag
		proto = "tcp"
	case opts.PreferUDP:
		proto = "udp"
	default:
		proto = state.Proto()
	}
	// if server is listening on SCION Address i.e. squic://19-ffaa:1:1067,127.0.0.1:8853  opts.transport is 'squic'.
	// The Proxy 'p' might have another though

	// only if proxy's Address can successfully be parsed to a SCION pan.UDPAddr
	// it really is a SCION server himself
	if _, ok := pan.ParseUDPAddr(p.Addr()); ok == nil {
		fmt.Printf("forwarded to SCION proxy: %v \n", p.Addr())
	} else {
		// Server and Proxy/Forwarder dont use the same Transport
		// so parse it from Proxy's URL

		var proxy_proto *url.URL
		var err error
		proxy_proto, err = url.Parse(p.addr)
		if err == nil {
			proto = proxy_proto.Scheme
		} else { // anything that doesnt specify a scheme i.e. 8.8.8.8 will default to dns://8.8.8.8 plain old UDP
			proto = "udp"
		}
	}

	pc, cached, err := p.transport.Dial(proto)
	if err != nil {
		return nil, err
	}

	// Set buffer size correctly for this client.
	pc.c.UDPSize = uint16(state.Size())
	if pc.c.UDPSize < 512 {
		pc.c.UDPSize = 512
	}

	pc.c.SetWriteDeadline(time.Now().Add(maxTimeout))
	// records the origin Id before upstream.
	originId := state.Req.Id
	state.Req.Id = dns.Id()
	defer func() {
		state.Req.Id = originId
	}()

	if err := pc.c.WriteMsg(state.Req); err != nil {
		pc.c.Close() // not giving it back
		if err == io.EOF && cached {
			return nil, ErrCachedClosed
		}
		return nil, err
	}

	var ret *dns.Msg
	pc.c.SetReadDeadline(time.Now().Add(p.readTimeout))
	for {
		ret, err = pc.c.ReadMsg()
		if err != nil {
			// For UDP, if the error is not a network error keep waiting for a valid response to prevent malformed
			// spoofs from blocking the upstream response.
			// In the case this is a legitimate malformed response from the upstream, this will result in a timeout.
			if proto == "udp" {
				// fmt.Printf("is TimeoutError: %v", err.(net.Error).Timeout())
				if _, ok := err.(net.Error); !ok {
					continue
				}
			}
			pc.c.Close() // connection closed by peer, close the persistent connection
			if err == io.EOF && cached {
				return nil, ErrCachedClosed
			}

			// recover the origin Id after upstream.
			if ret != nil {
				ret.Id = originId
			}
			return ret, err
		}
		// drop out-of-order responses
		if state.Req.Id == ret.Id {
			break
		}
	}
	// recovery the origin Id after upstream.
	ret.Id = originId

	p.transport.Yield(pc)

	rc, ok := dns.RcodeToString[ret.Rcode]
	if !ok {
		rc = strconv.Itoa(ret.Rcode)
	}

	RequestCount.WithLabelValues(p.addr).Add(1)
	RcodeCount.WithLabelValues(rc, p.addr).Add(1)
	RequestDuration.WithLabelValues(p.addr, rc).Observe(time.Since(start).Seconds())

	return ret, nil
}

const cumulativeAvgWeight = 4
