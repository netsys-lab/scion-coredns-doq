package file

import (
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"time"

	util "github.com/miekg/dns/dnsutil"

	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/miekg/dns"
	"github.com/miekg/dns/resolvapi"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"inet.af/netaddr"
)

// TransferIn retrieves the zone from the masters, parses it and sets it live.
func (z *Zone) TransferIn() error {
	if len(z.TransferFrom) == 0 {
		return nil
	}
	m := new(dns.Msg)
	m.SetAxfr(z.origin)

	z1 := z.CopyWithoutApex()
	var (
		Err error
		tr  string
	)

Transfer:
	for _, tr = range z.TransferFrom {
		// tr can be either IPv4/6 , SCION Address or domain-name or url i.e. squic://ns1.exmple.org:8853

		t := new(dns.Transfer)
		var client *dns.Client
		var netw string = "udp"
		var tlsCfg *tls.Config

		if _, ok := dns.IsDomainName(tr); ok {
			// we only have the domain-name of out primary NS
			// so we need to resolve it first
		}

		if u, e := url.Parse(tr); e == nil {

			netw = u.Scheme
			host, p, e := net.SplitHostPort(u.Host)
			if e != nil {
				return e
			}

			// if 'host' has only IPv4/6 addresses, they are resolved by net.Dialer )DialContext
			// in Client.Dial automatically
			// only for SCION addresses the host might potentially have we need to do this ourselves
			scaddrs, err := resolvapi.LookupSCIONAddress(host)
			if err != nil {
				// resolution failed, probably because scion capable sdns resolver is not running locally
				if netw == "squic" {
					// we wanted to dial primary with SCION, but didnt get its SCION address, how sad
					return err
				}
				goto dialPrimary // fallback to old legacy way of things
			}
			if len(scaddrs) == 0 {
				if netw == "squic" {
					return errors.New("schema is squic:// but no SCION Address could be resolved for host")
				}
				goto dialPrimary
			}
			tlsCfg = z.Config.TLSConfigQUIC.Clone()
			tlsCfg.ServerName = host

			if p != "" {
				port, eee := strconv.Atoi(p)
				if eee != nil {
					return eee
				}

				tr = util.WithPortIfNotSet(scaddrs[0], port)

			} else {
				// use the default SCION DoQ Port if none was given
				tr = util.WithPortIfNotSet(scaddrs[0], 8853)

			}

		}

		if _, er := pan.ParseUDPAddr(tr); er == nil {
			netw = "squic"
			tlsCfg = z.Config.TLSConfigQUIC.Clone()
			//tlsCfg.ServerName = "localhost"
			// Check if we find our primary Server in hosts file
			// otherwise the Client does the lookup in DialContext()
			if result, err := z.LookupInHosts(tr); err == nil {
				tlsCfg.ServerName = result
			} else { // (be a good proggy,do not rely on knowledge about dns.Client impl and lookup the servername ourselves)
				if hostname, err := resolvapi.XLookupStub(tr); err == nil {
					tlsCfg.ServerName = hostname
				} else {
					// there would be no point in dialing the primary,
					// as without its serverName in the tlsCfg the handshake would fail anyway
					return err
				}
			}
		}

		if _, er := netaddr.ParseIPPort(tr); er == nil {
			// tr is an ordenary IPv4/6 address, so nothing to do
			goto dialPrimary
		}

	dialPrimary:
		client = &dns.Client{Net: netw, TLSConfig: tlsCfg}
		var e error
		t.Conn, e = client.Dial(tr)
		if e != nil {
			return e
		}
		c, err := t.In(m, tr)
		if err != nil {
			log.Errorf("Failed to setup transfer `%s' with `%q': %v", z.origin, tr, err)
			Err = err
			continue Transfer
		}
		for env := range c {
			if env.Error != nil {
				log.Errorf("Failed to transfer `%s' from %q: %v", z.origin, tr, env.Error)
				Err = env.Error
				continue Transfer
			}
			for _, rr := range env.RR {
				if err := z1.Insert(rr); err != nil {
					log.Errorf("Failed to parse transfer `%s' from: %q: %v", z.origin, tr, err)
					Err = err
					continue Transfer
				}
			}
		}
		Err = nil
		break
	}
	if Err != nil {
		return Err
	}

	z.Lock()
	z.Tree = z1.Tree
	z.Apex = z1.Apex
	z.Expired = false
	z.Unlock()
	log.Infof("Transferred: %s from %s", z.origin, tr)
	return nil
}

// shouldTransfer checks the primaries of zone, retrieves the SOA record, checks the current serial
// and the remote serial and will return true if the remote one is higher than the locally configured one.
func (z *Zone) shouldTransfer() (bool, error) {
	var c *dns.Client

	m := new(dns.Msg)
	m.SetQuestion(z.origin, dns.TypeSOA)

	var Err error
	serial := -1

Transfer:
	for _, tr := range z.TransferFrom {
		Err = nil

		if dnsutil.IsSCIONAddress(tr) {
			tlsCfg := z.Config.TLSConfigQUIC.Clone()

			// Check if we find our primary Server in hosts file
			if result, err := z.LookupInHosts(tr); err == nil {
				tlsCfg.ServerName = result
			}

			// otherwise the Client does the lookup in DialContext()
			c = &dns.Client{Net: "squic", TLSConfig: tlsCfg}
		} else {
			c = new(dns.Client)
			c.Net = "tcp" // do this query over TCP to minimize spoofing
		}

		ret, _, err := c.Exchange(m, tr)
		if err != nil || ret.Rcode != dns.RcodeSuccess {
			Err = err
			continue
		}
		for _, a := range ret.Answer {
			if a.Header().Rrtype == dns.TypeSOA {
				serial = int(a.(*dns.SOA).Serial)
				break Transfer
			}
		}
	}
	if serial == -1 {
		return false, Err
	}
	if z.Apex.SOA == nil {
		return true, Err
	}
	return less(z.Apex.SOA.Serial, uint32(serial)), Err
}

// less returns true of a is smaller than b when taking RFC 1982 serial arithmetic into account.
func less(a, b uint32) bool {
	if a < b {
		return (b - a) <= MaxSerialIncrement
	}
	return (a - b) > MaxSerialIncrement
}

// Update updates the secondary zone according to its SOA. It will run for the life time of the server
// and uses the SOA parameters. Every refresh it will check for a new SOA number. If that fails (for all
// server) it will retry every retry interval. If the zone failed to transfer before the expire, the zone
// will be marked expired.
func (z *Zone) Update() error {
	// If we don't have a SOA, we don't have a zone, wait for it to appear.
	for z.Apex.SOA == nil {
		time.Sleep(1 * time.Second)
	}
	retryActive := false

Restart:
	refresh := time.Second * time.Duration(z.Apex.SOA.Refresh)
	retry := time.Second * time.Duration(z.Apex.SOA.Retry)
	expire := time.Second * time.Duration(z.Apex.SOA.Expire)

	refreshTicker := time.NewTicker(refresh)
	retryTicker := time.NewTicker(retry)
	expireTicker := time.NewTicker(expire)

	for {
		select {
		case <-expireTicker.C:
			if !retryActive {
				break
			}
			z.Expired = true

		case <-retryTicker.C:
			if !retryActive {
				break
			}

			time.Sleep(jitter(2000)) // 2s randomize

			ok, err := z.shouldTransfer()
			if err != nil {
				log.Warningf("Failed retry check %s", err)
				continue
			}

			if ok {
				if err := z.TransferIn(); err != nil {
					// transfer failed, leave retryActive true
					break
				}
			}

			// no errors, stop timers and restart
			retryActive = false
			refreshTicker.Stop()
			retryTicker.Stop()
			expireTicker.Stop()
			goto Restart

		case <-refreshTicker.C:

			time.Sleep(jitter(5000)) // 5s randomize

			ok, err := z.shouldTransfer()
			if err != nil {
				log.Warningf("Failed refresh check %s", err)
				retryActive = true
				continue
			}

			if ok {
				if err := z.TransferIn(); err != nil {
					// transfer failed
					retryActive = true
					break
				}
			}

			// no errors, stop timers and restart
			retryActive = false
			refreshTicker.Stop()
			retryTicker.Stop()
			expireTicker.Stop()
			goto Restart
		}
	}
}

// jitter returns a random duration between [0,n) * time.Millisecond
func jitter(n int) time.Duration {
	r := rand.Intn(n)
	return time.Duration(r) * time.Millisecond
}

// MaxSerialIncrement is the maximum difference between two serial numbers. If the difference between
// two serials is greater than this number, the smaller one is considered greater.
const MaxSerialIncrement uint32 = 2147483647
