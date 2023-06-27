package dnsutil

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

func IsSCIONAddress(address string) bool {
	_, err := pan.ParseUDPAddr(address)
	return err == nil
}

func AddressToReverse(address string) (string, error) {
	if IsSCIONAddress(address) {
		return ReverseSCIONAddr(address)

	}
	if ip4 := ParseIPv4(address); ip4 != nil {
		return InvertIPv4(address)

	}
	if ip6 := ParseIPv6(address); ip6 != nil {
		return InvertIPv6(address)
	}
	return "", errors.New("invalid address passed. Neither ipv4/6 nor scion")
}

// ExtractAddressFromReverse turns a standard PTR reverse record name
// into an IP address or SCION address. This works for ipv4 or ipv6.
//
// 54.119.58.176.in-addr.arpa. becomes 176.58.119.54.
// 1.0.0.127.in-addr.19-ffaa-1-1067.scion.arpa. => 19-ffaa:1:1067,[127.0.0.1]
// If the conversion fails the empty string is returned.
func ExtractAddressFromReverse(reverseName string) string {
	search := ""

	f := reverse

	switch {
	case strings.HasSuffix(reverseName, IP4arpa):
		search = strings.TrimSuffix(reverseName, IP4arpa)
	case strings.HasSuffix(reverseName, IP6arpa):
		search = strings.TrimSuffix(reverseName, IP6arpa)
		f = reverse6
	case strings.HasSuffix(reverseName, SCIONarpa):

		return UnReverseSCION(reverseName)

	default:
		return ""
	}

	// Reverse the segments and then combine them.
	return f(strings.Split(search, "."))
}

// IsReverse returns 0 is name is not in a reverse zone. Anything > 0 indicates
// name is in a reverse zone. The returned integer will be 1 for in-addr.arpa. (IPv4)
// and 2 for ip6.arpa. (IPv6) 3 for .scion.arpa.
func IsReverse(name string) int {
	if strings.HasSuffix(name, IP4arpa) {
		return 1
	}
	if strings.HasSuffix(name, IP6arpa) {
		return 2
	}
	if strings.HasSuffix(name, SCIONarpa) {
		return 3
	}
	return 0
}

func reverse(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	ip := net.ParseIP(strings.Join(slice, ".")).To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

// reverse6 reverse the segments and combine them according to RFC3596:
// b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
// is reversed to 2001:db8::567:89ab
func reverse6(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice6 := []string{}
	for i := 0; i < len(slice)/4; i++ {
		slice6 = append(slice6, strings.Join(slice[i*4:i*4+4], ""))
	}
	ip := net.ParseIP(strings.Join(slice6, ":")).To16()
	if ip == nil {
		return ""
	}
	return ip.String()
}

const (
	InAddr4 = ".in-addr."
	InAddr6 = ".ip6."

	// IP4arpa is the reverse tree suffix for v4 IP addresses.
	IP4arpa = ".in-addr.arpa."
	// IP6arpa is the reverse tree suffix for v6 IP addresses.
	IP6arpa = ".ip6.arpa."

	SCIONarpa = ".scion.arpa."
)

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// Hexadecimal to integer.
// Returns number, characters consumed, success.
func xtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n *= 16
			n += int(s[i] - '0')
		} else if 'a' <= s[i] && s[i] <= 'f' {
			n *= 16
			n += int(s[i]-'a') + 10
		} else if 'A' <= s[i] && s[i] <= 'F' {
			n *= 16
			n += int(s[i]-'A') + 10
		} else {
			break
		}
		if n >= big {
			return 0, i, false
		}
	}
	if i == 0 {
		return 0, i, false
	}
	return n, i, true
}

// Parse IPv4 address (d.d.d.d).
func ParseIPv4(s string) net.IP {
	var p [net.IPv4len]byte
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		if c > 1 && s[0] == '0' {
			// Reject non-zero components with leading zeroes.
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return net.IPv4(p[0], p[1], p[2], p[3])
}

// HostPart.IS-AS.scion.arpa. => IS-AS,[HostPart]
// TODO: better change signature to return (string, error)
func UnReverseSCION(revAddr string) string {
	// TODO: it would be better to have a designated IsReverseSCIONAddress(string) bool
	// that matches a regex here
	if !strings.HasSuffix(revAddr, SCIONarpa) {
		return revAddr
	}
	addr := strings.TrimSuffix(revAddr, SCIONarpa)

	if strings.Contains(addr, InAddr4) {
		token := strings.Split(addr, InAddr4)
		// we expect two token here: the left is the reversed HostPart, the right the IS-AS Part
		if len(token) != 2 {
			return revAddr
		}
		hostpart4 := reverse(strings.Split(token[0], "."))
		isasPart, e := uninvertISAS(token[1])
		if e == nil {
			return isasPart + "," + hostpart4
		} else {
			return revAddr
		}

	} else if strings.Contains(addr, InAddr6) {
		token := strings.Split(addr, InAddr6)
		// we expect two token here: the left is the reversed HostPart, the right the IS-AS Part
		if len(token) != 2 {
			return revAddr
		}

		hostpart6 := reverse6(strings.Split(token[0], "."))
		isasPart, e := uninvertISAS(token[1])
		if e == nil {
			return isasPart + "," + hostpart6
		} else {
			return revAddr
		}

	} else {

		return revAddr
	}
}

func invertISAS(s string) string {
	return strings.Replace(s, ":", "-", -1)
}

// converts 19-ffaa-1-1067 to 19-ffaa:1:1067
func uninvertISAS(invISAS string) (string, error) {
	if strings.Count(invISAS, "-") != 3 {
		return invISAS, errors.New("invalid string for reverse IS-AS")
	}

	return strings.Replace(strings.Replace(invISAS, "-", ":", -1), ":", "-", 1), nil
}

// computes the inverse address for rDNS lookup
// i.e. 19-ffaa:1:1067,[127.0.0.1] => 1.0.0.127.in-addr.19-ffaa-1-1067.scion.arpa.
// returns Address unchanged if its no valid SCION address
func ReverseSCIONAddr(scaddr string) (string, error) {
	addr, err := pan.ParseUDPAddr(scaddr)
	if err != nil {
		// if it wasnt a valid SCION address, we were passed
		// just act as the identity Fcn
		return scaddr, err
	}
	var invName string
	invIA := invertISAS(addr.IA.String())
	var revIP string
	if addr.IP.Is4() {
		str := addr.IP.String()
		revIP, err = InvertIPv4(str)
		if err != nil {
			return scaddr, err
		}
		invName = revIP + InAddr4 + invIA + SCIONarpa
		return invName, nil
	} else if addr.IP.Is6() {
		tmpIP, err := InvertIPv6(addr.IP.StringExpanded())
		if err != nil {
			return scaddr, err
		}
		revIP = strings.Replace(tmpIP, ":", ".", -1)
		invName = revIP + InAddr4 + invIA + SCIONarpa
		return invName, nil
	}
	return scaddr, errors.New("your AS's host addressing scheme is neither IPv4 nor 6 and not supported for rDNS lookup yet")
}

func ParseIPv6(s string) (ip net.IP) {
	ip = make(net.IP, net.IPv6len)
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return ip
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i := 0
	for i < net.IPv6len {
		// Hex number.
		n, c, ok := xtoi(s)
		if !ok || n > 0xFFFF {
			return nil
		}

		// If followed by dot, might be in trailing IPv4.
		if c < len(s) && s[c] == '.' {
			if ellipsis < 0 && i != net.IPv6len-net.IPv4len {
				// Not the right place.
				return nil
			}
			if i+net.IPv4len > net.IPv6len {
				// Not enough room.
				return nil
			}
			ip4 := ParseIPv4(s)
			if ip4 == nil {
				return nil
			}
			ip[i] = ip4[12]
			ip[i+1] = ip4[13]
			ip[i+2] = ip4[14]
			ip[i+3] = ip4[15]
			s = ""
			i += net.IPv4len
			break
		}

		// Save this 16-bit chunk.
		ip[i] = byte(n >> 8)
		ip[i+1] = byte(n)
		i += 2

		// Stop at end of string.
		s = s[c:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' || len(s) == 1 {
			return nil
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return nil
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return nil
	}

	// If didn't parse enough, expand ellipsis.
	if i < net.IPv6len {
		if ellipsis < 0 {
			return nil
		}
		n := net.IPv6len - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return nil
	}
	return ip
}

func InvertIPv4(ip string) (invertedIP string, err error) {

	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("%v is not an IPV4", ip)
	}

	for i := 3; i >= 0; i-- {
		invertedIP += octets[i]
		if i != 0 {
			invertedIP += "."
		}
	}
	return invertedIP, nil
}

func InvertIPv6(ip string) (invertedIP string, err error) {

	octets := strings.Split(ip, ":")
	if len(octets) != 15 {
		return "", fmt.Errorf("%v is not an IPV6", ip)
	}

	for i := 15; i >= 0; i-- {
		invertedIP += octets[i]
		if i != 0 {
			invertedIP += ":"
		}
	}
	return invertedIP, nil
}
