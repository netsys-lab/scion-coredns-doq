package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

func (p Pair) signRRs(rrs []dns.RR, signerName string, ttl, incep, expir uint32) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG, Ttl: ttl},
		Algorithm:  p.Public.Algorithm,
		SignerName: signerName,
		KeyTag:     p.KeyTag,
		OrigTtl:    ttl,
		Inception:  incep,
		Expiration: expir,
	}

	e := rrsig.Sign(p.Private, rrs)
	return rrsig, e
}

// this should move into the miekg/dns package
// it is currently duplicated here and in exdns/q
func x509PubAlgoCodeToDNS(cert *x509.Certificate) (uint8, error) {

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:

		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA:
			return dns.RSASHA1, nil
		case x509.SHA256WithRSA:
			return dns.RSASHA256, nil
		//case x509.SHA384WithRSA:
		case x509.SHA512WithRSA:
			return dns.RSASHA512, nil
		case x509.MD5WithRSA:
			return dns.RSAMD5, nil
		}

		//dns.RSASHA1NSEC3SHA1

	case x509.ECDSA:

		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			return dns.ECDSAP256SHA256, nil
		case x509.ECDSAWithSHA384:
			return dns.ECDSAP384SHA384, nil
		}

	case x509.Ed25519:
		// assert SignatureAlgorithm is x509.PureEd25519 ?!
		return dns.ED25519, nil
	}

	return 0, fmt.Errorf("unsupported certificate PublicKeyAlgorithm: %s SignatureAlgorithm: %s",
		cert.PublicKeyAlgorithm.String(),
		cert.SignatureAlgorithm.String())
}

/* use the RHINE certs private key to sign the DNSKEY ( public zone key) of the zone (generate a RRSIG(DNSKEY) RR for the zone)
 */
func signZSK2(dnskey dns.RR, rcert *RCertPair, signerName string, ttl, incep, expir uint32, keytag uint16) (*dns.RRSIG, error) {

	algocode := dnskey.(*dns.DNSKEY).Algorithm
	if code, err := x509PubAlgoCodeToDNS(rcert.Rcert); err != nil {
		return nil, err
	} else {
		if code != algocode {
			return nil, errors.New("DNSkey RHINECert keytype mismatch")
		}
	}

	key := &dns.DNSKEY{Flags: 257, //256=Zone und 257=key
		Protocol:  3,
		Algorithm: algocode}

	key.Hdr = dns.RR_Header{Name: signerName,
		Rrtype: dns.TypeDNSKEY,
		Class:  dns.ClassINET,
		Ttl:    ttl}

	var pubkeybytes []byte
	pubkey := rcert.Rcert.PublicKey
	switch algocode {
	case dns.ECDSAP256SHA256:
		// pubkeybytes = elliptic.Marshal(elliptic.P256(), cert.PublicKey.(*ecdsa.PublicKey).X, cert.PublicKey.(*ecdsa.PublicKey).Y)
		pcdh, err := pubkey.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, err
		}
		pubkeybytes = pcdh.Bytes()
	case dns.ECDSAP384SHA384:
		pubkeybytes = elliptic.Marshal(elliptic.P384(), pubkey.(*ecdsa.PublicKey).X, pubkey.(*ecdsa.PublicKey).Y)
	case dns.ED25519:
		pubkeybytes = pubkey.(ed25519.PublicKey) //.([]byte)
	default:
		// FIXME: this is probably wrong ^^ with ECDSAP384 it produced length 120 bytes, instead of the expected 97
		_rawkeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
		if err != nil {
			return nil, err
		}
		pubkeybytes = _rawkeybytes
	}

	key.PublicKey = base64.StdEncoding.EncodeToString(pubkeybytes)

	rhineprivatekeytag := key.KeyTag()
	fmt.Printf("[INFO] RHINE public key keytag: %d  keylength: %d\n", rhineprivatekeytag, len(pubkeybytes))

	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG, Ttl: ttl},
		Algorithm:  algocode,
		SignerName: signerName,
		//KeyTag:     keytag, // FIXME i think this is a bug !!! we should use rcert.Private's keyTag instead. Not the keytag of the DNSKEY (zonekey) that is subject to signing
		KeyTag:     rhineprivatekeytag,
		OrigTtl:    ttl,
		Inception:  incep,
		Expiration: expir,
	}

	e := rrsig.Sign(rcert.Private, []dns.RR{dnskey})
	return rrsig, e
}
