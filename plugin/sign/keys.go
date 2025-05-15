package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// "github.com/google/certificate-transparency-go/x509"
	"crypto/x509"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

// Pair holds DNSSEC key information, both the public and private components are stored here.
type Pair struct {
	Public  *dns.DNSKEY
	KeyTag  uint16
	Private crypto.Signer
}

type RCertPair struct {
	Rcert   *x509.Certificate
	Private crypto.Signer
}

// keyParse reads the public and private key from disk.
func keyParse(c *caddy.Controller) ([]Pair, error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}
	pairs := []Pair{}
	config := dnsserver.GetConfig(c)

	switch c.Val() {
	case "file":
		ks := c.RemainingArgs()
		if len(ks) == 0 {
			return nil, c.ArgErr()
		}
		for _, k := range ks {
			base := k
			// Kmiek.nl.+013+26205.key, handle .private or without extension: Kmiek.nl.+013+26205
			if strings.HasSuffix(k, ".key") {
				base = k[:len(k)-4]
			}
			if strings.HasSuffix(k, ".private") {
				base = k[:len(k)-8]
			}
			if !filepath.IsAbs(base) && config.Root != "" {
				base = filepath.Join(config.Root, base)
			}

			pair, err := readKeyPair(base+".key", base+".private")
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, pair)
		}
	case "directory":
		return nil, fmt.Errorf("directory: not implemented")
	}

	return pairs, nil
}

func readKeyPair(public, private string) (Pair, error) {
	rk, err := os.Open(filepath.Clean(public))
	if err != nil {
		return Pair{}, err
	}
	b, err := io.ReadAll(rk)
	if err != nil {
		return Pair{}, err
	}
	dnskey, err := dns.NewRR(string(b))
	if err != nil {
		return Pair{}, err
	}
	if _, ok := dnskey.(*dns.DNSKEY); !ok {
		return Pair{}, fmt.Errorf("RR in %q is not a DNSKEY: %d", public, dnskey.Header().Rrtype)
	}
	ksk := dnskey.(*dns.DNSKEY).Flags&(1<<8) == (1<<8) && dnskey.(*dns.DNSKEY).Flags&1 == 1
	if !ksk {
		return Pair{}, fmt.Errorf("DNSKEY in %q is not a CSK/KSK", public)
	}

	rp, err := os.Open(filepath.Clean(private))
	if err != nil {
		return Pair{}, err
	}
	privkey, err := dnskey.(*dns.DNSKEY).ReadPrivateKey(rp, private)
	if err != nil {
		return Pair{}, err
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case ed25519.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case *rsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), KeyTag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	default:
		return Pair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}
func rCertParse(c *caddy.Controller) (pair *RCertPair, err error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}
	config := dnsserver.GetConfig(c)
	switch c.Val() {
	case "file":
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		k := c.Val()
		base := k

		// Kmiek.nl.+013+26205.key, handle .private or without extension: Kmiek.nl.+013+26205
		if strings.HasSuffix(k, "_private.pem") {
			base = k[:len(k)-12]
		}
		if strings.HasSuffix(k, "_cert.pem") {
			base = k[:len(k)-9]
		}
		if !filepath.IsAbs(base) && config.Root != "" {
			base = filepath.Join(config.Root, base)
		}

		pair, err = readRCertPair(base+"_private.pem", base+"_cert.pem")
		if err != nil {
			return nil, err
		}

	case "directory":
		return nil, fmt.Errorf("directory: not implemented")
	}

	return pair, nil
}

func LoadPrivateKey(key_path string) (crypto.PrivateKey, error) {
	pemData, err := os.ReadFile(key_path)
	if err != nil {
		log.Fatalf("Failed to read PEM file: %v", err)
	}

	// Decode the PEM data
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatal("Failed to decode PEM data")
	}

	// Parse the private key
	privateKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	return privateKey, nil

}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// Try parsing as PKCS#8 private key
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	// Try parsing as PKCS#1 RSA private key
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// Try parsing as EC private key
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func readRCertPair(private, cert string) (*RCertPair, error) {
	rcert, err := LoadCertificatePEM(cert)
	if err != nil {
		return &RCertPair{}, err
	}
	privkey, err := LoadPrivateKey(private)
	if err != nil {
		return &RCertPair{}, err
	}
	signer, ok := privkey.(crypto.Signer)
	if !ok {
		log.Fatal("Private key does not implement crypto.Signer")
	}
	return &RCertPair{Rcert: rcert, Private: signer}, nil
}

const certprefix = "_rhinecert."
const dsumprefix = "_dsum."

func createCertRR(cert *x509.Certificate, origin string) dns.RR {

	txtcertvalueprefix := fmt.Sprintf("rhineCert %s ", cert.PublicKeyAlgorithm)

	certRR := dns.TXT{}
	if origin == "." {
		origin = ""
	}
	certRR.Hdr = dns.RR_Header{
		Name:   certprefix + origin,
		Rrtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		Ttl:    604800,
	}

	txtvalue := base64.StdEncoding.EncodeToString(cert.Raw)
	certRR.Txt = split255TXT(txtcertvalueprefix + txtvalue)

	return &certRR

}

func split255TXT(in string) []string {
	tmp := in
	res := []string{}

	for len(tmp) > 255 {
		res = append(res, tmp[:255])
		tmp = tmp[255:]

	}

	if len(tmp) > 0 {
		res = append(res, tmp)
	}
	return res
}

func LoadCertificatePEM(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func LoadPrivateKeyEd25519(path string) (ed25519.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	privKey := block.Bytes
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

// keyTag returns the key tags of the keys in ps as a formatted string.
func keyTag(ps []Pair) string {
	if len(ps) == 0 {
		return ""
	}
	s := ""
	for _, p := range ps {
		s += strconv.Itoa(int(p.KeyTag)) + ","
	}
	return s[:len(s)-1]
}
