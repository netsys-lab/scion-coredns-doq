package transport

// These transports are supported by CoreDNS.
const (
	DNS   = "dns"
	TLS   = "tls"
	GRPC  = "grpc"
	QUIC  = "quic"
	SQUIC = "squic"
	HTTPS = "https"
)

// Port numbers for the various transports.
const (
	// Port is the default port for DNS
	Port = "53"
	// TLSPort is the default port for DNS-over-TLS.
	TLSPort = "853"
	// GRPCPort is the default port for DNS-over-gRPC.
	GRPCPort = "443"
	// HTTPSPort is the default port for DNS-over-HTTPS.
	HTTPSPort = "443"
	// QUICPort is the default port for DNS-over-QUIC.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-10.2.1
	// Early experiments MAY use port 8853. This port is marked in the IANA registry as unassigned.
	// (Note that prior to version -02 of this draft, experiments were directed to use port 784.)
	QUICPort = "8853"
)
