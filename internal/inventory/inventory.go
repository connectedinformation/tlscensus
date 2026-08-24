// Package inventory turns raw handshake observations into reportable
// records: named parameters, a post-quantum readiness verdict, and findings.
//
// This is where policy lives. tlsparse deliberately says only what was on
// the wire; deciding that 3DES is worth flagging, or that a TLS 1.2 flow is
// noteworthy, is a judgement that changes over time and must not be welded
// into the parser.
package inventory

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/netip"
	"time"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/tlsparse"
)

// PQStatus is the post-quantum readiness of a single handshake.
//
// The distinction between the middle states is the point of the whole
// exercise. A client that lists X25519MLKEM768 in supported_groups but sends
// no key share for it will complete a fully classical handshake against any
// server that accepts the offer. Counting it as "post-quantum ready" is the
// most common way a migration dashboard flatters itself.
type PQStatus string

const (
	// PQNegotiated: the server selected a post-quantum group. Actually done.
	PQNegotiated PQStatus = "post_quantum"
	// PQOffered: the client sent a post-quantum key share and the server
	// chose classical anyway. The client is ready; the server is not.
	PQOffered PQStatus = "offered_not_selected"
	// PQAdvertised: post-quantum appears only in supported_groups, with no
	// key share. Nothing post-quantum will happen without a retry.
	PQAdvertised PQStatus = "advertised_only"
	// PQClassical: no post-quantum group anywhere in the handshake.
	PQClassical PQStatus = "classical"
	// PQUnknown: not enough of the handshake was captured to say.
	PQUnknown PQStatus = "unknown"
)

// Severity ranks a finding.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var severityRank = map[Severity]int{
	SevCritical: 4, SevHigh: 3, SevMedium: 2, SevLow: 1, SevInfo: 0,
}

// Finding is one thing worth reporting about a handshake.
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// CertInfo summarises one certificate. Available for TLS 1.2 and below only:
// TLS 1.3 encrypts the Certificate message, so on a modern handshake there
// is nothing to report and this stays empty.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	KeyBits            int       `json:"key_bits,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SelfSigned         bool      `json:"self_signed,omitempty"`
}

// Record is one handshake, named and judged.
type Record struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Transport is "tcp" or "quic". Worth reporting because it changes
	// what could have been seen: over QUIC the certificate is encrypted at
	// the Handshake level, so an empty certificate list means "not
	// visible", not "none presented".
	Transport string `json:"transport"`

	ClientIP   netip.Addr `json:"client_ip"`
	ClientPort uint16     `json:"client_port"`
	ServerIP   netip.Addr `json:"server_ip"`
	ServerPort uint16     `json:"server_port"`

	ServerName string `json:"server_name,omitempty"`
	// ECH reports that encrypted_client_hello was present, which means
	// ServerName is the provider's public name and not the real
	// destination. Consumers must not fold these into hostname counts.
	ECH bool `json:"ech,omitempty"`

	VersionOffered string `json:"version_offered"`
	Version        string `json:"version,omitempty"`

	CipherSuite         string   `json:"cipher_suite,omitempty"`
	CipherSuitesOffered []string `json:"cipher_suites_offered"`
	ForwardSecrecy      *bool    `json:"forward_secrecy,omitempty"`

	Group           string   `json:"group,omitempty"`
	GroupSource     string   `json:"group_source,omitempty"`
	KeyShareGroups  []string `json:"key_share_groups,omitempty"`
	SupportedGroups []string `json:"supported_groups,omitempty"`

	SignatureAlgorithms []string `json:"signature_algorithms,omitempty"`
	ALPNOffered         []string `json:"alpn_offered,omitempty"`
	ALPN                string   `json:"alpn,omitempty"`

	JA4  string `json:"ja4,omitempty"`
	JA4S string `json:"ja4s,omitempty"`

	PQ           PQStatus   `json:"pq_status"`
	Findings     []Finding  `json:"findings,omitempty"`
	Certificates []CertInfo `json:"certificates,omitempty"`

	// ServerObserved is false when only the client side was captured. Such
	// a record still reports what was offered, but nothing negotiated.
	ServerObserved bool `json:"server_observed"`
	Truncated      bool `json:"truncated,omitempty"`
}

// MaxSeverity returns the highest severity among the findings.
func (r *Record) MaxSeverity() Severity {
	worst := SevInfo
	for _, f := range r.Findings {
		if severityRank[f.Severity] > severityRank[worst] {
			worst = f.Severity
		}
	}
	return worst
}

// Analyze converts an observed flow into a record.
func Analyze(f *assemble.Flow) *Record {
	ch := f.Client
	r := &Record{
		Transport:      f.Transport,
		FirstSeen:      f.FirstSeen,
		LastSeen:       f.LastSeen,
		ClientIP:       f.ClientIP,
		ClientPort:     f.ClientPort,
		ServerIP:       f.ServerIP,
		ServerPort:     f.ServerPort,
		ServerName:     ch.ServerName,
		ECH:            ch.ECH != nil,
		VersionOffered: tlsparse.VersionName(ch.NegotiatedVersion()),
		ALPNOffered:    ch.ALPN,
		JA4:            ch.JA4(),
		ServerObserved: f.Server != nil,
		Truncated:      f.PrefixTruncated || ch.Truncated,
	}

	for _, c := range ch.CipherSuites {
		r.CipherSuitesOffered = append(r.CipherSuitesOffered, tlsparse.CipherName(c))
	}
	for _, g := range ch.SupportedGroups {
		r.SupportedGroups = append(r.SupportedGroups, tlsparse.GroupName(g))
	}
	for _, g := range ch.KeyShareGroups {
		r.KeyShareGroups = append(r.KeyShareGroups, tlsparse.GroupName(g))
	}
	for _, s := range ch.SignatureAlgorithms {
		r.SignatureAlgorithms = append(r.SignatureAlgorithms, tlsparse.SigAlgName(s))
	}

	var cipher tlsparse.CipherProperties
	if sh := f.Server; sh != nil {
		r.Version = tlsparse.VersionName(sh.NegotiatedVersion())
		cipher = tlsparse.Cipher(sh.CipherSuite)
		r.CipherSuite = cipher.Name
		fs := cipher.ForwardSecrecy
		r.ForwardSecrecy = &fs
		r.ALPN = sh.SelectedALPN
		r.JA4S = sh.JA4S(ch.QUIC)
		if sh.Group != 0 {
			r.Group = tlsparse.GroupName(sh.Group)
			r.GroupSource = sh.GroupSource
		}
		r.Certificates = analyzeCerts(sh.CertificateChain)
	}

	r.PQ = pqStatus(f)
	r.Findings = findings(f, r, cipher)
	return r
}

// pqStatus grades a handshake on the readiness ladder.
func pqStatus(f *assemble.Flow) PQStatus {
	if sh := f.Server; sh != nil && sh.Group != 0 {
		if tlsparse.Group(sh.Group).PostQuantum {
			return PQNegotiated
		}
		// The server picked a classical group. Whether that is the client's
		// limitation or the server's depends on what the client offered.
		if anyPQ(f.Client.KeyShareGroups) {
			return PQOffered
		}
		if anyPQ(f.Client.SupportedGroups) {
			return PQAdvertised
		}
		return PQClassical
	}

	// Client side only. Report the strongest claim the client made, but
	// never claim a negotiation that was not observed.
	switch {
	case anyPQ(f.Client.KeyShareGroups):
		return PQOffered
	case anyPQ(f.Client.SupportedGroups):
		return PQAdvertised
	case len(f.Client.SupportedGroups) > 0:
		return PQClassical
	}
	return PQUnknown
}

func anyPQ(groups []uint16) bool {
	for _, g := range groups {
		if tlsparse.Group(g).PostQuantum {
			return true
		}
	}
	return false
}

func analyzeCerts(chain [][]byte) []CertInfo {
	var out []CertInfo
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		info := CertInfo{
			Subject:            c.Subject.CommonName,
			Issuer:             c.Issuer.CommonName,
			NotAfter:           c.NotAfter,
			PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
			SelfSigned:         c.Subject.String() == c.Issuer.String(),
		}
		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			info.KeyBits = pub.N.BitLen()
		case *ecdsa.PublicKey:
			info.KeyBits = pub.Curve.Params().BitSize
		case ed25519.PublicKey:
			info.KeyBits = 256
		}
		out = append(out, info)
	}
	return out
}
