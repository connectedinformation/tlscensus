package tlsparse

import (
	"fmt"
	"strings"
)

// This file maps IANA codepoints to names and derives cryptographic
// properties from them. It is deliberately descriptive only: nothing here
// decides whether a parameter is "weak". That is policy, and it lives in
// internal/inventory so it can change without touching the parser.

// ---------------------------------------------------------------- ciphers

var cipherSuiteNames = map[uint16]string{
	// TLS 1.3 (RFC 8446). No key exchange or authentication is encoded in
	// the suite; both are negotiated by extension.
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",

	// TLS 1.2 AEAD with forward secrecy — the modern baseline.
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",

	// Forward secrecy, CBC construction.
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",

	// Static RSA key exchange: no forward secrecy. Removed in TLS 1.3.
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",

	// Obsolete primitives. Present so an inventory can name what it found
	// rather than reporting an opaque codepoint.
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",

	// Null encryption.
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x003b: "TLS_RSA_WITH_NULL_SHA256",
	0xc010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xc006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",

	// Export-grade. The FREAK and Logjam families.
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",

	// Unauthenticated key exchange.
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x001b: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x003a: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0xc015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xc016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xc018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xc019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",

	// Signalling values, not real suites.
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x5600: "TLS_FALLBACK_SCSV",
}

// CipherProperties describes a cipher suite. Fields are derived from the
// structure of the IANA name, which is rigidly formatted as
// TLS_<kx>_WITH_<cipher>_<mac> for TLS 1.2 and below, and TLS_<aead>_<hash>
// for TLS 1.3.
type CipherProperties struct {
	Name string `json:"name"`
	// KeyExchange is "ECDHE", "DHE", "RSA", "DH_anon", ... or "" for TLS 1.3
	// suites, where key exchange is negotiated by extension instead.
	KeyExchange string `json:"key_exchange,omitempty"`
	// Authentication is the signature algorithm family implied by the suite:
	// "RSA", "ECDSA", "DSS", "anon", or "" for TLS 1.3.
	Authentication string `json:"authentication,omitempty"`
	Encryption     string `json:"encryption"`
	MAC            string `json:"mac"`
	ForwardSecrecy bool   `json:"forward_secrecy"`
	AEAD           bool   `json:"aead"`
	Export         bool   `json:"export,omitempty"`
	Anonymous      bool   `json:"anonymous,omitempty"`
	TLS13          bool   `json:"tls13,omitempty"`
	Signalling     bool   `json:"signalling,omitempty"`
	// Known is false when the codepoint is not in the table; Name is then
	// the hex form and every other field is zero.
	Known bool `json:"known"`
}

// CipherName returns the IANA name for a cipher suite codepoint, or its hex
// form when unrecognised.
func CipherName(id uint16) string {
	if n, ok := cipherSuiteNames[id]; ok {
		return n
	}
	if IsGREASE(id) {
		return fmt.Sprintf("GREASE(%#04x)", id)
	}
	return fmt.Sprintf("%#04x", id)
}

// Cipher returns the properties of a cipher suite codepoint.
func Cipher(id uint16) CipherProperties {
	name, ok := cipherSuiteNames[id]
	if !ok {
		return CipherProperties{Name: CipherName(id)}
	}
	p := CipherProperties{Name: name, Known: true}

	if strings.HasSuffix(name, "_SCSV") {
		p.Signalling = true
		return p
	}

	body := strings.TrimPrefix(name, "TLS_")
	kx, rest, hasWith := strings.Cut(body, "_WITH_")
	if !hasWith {
		// TLS 1.3: TLS_AES_128_GCM_SHA256 — the trailing token is the
		// handshake hash, everything before it is the AEAD.
		p.TLS13 = true
		p.ForwardSecrecy = true
		p.AEAD = true
		p.MAC = "AEAD"
		if i := strings.LastIndex(body, "_SHA"); i > 0 {
			p.Encryption = body[:i]
		} else {
			p.Encryption = body
		}
		return p
	}

	p.Export = strings.Contains(kx, "EXPORT")
	kx = strings.TrimSuffix(kx, "_EXPORT")
	p.Anonymous = strings.HasSuffix(kx, "_anon")

	switch {
	case p.Anonymous:
		p.KeyExchange = kx
		p.Authentication = "anon"
	case kx == "NULL":
		p.KeyExchange = "NULL"
		p.Authentication = "NULL"
	default:
		// "ECDHE_RSA" -> kx ECDHE, auth RSA. A bare "RSA" means static RSA
		// key exchange authenticated by the same key.
		if k, a, ok := strings.Cut(kx, "_"); ok {
			p.KeyExchange, p.Authentication = k, a
		} else {
			p.KeyExchange, p.Authentication = kx, kx
		}
	}

	// Ephemeral key exchange is what provides forward secrecy. Anonymous
	// suites are ephemeral too, but an unauthenticated handshake has no
	// secrecy property worth claiming, so they are excluded.
	switch p.KeyExchange {
	case "ECDHE", "DHE":
		p.ForwardSecrecy = !p.Anonymous
	}

	// Split the trailing MAC/PRF token off the cipher.
	i := strings.LastIndex(rest, "_")
	if i < 0 {
		p.Encryption = rest
		return p
	}
	p.Encryption, p.MAC = rest[:i], rest[i+1:]

	// GCM, CCM and Poly1305 are AEADs: the trailing token is the PRF hash,
	// not a MAC. CCM_8 splits awkwardly, so repair it first.
	if p.MAC == "8" {
		p.Encryption, p.MAC = rest, ""
	}
	switch {
	case strings.Contains(p.Encryption, "_GCM"),
		strings.Contains(p.Encryption, "_CCM"),
		strings.Contains(p.Encryption, "CHACHA20_POLY1305"):
		p.AEAD = true
		p.MAC = "AEAD"
	}
	return p
}

// ----------------------------------------------------------------- groups

var groupNames = map[uint16]string{
	19:     "secp192r1",
	21:     "secp224r1",
	22:     "secp256k1",
	23:     "secp256r1",
	24:     "secp384r1",
	25:     "secp521r1",
	29:     "x25519",
	30:     "x448",
	256:    "ffdhe2048",
	257:    "ffdhe3072",
	258:    "ffdhe4096",
	259:    "ffdhe6144",
	260:    "ffdhe8192",
	0x0200: "MLKEM512",
	0x0201: "MLKEM768",
	0x0202: "MLKEM1024",
	0x11eb: "SecP256r1MLKEM768",
	0x11ec: "X25519MLKEM768",
	0x11ed: "SecP384r1MLKEM1024",
	0x6399: "X25519Kyber768Draft00",
	0x639a: "SecP256r1Kyber768Draft00",
}

// pureKEM are groups whose shared secret comes only from a post-quantum KEM,
// with no classical component. Everything else in the PQ set is hybrid.
var pureKEM = map[uint16]bool{
	0x0200: true, 0x0201: true, 0x0202: true,
}

// GroupProperties describes a named group offered or selected for key
// exchange.
type GroupProperties struct {
	Name string `json:"name"`
	// PostQuantum is true when the group contributes a post-quantum KEM to
	// the shared secret, whether or not it is hybrid.
	PostQuantum bool `json:"post_quantum"`
	// Hybrid is true when a classical and a post-quantum component are
	// combined. Hybrid is the deployable form today; a pure KEM group means
	// classical security has been dropped entirely.
	Hybrid bool `json:"hybrid,omitempty"`
	Known  bool `json:"known"`
}

// GroupName returns the name for a named-group codepoint, or its hex form.
func GroupName(id uint16) string {
	if n, ok := groupNames[id]; ok {
		return n
	}
	if IsGREASE(id) {
		return fmt.Sprintf("GREASE(%#04x)", id)
	}
	return fmt.Sprintf("%#04x", id)
}

// Group returns the properties of a named-group codepoint.
func Group(id uint16) GroupProperties {
	name, ok := groupNames[id]
	if !ok {
		return GroupProperties{Name: GroupName(id)}
	}
	g := GroupProperties{Name: name, Known: true}
	switch {
	case pureKEM[id]:
		g.PostQuantum = true
	case strings.Contains(name, "MLKEM"), strings.Contains(name, "Kyber"):
		g.PostQuantum = true
		g.Hybrid = true
	}
	return g
}

// ------------------------------------------------------- signature algs

var sigAlgNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0202: "dsa_sha1",
	0x0203: "ecdsa_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0402: "dsa_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0502: "dsa_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0602: "dsa_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

// SigAlgName returns the name for a signature-algorithm codepoint, or its
// hex form.
func SigAlgName(id uint16) string {
	if n, ok := sigAlgNames[id]; ok {
		return n
	}
	if IsGREASE(id) {
		return fmt.Sprintf("GREASE(%#04x)", id)
	}
	return fmt.Sprintf("%#04x", id)
}

// SigAlgPostQuantum reports whether a signature algorithm is post-quantum.
func SigAlgPostQuantum(id uint16) bool {
	return strings.HasPrefix(SigAlgName(id), "mldsa")
}

// --------------------------------------------------------------- version

// VersionName returns a human-readable protocol version.
func VersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0xfefd:
		return "DTLS 1.2"
	case 0xfefc:
		return "DTLS 1.3"
	}
	if IsGREASE(v) {
		return fmt.Sprintf("GREASE(%#04x)", v)
	}
	return fmt.Sprintf("%#04x", v)
}

// ------------------------------------------------------- reverse lookup

// Reverse indexes, built once. Callers that hold a rendered name — a report
// writer reading back its own output, for instance — need the codepoint to
// emit an identifier, and scanning the forward table per lookup is both slow
// and easy to get subtly wrong.
var (
	cipherIDs = reverseIndex(cipherSuiteNames)
	groupIDs  = reverseIndex(groupNames)
)

func reverseIndex(m map[uint16]string) map[string]uint16 {
	out := make(map[string]uint16, len(m))
	for id, name := range m {
		out[name] = id
	}
	return out
}

// CipherByName returns the codepoint for an IANA cipher suite name.
func CipherByName(name string) (uint16, bool) {
	id, ok := cipherIDs[name]
	return id, ok
}

// GroupByName returns the codepoint for a named group.
func GroupByName(name string) (uint16, bool) {
	id, ok := groupIDs[name]
	return id, ok
}
