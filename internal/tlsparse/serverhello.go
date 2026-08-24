package tlsparse

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

// helloRetryRequestRandom is the fixed Random value that marks a ServerHello
// as a HelloRetryRequest (RFC 8446 section 4.1.3). It is the SHA-256 of the
// string "HelloRetryRequest".
var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// Key exchange sources, reported in ServerHello.GroupSource.
const (
	GroupSourceKeyShare          = "key_share"
	GroupSourceServerKeyExchange = "server_key_exchange"
)

// ServerHello is the decoded content of a TLS ServerHello, enriched with
// what the surrounding cleartext handshake messages reveal.
//
// Under TLS 1.3 that is everything the server will ever disclose in the
// clear: Certificate, CertificateVerify and EncryptedExtensions all move
// under handshake encryption. Certificate inventory — key type, key size,
// issuer, validity — is therefore only available for TLS 1.2 and below.
// This is a property of the protocol, not a gap in this parser.
type ServerHello struct {
	LegacyVersion     uint16   `json:"legacy_version"`
	CipherSuite       uint16   `json:"cipher_suite"`
	CompressionMethod uint8    `json:"compression_method"`
	Extensions        []uint16 `json:"extensions"`

	// SelectedVersion is the supported_versions value when present. It is
	// authoritative over LegacyVersion, which a TLS 1.3 server pins to
	// TLS 1.2 for middlebox compatibility.
	SelectedVersion uint16 `json:"selected_version,omitempty"`

	// Group is the negotiated key exchange group, and GroupSource records
	// where it was read from.
	Group       uint16 `json:"group,omitempty"`
	GroupSource string `json:"group_source,omitempty"`

	SelectedALPN string `json:"selected_alpn,omitempty"`

	IsHelloRetryRequest bool `json:"is_hello_retry_request,omitempty"`
	HasPreSharedKey     bool `json:"has_pre_shared_key,omitempty"`

	// FlightComplete reports that the server has said everything it will
	// ever say in the clear, so nothing is gained by waiting for more
	// bytes on this connection.
	//
	// Under TLS 1.3 that is the ServerHello itself: Certificate,
	// CertificateVerify and EncryptedExtensions all move under handshake
	// encryption. Under TLS 1.2 it is ServerHelloDone, which closes the
	// server's flight after Certificate and ServerKeyExchange.
	//
	// It exists so an observation can be reported as soon as it is
	// complete rather than when the connection closes. A browser holds
	// connections open for minutes, so waiting for the close means a live
	// capture shows nothing for minutes after the handshake it just saw.
	//
	// A resumed TLS 1.2 session sends no ServerHelloDone — the server goes
	// straight to ChangeCipherSpec — so those stay false and are reported
	// when the connection ends. That is a latency cost on an uncommon case,
	// not a loss.
	FlightComplete bool `json:"flight_complete,omitempty"`

	// CertificateChain holds the raw DER of the server's certificate chain,
	// leaf first. Populated for TLS 1.2 and below only.
	CertificateChain [][]byte `json:"-"`

	Truncated bool `json:"truncated,omitempty"`
}

// NegotiatedVersion returns the version actually in force.
func (sh *ServerHello) NegotiatedVersion() uint16 {
	if sh.SelectedVersion != 0 {
		return sh.SelectedVersion
	}
	return sh.LegacyVersion
}

// ParseServerHello decodes a ServerHello handshake message body, excluding
// the four-byte handshake header.
func ParseServerHello(body []byte) (*ServerHello, error) {
	s := cryptobyte.String(body)
	sh := &ServerHello{}

	var random, sessionID cryptobyte.String
	if !s.ReadUint16(&sh.LegacyVersion) {
		return nil, ErrTruncated
	}
	if !s.ReadBytes((*[]byte)(&random), 32) {
		return nil, ErrTruncated
	}
	sh.IsHelloRetryRequest = bytes.Equal(random, helloRetryRequestRandom)

	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, ErrTruncated
	}
	if !s.ReadUint16(&sh.CipherSuite) {
		return nil, ErrTruncated
	}
	if !s.ReadUint8(&sh.CompressionMethod) {
		return nil, ErrTruncated
	}

	if s.Empty() {
		return sh, nil
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		sh.Truncated = true
		return sh, nil
	}
	sh.parseExtensions(exts)
	return sh, nil
}

func (sh *ServerHello) parseExtensions(exts cryptobyte.String) {
	for !exts.Empty() {
		var extType uint16
		var body cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&body) {
			sh.Truncated = true
			return
		}
		if IsGREASE(extType) {
			continue
		}
		sh.Extensions = append(sh.Extensions, extType)

		switch extType {
		case ExtSupportedVersions:
			// Unlike the ClientHello form, the server sends a bare uint16.
			var v uint16
			if body.ReadUint16(&v) {
				sh.SelectedVersion = v
			}
		case ExtKeyShare:
			sh.parseKeyShare(body)
		case ExtALPN:
			if list, ok := parseALPN(body); ok && len(list) > 0 {
				sh.SelectedALPN = list[0]
			}
		case ExtPreSharedKey:
			sh.HasPreSharedKey = true
		}
	}
}

// parseKeyShare handles both server forms: a HelloRetryRequest carries only
// the selected group, while a real ServerHello carries a full KeyShareEntry.
func (sh *ServerHello) parseKeyShare(body cryptobyte.String) {
	var group uint16
	if !body.ReadUint16(&group) {
		return
	}
	if sh.IsHelloRetryRequest {
		sh.Group, sh.GroupSource = group, GroupSourceKeyShare
		return
	}
	var key cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&key) {
		return
	}
	sh.Group, sh.GroupSource = group, GroupSourceKeyShare
}

// ParseServerKeyExchangeGroup extracts the named curve from a TLS 1.2 ECDHE
// ServerKeyExchange message.
//
// This is the only place a TLS 1.2 handshake states its key exchange group,
// since there is no key_share extension before TLS 1.3. Without it every
// TLS 1.2 flow would report an unknown group, which would make the
// classical-versus-post-quantum split meaningless on exactly the traffic
// most likely to be classical.
//
// Non-ECDHE key exchanges (plain DHE, static RSA) have a different body
// shape and report ok=false.
func ParseServerKeyExchangeGroup(body []byte) (group uint16, ok bool) {
	s := cryptobyte.String(body)
	var curveType uint8
	if !s.ReadUint8(&curveType) {
		return 0, false
	}
	const namedCurve = 3
	if curveType != namedCurve {
		return 0, false
	}
	if !s.ReadUint16(&group) {
		return 0, false
	}
	return group, true
}

// ParseCertificateChain extracts the raw DER certificates from a TLS 1.2
// Certificate message. TLS 1.3 uses a different encoding and encrypts the
// message regardless, so this only ever runs on 1.2 and below.
func ParseCertificateChain(body []byte) ([][]byte, bool) {
	s := cryptobyte.String(body)
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return nil, false
	}
	var chain [][]byte
	for !list.Empty() {
		var cert cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&cert) {
			return chain, len(chain) > 0
		}
		chain = append(chain, []byte(cert))
	}
	return chain, true
}
