// Package tlssynth builds synthetic TLS handshake bytes for tests and for
// generating sample captures.
//
// It deliberately does not import tlsparse and defines its own codepoint
// constants. A test oracle that shares definitions with the code under test
// cannot catch a wrong constant: rename a value in the parser and a shared
// table follows it silently. Keeping the two independent means the builders
// encode what the RFCs say, and the parser has to agree with that.
package tlssynth

import (
	"golang.org/x/crypto/cryptobyte"
)

// Codepoints used by the builders, written out independently of the parser.
const (
	extServerName           uint16 = 0
	extSupportedGroups      uint16 = 10
	extSignatureAlgorithms  uint16 = 13
	extALPN                 uint16 = 16
	extSupportedVersions    uint16 = 43
	extKeyShare             uint16 = 51
	extQUICTransportParams  uint16 = 57
	extEncryptedClientHello uint16 = 0xfe0d

	RecordHandshake        uint8 = 22
	RecordChangeCipherSpec uint8 = 20
	RecordApplicationData  uint8 = 23

	MsgClientHello       uint8 = 1
	MsgServerHello       uint8 = 2
	MsgCertificate       uint8 = 11
	MsgServerKeyExchange uint8 = 12
	MsgServerHelloDone   uint8 = 14
)

// HelloRetryRequestRandom is the fixed Random marking a HelloRetryRequest
// (RFC 8446 section 4.1.3): SHA-256 of "HelloRetryRequest".
var HelloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// ClientHelloSpec describes a ClientHello to build. GREASE values are added
// automatically in the places a real BoringSSL client puts them.
type ClientHelloSpec struct {
	LegacyVersion     uint16
	Ciphers           []uint16
	Compression       []uint8
	SNI               string
	ALPN              []string
	SupportedVersions []uint16
	Groups            []uint16
	KeyShares         []uint16
	SigAlgs           []uint16
	ECH               bool
	QUIC              bool
	OmitExtensions    bool
	// NoGREASE suppresses the injected GREASE values, for building a
	// non-browser client.
	NoGREASE bool
}

// KeyShareLen returns a realistic public key length for a group. The
// post-quantum sizes are the reason a PQ ClientHello does not fit in one
// TCP segment: X25519MLKEM768 alone is 1216 bytes of client share.
func KeyShareLen(group uint16) int {
	switch group {
	case 0x11ec: // X25519MLKEM768
		return 1216
	case 0x11eb: // SecP256r1MLKEM768
		return 1249
	case 0x11ed: // SecP384r1MLKEM1024
		return 1665
	case 0x6399: // X25519Kyber768Draft00
		return 1216
	case 29: // x25519
		return 32
	case 30: // x448
		return 56
	case 23: // secp256r1
		return 65
	case 24: // secp384r1
		return 97
	case 25: // secp521r1
		return 133
	}
	return 32
}

func addExt(b *cryptobyte.Builder, typ uint16, f func(*cryptobyte.Builder)) {
	b.AddUint16(typ)
	b.AddUint16LengthPrefixed(f)
}

func addU16Vector(b *cryptobyte.Builder, vs []uint16) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, v := range vs {
			b.AddUint16(v)
		}
	})
}

// ClientHello builds a ClientHello message body, without the handshake
// header.
func ClientHello(s ClientHelloSpec) []byte {
	var b cryptobyte.Builder
	if s.LegacyVersion == 0 {
		s.LegacyVersion = 0x0303
	}
	if s.Compression == nil {
		s.Compression = []uint8{0}
	}

	b.AddUint16(s.LegacyVersion)
	b.AddBytes(make([]byte, 32))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(make([]byte, 32))
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if !s.NoGREASE {
			b.AddUint16(0x0a0a)
		}
		for _, c := range s.Ciphers {
			b.AddUint16(c)
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(s.Compression)
	})
	if s.OmitExtensions {
		return b.BytesOrPanic()
	}

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if !s.NoGREASE {
			addExt(b, 0x1a1a, func(b *cryptobyte.Builder) {})
		}
		if s.SNI != "" {
			addExt(b, extServerName, func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(s.SNI))
					})
				})
			})
		}
		if len(s.ALPN) > 0 {
			addExt(b, extALPN, func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, p := range s.ALPN {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(p))
						})
					}
				})
			})
		}
		if len(s.SupportedVersions) > 0 {
			addExt(b, extSupportedVersions, func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					if !s.NoGREASE {
						b.AddUint16(0x3a3a)
					}
					for _, v := range s.SupportedVersions {
						b.AddUint16(v)
					}
				})
			})
		}
		if len(s.Groups) > 0 {
			addExt(b, extSupportedGroups, func(b *cryptobyte.Builder) {
				g := s.Groups
				if !s.NoGREASE {
					g = append([]uint16{0x5a5a}, g...)
				}
				addU16Vector(b, g)
			})
		}
		if len(s.SigAlgs) > 0 {
			addExt(b, extSignatureAlgorithms, func(b *cryptobyte.Builder) {
				addU16Vector(b, s.SigAlgs)
			})
		}
		if len(s.KeyShares) > 0 {
			addExt(b, extKeyShare, func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					if !s.NoGREASE {
						b.AddUint16(0xdada)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint8(0)
						})
					}
					for _, g := range s.KeyShares {
						b.AddUint16(g)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(make([]byte, KeyShareLen(g)))
						})
					}
				})
			})
		}
		if s.ECH {
			addExt(b, extEncryptedClientHello, func(b *cryptobyte.Builder) {
				b.AddUint8(0)       // ClientHelloOuter
				b.AddUint16(0x0001) // HKDF-SHA256
				b.AddUint16(0x0001) // AES-128-GCM
				b.AddUint8(7)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(make([]byte, 32))
				})
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(make([]byte, 128))
				})
			})
		}
		if s.QUIC {
			addExt(b, extQUICTransportParams, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0x01, 0x02, 0x03})
			})
		}
	})
	return b.BytesOrPanic()
}

// ServerHelloSpec describes a ServerHello to build.
type ServerHelloSpec struct {
	LegacyVersion   uint16
	Cipher          uint16
	SelectedVersion uint16
	Group           uint16
	ALPN            string
	HelloRetry      bool
}

// ServerHello builds a ServerHello message body, without the handshake
// header.
func ServerHello(s ServerHelloSpec) []byte {
	var b cryptobyte.Builder
	if s.LegacyVersion == 0 {
		s.LegacyVersion = 0x0303
	}
	b.AddUint16(s.LegacyVersion)
	if s.HelloRetry {
		b.AddBytes(HelloRetryRequestRandom)
	} else {
		b.AddBytes(make([]byte, 32))
	}
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(make([]byte, 32))
	})
	b.AddUint16(s.Cipher)
	b.AddUint8(0)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if s.SelectedVersion != 0 {
			addExt(b, extSupportedVersions, func(b *cryptobyte.Builder) {
				b.AddUint16(s.SelectedVersion)
			})
		}
		if s.Group != 0 {
			addExt(b, extKeyShare, func(b *cryptobyte.Builder) {
				b.AddUint16(s.Group)
				if !s.HelloRetry {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(make([]byte, KeyShareLen(s.Group)))
					})
				}
			})
		}
		if s.ALPN != "" {
			addExt(b, extALPN, func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(s.ALPN))
					})
				})
			})
		}
	})
	return b.BytesOrPanic()
}

// ServerKeyExchangeECDHE builds a TLS 1.2 ECDHE ServerKeyExchange body. It
// is the only place a TLS 1.2 handshake names its key exchange group.
func ServerKeyExchangeECDHE(group uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint8(3) // named_curve
	b.AddUint16(group)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(make([]byte, KeyShareLen(group)))
	})
	b.AddUint16(0x0401) // rsa_pkcs1_sha256
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(make([]byte, 256))
	})
	return b.BytesOrPanic()
}

// CertificateMsg builds a TLS 1.2 Certificate message body from raw DER.
func CertificateMsg(chain [][]byte) []byte {
	var b cryptobyte.Builder
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, der := range chain {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(der)
			})
		}
	})
	return b.BytesOrPanic()
}

// HandshakeMsg prefixes a body with its four-byte handshake header.
func HandshakeMsg(typ uint8, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	out[0] = typ
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

// Records wraps a byte stream in TLS records of at most chunk bytes each.
// A chunk smaller than the payload exercises handshake fragmentation.
func Records(contentType uint8, payload []byte, chunk int) []byte {
	if chunk <= 0 {
		chunk = len(payload)
	}
	if chunk <= 0 {
		return nil
	}
	var out []byte
	for len(payload) > 0 {
		n := min(chunk, len(payload))
		out = append(out, contentType, 0x03, 0x03, byte(n>>8), byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return out
}
