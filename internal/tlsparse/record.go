// Package tlsparse decodes TLS handshake messages from raw bytes.
//
// Everything in this package is a pure function over a byte slice: no I/O,
// no network access, no global state, and no dependency beyond
// golang.org/x/crypto/cryptobyte. That is deliberate. This is the code that
// reads attacker-controlled input inside a privileged process, so it is
// also the code that has to be trivially fuzzable, auditable in isolation,
// and testable without a capture device.
//
// Parsers here are tolerant of truncation by design. A capture keeps only a
// bounded prefix of each stream, so a ServerHello may legitimately arrive
// cut in half. Parsers return what they could decode rather than failing
// the whole flow, and callers decide whether a partial record is useful.
package tlsparse

import "errors"

// TLS record content types (RFC 8446 section 5.1).
const (
	RecordChangeCipherSpec uint8 = 20
	RecordAlert            uint8 = 21
	RecordHandshake        uint8 = 22
	RecordApplicationData  uint8 = 23
)

// Handshake message types (RFC 8446 appendix B.3).
const (
	HandshakeClientHello         uint8 = 1
	HandshakeServerHello         uint8 = 2
	HandshakeNewSessionTicket    uint8 = 4
	HandshakeEncryptedExtensions uint8 = 8
	HandshakeCertificate         uint8 = 11
	HandshakeServerKeyExchange   uint8 = 12
	HandshakeCertificateRequest  uint8 = 13
	HandshakeServerHelloDone     uint8 = 14
)

const (
	recordHeaderLen = 5
	// TLSPlaintext.length must not exceed 2^14; TLSCiphertext adds at most
	// 256 bytes of expansion. Anything larger is not a TLS record stream.
	maxRecordPayload = 1<<14 + 256
)

var (
	// ErrNotTLS means the bytes do not begin with a plausible TLS handshake
	// record. Callers use this to reject non-TLS flows cheaply.
	ErrNotTLS = errors.New("tlsparse: not a TLS handshake record")
	// ErrTruncated means the message ended before a required field.
	ErrTruncated = errors.New("tlsparse: truncated message")
	// ErrMalformed means a length prefix was internally inconsistent.
	ErrMalformed = errors.New("tlsparse: malformed message")
)

// HandshakeMessage is one handshake message lifted out of the record layer.
// Body excludes the four-byte type and length header.
type HandshakeMessage struct {
	Type uint8
	Body []byte
}

// HandshakeMessages coalesces the payloads of the handshake records in b and
// splits the result into messages.
//
// Coalescing matters: a handshake message may be fragmented across several
// records, and a record may carry several messages. Parsers that assume one
// message per record work on most traffic and then fail on exactly the
// handshakes worth reporting.
//
// Reading stops at the first application-data record, since under TLS 1.3
// every handshake message after ServerHello is encrypted inside those.
func HandshakeMessages(b []byte) ([]HandshakeMessage, error) {
	var buf []byte
	first := true

loop:
	for len(b) >= recordHeaderLen {
		typ := b[0]
		length := int(b[3])<<8 | int(b[4])

		if first {
			// Cheap rejection of non-TLS flows: the first record must be a
			// non-empty handshake record with a 0x03xx legacy version.
			if typ != RecordHandshake || b[1] != 0x03 || length == 0 {
				return nil, ErrNotTLS
			}
			first = false
		}
		if length > maxRecordPayload {
			return nil, ErrNotTLS
		}

		payload := b[recordHeaderLen:]
		if len(payload) < length {
			// The capture prefix cut the final record short. Keep what is
			// present; a ClientHello is often fully readable even when the
			// records after it are not.
			if typ == RecordHandshake {
				buf = append(buf, payload...)
			}
			break
		}

		switch typ {
		case RecordHandshake:
			buf = append(buf, payload[:length]...)
		case RecordChangeCipherSpec, RecordAlert:
			// Interleaved, but carries no handshake content.
		default:
			break loop
		}
		b = b[recordHeaderLen+length:]
	}

	return splitMessages(buf), nil
}

// splitMessages walks the coalesced handshake stream. A trailing message
// whose body is incomplete is dropped rather than reported as an error:
// truncation at the end of a bounded capture prefix is expected.
func splitMessages(buf []byte) []HandshakeMessage {
	var msgs []HandshakeMessage
	for len(buf) >= 4 {
		length := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+length {
			break
		}
		msgs = append(msgs, HandshakeMessage{Type: buf[0], Body: buf[4 : 4+length]})
		buf = buf[4+length:]
	}
	return msgs
}

// FindClientHello returns the first ClientHello in a client-to-server byte
// stream, or nil if there is none.
func FindClientHello(stream []byte) (*ClientHello, error) {
	msgs, err := HandshakeMessages(stream)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Type == HandshakeClientHello {
			return ParseClientHello(m.Body)
		}
	}
	return nil, nil
}

// FindServerHello returns the first real ServerHello in a server-to-client
// byte stream, or nil if there is none.
//
// The result is enriched from the messages that follow it in the clear. For
// TLS 1.2 that means the ServerKeyExchange group and the certificate chain;
// for TLS 1.3 those messages are encrypted and nothing further is available.
//
// A HelloRetryRequest is encoded as a ServerHello. When one is present the
// scan keeps going, because the client answers it with a second ClientHello
// and the server with the real ServerHello, both still in the clear. The
// HRR is only returned if no real ServerHello follows it in the captured
// prefix.
func FindServerHello(stream []byte) (*ServerHello, error) {
	msgs, err := HandshakeMessages(stream)
	if err != nil {
		return nil, err
	}

	var sh, retry *ServerHello
	for _, m := range msgs {
		switch m.Type {
		case HandshakeServerHello:
			parsed, err := ParseServerHello(m.Body)
			if err != nil {
				if sh == nil && retry == nil {
					return nil, err
				}
				continue
			}
			if parsed.IsHelloRetryRequest {
				if retry == nil {
					retry = parsed
				}
				continue
			}
			sh = parsed

		case HandshakeServerKeyExchange:
			// TLS 1.2 only, and only meaningful once a ServerHello has been
			// seen on this stream.
			if sh == nil || sh.Group != 0 {
				continue
			}
			if group, ok := ParseServerKeyExchangeGroup(m.Body); ok {
				sh.Group = group
				sh.GroupSource = GroupSourceServerKeyExchange
			}

		case HandshakeCertificate:
			if sh == nil || sh.CertificateChain != nil {
				continue
			}
			if chain, ok := ParseCertificateChain(m.Body); ok {
				sh.CertificateChain = chain
			}
		}
	}

	if sh != nil {
		return sh, nil
	}
	return retry, nil
}
