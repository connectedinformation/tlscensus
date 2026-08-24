// Package quic decodes the cleartext part of a QUIC handshake.
//
// QUIC Initial packets are encrypted, but not secretly: the keys are derived
// from the client's Destination Connection ID, which travels in the clear in
// the first packet (RFC 9001 section 5.2). Anyone who can see the packet can
// derive the keys. The protection exists to stop middleboxes ossifying the
// wire format, not to hide the handshake — so a passive observer can recover
// the ClientHello and ServerHello exactly as it can over TCP.
//
// This matters because ignoring QUIC does not merely lose some traffic, it
// loses it selectively. Google and Cloudflare advertise HTTP/3, browsers
// switch to it after the first visit, and those providers deployed hybrid
// post-quantum key exchange early. A TCP-only inventory therefore reports a
// more classical world than the one on the wire.
//
// Like tlsparse, everything here is a pure function over bytes with no I/O.
package quic

import "errors"

var (
	// ErrNotQUIC means the bytes are not a QUIC long-header packet.
	ErrNotQUIC = errors.New("quic: not a long-header packet")
	// ErrTruncated means a field ran past the end of the datagram.
	ErrTruncated = errors.New("quic: truncated packet")
	// ErrUnsupportedVersion means the QUIC version has different initial
	// keys than this package knows how to derive.
	ErrUnsupportedVersion = errors.New("quic: unsupported version")
)

// readVarint decodes a QUIC variable-length integer (RFC 9000 section 16).
// The top two bits of the first byte give the encoded length; the remaining
// bits are the most significant bits of the value.
func readVarint(b []byte) (value uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6) // 1, 2, 4 or 8
	if len(b) < n {
		return 0, 0, false
	}
	value = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		value = value<<8 | uint64(b[i])
	}
	return value, n, true
}
