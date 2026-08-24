package quic

import "encoding/binary"

// Long header packet types (RFC 9000 section 17.2).
const (
	TypeInitial   = 0x00
	TypeZeroRTT   = 0x01
	TypeHandshake = 0x02
	TypeRetry     = 0x03
)

const (
	// A connection ID is at most 20 bytes in QUIC v1.
	maxConnIDLen = 20
	// Header protection samples 16 bytes starting four past the packet
	// number offset, so a packet shorter than this cannot be unprotected.
	sampleLen    = 16
	sampleOffset = 4
)

// LongHeader is the cleartext part of a long-header packet.
type LongHeader struct {
	Type    byte
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte

	// PNOffset is where the (still protected) packet number begins.
	PNOffset int
	// Length is the value of the Length field: packet number plus payload.
	Length int
	// End is where this packet ends within the datagram. A datagram may
	// carry several packets back to back — typically an Initial followed by
	// a Handshake — so this is where the next one starts.
	End int
}

// IsLongHeader reports whether b starts a long-header packet with the fixed
// bit set. It is the cheap test used to reject the great majority of UDP
// traffic without deriving anything.
func IsLongHeader(b []byte) bool {
	return len(b) > 0 && b[0]&0xc0 == 0xc0
}

// ParseLongHeader decodes the unprotected fields of a long-header packet.
//
// Everything it reads is in the clear: the version, the connection IDs, the
// token and the length. Only the packet number and payload are protected,
// and the connection ID read here is what derives the keys for them.
func ParseLongHeader(b []byte) (*LongHeader, error) {
	if !IsLongHeader(b) {
		return nil, ErrNotQUIC
	}
	if len(b) < 7 {
		return nil, ErrTruncated
	}
	h := &LongHeader{
		Type:    (b[0] & 0x30) >> 4,
		Version: binary.BigEndian.Uint32(b[1:5]),
	}
	// A Version Negotiation packet carries version 0 and no encrypted
	// payload; it is not something to decrypt.
	if h.Version == 0 {
		return nil, ErrUnsupportedVersion
	}

	p := 5
	readCID := func() ([]byte, bool) {
		if p >= len(b) {
			return nil, false
		}
		n := int(b[p])
		p++
		if n > maxConnIDLen || p+n > len(b) {
			return nil, false
		}
		cid := b[p : p+n]
		p += n
		return cid, true
	}
	var ok bool
	if h.DCID, ok = readCID(); !ok {
		return nil, ErrTruncated
	}
	if h.SCID, ok = readCID(); !ok {
		return nil, ErrTruncated
	}

	// Retry carries a token and an integrity tag but no length or packet
	// number, so it stops here. It matters for a different reason: a Retry
	// makes the client start again with a new connection ID, and the keys
	// derived from the original one no longer apply.
	if h.Type == TypeRetry {
		h.End = len(b)
		return h, nil
	}

	if h.Type == TypeInitial {
		tokenLen, n, ok := readVarint(b[p:])
		if !ok {
			return nil, ErrTruncated
		}
		p += n
		if tokenLen > uint64(len(b)-p) {
			return nil, ErrTruncated
		}
		h.Token = b[p : p+int(tokenLen)]
		p += int(tokenLen)
	}

	length, n, ok := readVarint(b[p:])
	if !ok {
		return nil, ErrTruncated
	}
	p += n
	h.PNOffset = p
	h.Length = int(length)
	h.End = p + int(length)
	if h.Length < 0 || h.End > len(b) {
		return nil, ErrTruncated
	}
	return h, nil
}

// Open removes header protection and decrypts the packet payload.
//
// The datagram is not modified: header protection is undone on a copy,
// because the same bytes are still owned by the capture buffer and because a
// caller may want to re-read the protected form.
//
// The packet number is taken as the truncated value on the wire. QUIC
// transmits only the low bytes and expects the peer to reconstruct the full
// number from the largest one it has acknowledged (RFC 9000 section 17.1),
// which a passive observer cannot always do. It does not matter at the
// Initial level: a connection's Initial packet numbers start at zero and
// there are only ever a handful, so the truncated value is the full value.
// If that assumption were ever violated the AEAD would fail closed rather
// than return wrong plaintext, because the packet number is part of the
// nonce.
func Open(datagram []byte, h *LongHeader, k *Keys) (packetNumber uint64, payload []byte, err error) {
	if h.PNOffset+sampleOffset+sampleLen > len(datagram) {
		return 0, nil, ErrTruncated
	}
	sample := datagram[h.PNOffset+sampleOffset : h.PNOffset+sampleOffset+sampleLen]
	mask := k.headerMask(sample)

	// The low four bits of a long header's first byte are protected.
	first := datagram[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if h.PNOffset+pnLen > h.End {
		return 0, nil, ErrTruncated
	}

	// The associated data is the header exactly as it appears once
	// unprotected, so it has to be rebuilt rather than sliced.
	header := make([]byte, h.PNOffset+pnLen)
	copy(header, datagram[:h.PNOffset+pnLen])
	header[0] = first
	for i := 0; i < pnLen; i++ {
		header[h.PNOffset+i] ^= mask[1+i]
		packetNumber = packetNumber<<8 | uint64(header[h.PNOffset+i])
	}

	ciphertext := datagram[h.PNOffset+pnLen : h.End]
	plaintext, err := k.aead.Open(nil, k.nonce(packetNumber), ciphertext, header)
	if err != nil {
		// Authentication failure here almost always means the keys came
		// from the wrong connection ID, not that the packet is corrupt.
		return 0, nil, err
	}
	return packetNumber, plaintext, nil
}
