package quic

// Frame types that can appear in an Initial packet (RFC 9000 section 17.2.2).
// Anything else is a protocol violation and is treated as the end of what
// can be read.
const (
	frameTypePadding         = 0x00
	frameTypePing            = 0x01
	frameTypeACK             = 0x02
	frameTypeACKECN          = 0x03
	frameTypeCrypto          = 0x06
	frameTypeConnectionClose = 0x1c
	frameTypeConnCloseApp    = 0x1d
)

// CryptoFrame is one run of handshake bytes at a given stream offset.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// CryptoFrames extracts the CRYPTO frames from a decrypted packet payload.
//
// Frames are not a stream: a ClientHello too large for one datagram is split
// across packets and arrives as several CRYPTO frames carrying offsets, in
// any order. The offsets are what the caller reassembles on, exactly as TCP
// sequence numbers are used for the same handshake over TCP — and for the
// same reason, since a post-quantum ClientHello does not fit in one Initial.
//
// Padding is skipped rather than treated as an error: an Initial is padded
// to at least 1200 bytes, so most of what arrives here is padding.
func CryptoFrames(payload []byte) []CryptoFrame {
	var out []CryptoFrame
	p := 0
	for p < len(payload) {
		typ, n, ok := readVarint(payload[p:])
		if !ok {
			return out
		}
		p += n

		switch typ {
		case frameTypePadding, frameTypePing:
			// No payload.

		case frameTypeACK, frameTypeACKECN:
			// largest acked, delay, range count, first range, then the
			// ranges themselves, then ECN counts for the 0x03 form.
			counts := 4
			var rangeCount uint64
			for i := 0; i < counts; i++ {
				v, n, ok := readVarint(payload[p:])
				if !ok {
					return out
				}
				if i == 2 {
					rangeCount = v
				}
				p += n
			}
			for i := uint64(0); i < rangeCount; i++ {
				for j := 0; j < 2; j++ { // gap, length
					_, n, ok := readVarint(payload[p:])
					if !ok {
						return out
					}
					p += n
				}
			}
			if typ == frameTypeACKECN {
				for i := 0; i < 3; i++ {
					_, n, ok := readVarint(payload[p:])
					if !ok {
						return out
					}
					p += n
				}
			}

		case frameTypeCrypto:
			offset, n, ok := readVarint(payload[p:])
			if !ok {
				return out
			}
			p += n
			length, n, ok := readVarint(payload[p:])
			if !ok {
				return out
			}
			p += n
			if length > uint64(len(payload)-p) {
				return out
			}
			out = append(out, CryptoFrame{Offset: offset, Data: payload[p : p+int(length)]})
			p += int(length)

		case frameTypeConnectionClose, frameTypeConnCloseApp:
			// error code, [frame type], reason length, reason
			fields := 2
			if typ == frameTypeConnectionClose {
				fields = 3
			}
			for i := 0; i < fields; i++ {
				_, n, ok := readVarint(payload[p:])
				if !ok {
					return out
				}
				p += n
			}
			// The reason phrase length was the last varint read; without
			// tracking it there is nothing further worth parsing.
			return out

		default:
			// Not permitted in an Initial packet. Stop rather than guess at
			// a frame whose length is unknown.
			return out
		}
	}
	return out
}
