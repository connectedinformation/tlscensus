package tlssynth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// QUIC Initial packet construction, for generating sample captures.
//
// The key derivation here is written out from RFC 9001 rather than imported
// from internal/quic, for the same reason the TLS builders define their own
// codepoints: a generator that shares its derivation with the decoder cannot
// disagree with it, so an end-to-end test over the result would prove only
// self-consistency. Both sides are independently anchored — this one to the
// RFC text, the decoder to the RFC's published vectors in keys_test.go.

var quicInitialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// QUICVersion1 is the version generated packets carry.
const QUICVersion1 uint32 = 0x00000001

type quicKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func quicHkdfLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 3+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(func() hash.Hash { return sha256.New() }, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

func quicInitialKeys(dcid []byte, server bool) *quicKeys {
	initial, err := hkdf.Extract(func() hash.Hash { return sha256.New() }, dcid, quicInitialSaltV1)
	if err != nil {
		panic(err)
	}
	label := "client in"
	if server {
		label = "server in"
	}
	secret := quicHkdfLabel(initial, label, 32)

	block, err := aes.NewCipher(quicHkdfLabel(secret, "quic key", 16))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	hpBlock, err := aes.NewCipher(quicHkdfLabel(secret, "quic hp", 16))
	if err != nil {
		panic(err)
	}
	return &quicKeys{aead: aead, iv: quicHkdfLabel(secret, "quic iv", 12), hp: hpBlock}
}

func quicVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	}
}

// CryptoFrame wraps handshake bytes in a QUIC CRYPTO frame at an offset.
func CryptoFrame(offset uint64, data []byte) []byte {
	out := []byte{0x06}
	out = quicVarint(out, offset)
	out = quicVarint(out, uint64(len(data)))
	return append(out, data...)
}

// QUICInitial builds one protected Initial packet carrying frames.
//
// padTo pads the packet with PADDING frames, as a client's first Initial
// must be (RFC 9000 requires at least 1200 bytes); pass 0 for none.
func QUICInitial(dcid, scid []byte, server bool, packetNumber uint32, frames []byte, padTo int) []byte {
	k := quicInitialKeys(dcid, server)

	const pnLen = 2
	payload := frames
	if padTo > 0 {
		// Pad the frame payload so the finished packet reaches padTo.
		overhead := 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + pnLen + 16
		if n := padTo - overhead - len(payload); n > 0 {
			payload = append(append([]byte(nil), payload...), make([]byte, n)...)
		}
	}

	hdr := []byte{0xc0 | byte(pnLen-1)}
	hdr = binary.BigEndian.AppendUint32(hdr, QUICVersion1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00) // no token
	hdr = quicVarint(hdr, uint64(pnLen+len(payload)+16))

	pnOffset := len(hdr)
	pnBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pnBytes, packetNumber)
	hdr = append(hdr, pnBytes[4-pnLen:]...)

	nonce := append([]byte(nil), k.iv...)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:],
		binary.BigEndian.Uint64(nonce[len(nonce)-8:])^uint64(packetNumber))

	pkt := append(hdr, k.aead.Seal(nil, nonce, payload, hdr)...)

	var mask [16]byte
	k.hp.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}
