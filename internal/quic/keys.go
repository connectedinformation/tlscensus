package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// QUIC versions whose Initial keys this package can derive.
const (
	Version1 uint32 = 0x00000001 // RFC 9000
	Version2 uint32 = 0x6b3343cf // RFC 9369
)

// Initial salts, one per version (RFC 9001 section 5.2, RFC 9369 section 3.3.1).
var (
	initialSaltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	initialSaltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

// Supported reports whether initial keys can be derived for a version.
func Supported(version uint32) bool {
	return version == Version1 || version == Version2
}

func saltFor(version uint32) []byte {
	if version == Version2 {
		return initialSaltV2
	}
	return initialSaltV1
}

// Version 2 renames the key labels but keeps the derivation identical.
func labelsFor(version uint32) (key, iv, hp string) {
	if version == Version2 {
		return "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	return "quic key", "quic iv", "quic hp"
}

// Keys are the Initial-level secrets for one direction.
type Keys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// DeriveInitialKeys computes the Initial keys for one direction of a
// connection, from the Destination Connection ID the client chose for its
// very first packet.
//
// The same connection ID derives both directions: the server's Initial
// packets are protected with keys from the client's *original* DCID, not
// from the connection ID the server later selects. Using the server's own
// connection ID is the obvious mistake and produces an authentication
// failure rather than anything diagnostic.
func DeriveInitialKeys(version uint32, originalDCID []byte, server bool) (*Keys, error) {
	keyBytes, iv, hpBytes, err := initialKeyMaterial(version, originalDCID, server)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hpBlock, err := aes.NewCipher(hpBytes)
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, iv: iv, hp: hpBlock}, nil
}

// initialKeyMaterial derives the raw key, IV and header-protection key.
//
// Split out from DeriveInitialKeys so the values can be compared directly
// against the vectors in RFC 9001 appendix A. Checking the derivation
// against the RFC rather than against a round-trip of this same code is the
// difference between testing the spec and testing an assumption.
func initialKeyMaterial(version uint32, originalDCID []byte, server bool) (key, iv, hp []byte, err error) {
	if !Supported(version) {
		return nil, nil, nil, ErrUnsupportedVersion
	}
	newHash := func() hash.Hash { return sha256.New() }

	initialSecret, err := hkdf.Extract(newHash, originalDCID, saltFor(version))
	if err != nil {
		return nil, nil, nil, err
	}
	label := "client in"
	if server {
		label = "server in"
	}
	secret, err := expandLabel(newHash, initialSecret, label, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	keyLabel, ivLabel, hpLabel := labelsFor(version)
	if key, err = expandLabel(newHash, secret, keyLabel, 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(newHash, secret, ivLabel, 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = expandLabel(newHash, secret, hpLabel, 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// expandLabel is HKDF-Expand-Label from TLS 1.3 (RFC 8446 section 7.1),
// which QUIC reuses unchanged. The label always carries the "tls13 " prefix,
// even for the quic-specific labels.
func expandLabel(newHash func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	return hkdf.Expand(newHash, secret, string(info), length)
}

// nonce combines the static IV with the packet number, right-aligned
// (RFC 9001 section 5.3).
func (k *Keys) nonce(packetNumber uint64) []byte {
	n := make([]byte, len(k.iv))
	copy(n, k.iv)
	binary.BigEndian.PutUint64(n[len(n)-8:], binary.BigEndian.Uint64(n[len(n)-8:])^packetNumber)
	return n
}

// headerMask returns the five mask bytes for header protection, from a
// 16-byte sample of the packet's ciphertext (RFC 9001 section 5.4.3).
func (k *Keys) headerMask(sample []byte) [5]byte {
	var out [16]byte
	k.hp.Encrypt(out[:], sample)
	return [5]byte{out[0], out[1], out[2], out[3], out[4]}
}
