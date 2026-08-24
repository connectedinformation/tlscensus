package quic

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// seal builds a protected Initial packet.
//
// It is the inverse of Open, written out separately from the RFC rather than
// by reusing Open's code, so the round trip checks the two directions
// against each other instead of checking one against itself. The key
// derivation it relies on is already pinned to the RFC's own vectors in
// keys_test.go, so an agreement here is not both halves being wrong in the
// same way about labels or salts.
func seal(t *testing.T, version uint32, dcid, scid []byte, k *Keys, pn uint32, pnLen int, payload []byte) []byte {
	t.Helper()

	var hdr []byte
	first := byte(0xc0) | byte(TypeInitial<<4) | byte(pnLen-1)
	hdr = append(hdr, first)
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0x00) // zero-length token

	// Length covers the packet number plus the sealed payload.
	length := pnLen + len(payload) + 16
	hdr = appendVarint(hdr, uint64(length))

	pnOffset := len(hdr)
	pnBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pnBytes, pn)
	hdr = append(hdr, pnBytes[4-pnLen:]...)

	sealed := k.aead.Seal(nil, k.nonce(uint64(pn)), payload, hdr)
	pkt := append(hdr, sealed...)

	// Header protection is applied last, over the finished packet.
	if pnOffset+sampleOffset+sampleLen > len(pkt) {
		t.Fatalf("packet too short to sample: %d bytes", len(pkt))
	}
	mask := k.headerMask(pkt[pnOffset+sampleOffset : pnOffset+sampleOffset+sampleLen])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc0000000_00000000)
	}
}

func TestOpenRoundTrip(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	scid := mustHex(t, "f067a5502a4262b5")

	for _, version := range []uint32{Version1, Version2} {
		for _, pnLen := range []int{1, 2, 3, 4} {
			ck, err := DeriveInitialKeys(version, dcid, false)
			if err != nil {
				t.Fatal(err)
			}
			// The packet number has to fit in the bytes on the wire. QUIC
			// truncates it and expects the peer to reconstruct the rest,
			// which a passive observer cannot do — see Open. Sealing a
			// value too large for pnLen would test an assumption neither
			// side of a real connection makes.
			var pn uint32
			for i := 0; i < pnLen; i++ {
				pn = pn<<8 | uint32(i+1)
			}
			want := append([]byte{frameTypeCrypto, 0x00, 0x41, 0x00}, bytes.Repeat([]byte{0xab}, 256)...)
			pkt := seal(t, version, dcid, scid, ck, pn, pnLen, want)

			h, err := ParseLongHeader(pkt)
			if err != nil {
				t.Fatalf("v%#x pnLen=%d: %v", version, pnLen, err)
			}
			if h.Type != TypeInitial {
				t.Errorf("Type = %d, want Initial", h.Type)
			}
			if h.Version != version {
				t.Errorf("Version = %#x, want %#x", h.Version, version)
			}
			if !bytes.Equal(h.DCID, dcid) {
				t.Errorf("DCID = %x, want %x", h.DCID, dcid)
			}
			if !bytes.Equal(h.SCID, scid) {
				t.Errorf("SCID = %x, want %x", h.SCID, scid)
			}
			if h.End != len(pkt) {
				t.Errorf("End = %d, want %d", h.End, len(pkt))
			}

			gotPN, got, err := Open(pkt, h, ck)
			if err != nil {
				t.Fatalf("v%#x pnLen=%d: Open: %v", version, pnLen, err)
			}
			if gotPN != uint64(pn) {
				t.Errorf("packet number = %d, want %d", gotPN, pn)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("v%#x pnLen=%d: payload mismatch", version, pnLen)
			}
		}
	}
}

// The server's Initial is protected with keys from the client's *original*
// connection ID. Deriving from the server's own is the obvious mistake, and
// it must fail closed rather than return plausible rubbish.
func TestServerKeysComeFromClientDCID(t *testing.T) {
	clientDCID := mustHex(t, "8394c8f03e515708")
	serverSCID := mustHex(t, "f067a5502a4262b5")

	sk, err := DeriveInitialKeys(Version1, clientDCID, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{frameTypeCrypto, 0x00, 0x41, 0x00}, bytes.Repeat([]byte{0xcd}, 256)...)
	pkt := seal(t, Version1, serverSCID, clientDCID, sk, 1, 2, payload)

	h, err := ParseLongHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(pkt, h, sk); err != nil {
		t.Fatalf("opening with the client's original DCID failed: %v", err)
	}

	wrong, err := DeriveInitialKeys(Version1, serverSCID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(pkt, h, wrong); err == nil {
		t.Error("opening with the server's own connection ID succeeded; it must not")
	}
}

// A datagram usually carries an Initial followed by a Handshake packet. The
// Initial's End is where the next one starts, and reading past it would feed
// encrypted Handshake bytes to the TLS parser.
func TestCoalescedPacketsAreDelimited(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	k, err := DeriveInitialKeys(Version1, dcid, false)
	if err != nil {
		t.Fatal(err)
	}
	initial := seal(t, Version1, dcid, nil, k, 0, 2,
		append([]byte{frameTypeCrypto, 0x00, 0x40, 0x40}, bytes.Repeat([]byte{0x11}, 64)...))
	trailing := bytes.Repeat([]byte{0xe5}, 120) // a Handshake packet, undecryptable here
	datagram := append(append([]byte{}, initial...), trailing...)

	h, err := ParseLongHeader(datagram)
	if err != nil {
		t.Fatal(err)
	}
	if h.End != len(initial) {
		t.Errorf("End = %d, want %d (the Initial's own length)", h.End, len(initial))
	}
	if _, _, err := Open(datagram, h, k); err != nil {
		t.Errorf("Open failed on a coalesced datagram: %v", err)
	}
}

func TestRejectsNonQUIC(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":               nil,
		"short header":        {0x40, 0x01, 0x02},
		"dns":                 {0x12, 0x34, 0x01, 0x00, 0x00, 0x01},
		"version negotiation": append([]byte{0xc0, 0, 0, 0, 0}, bytes.Repeat([]byte{0}, 8)...),
	} {
		if _, err := ParseLongHeader(b); err == nil {
			t.Errorf("%s: parsed as a QUIC long header", name)
		}
	}
}

func TestCryptoFrames(t *testing.T) {
	// Padding, a ping, an ack with one range, then two crypto frames.
	var payload []byte
	payload = append(payload, 0x00, 0x00, 0x00)             // PADDING
	payload = append(payload, 0x01)                         // PING
	payload = append(payload, 0x02, 0x05, 0x00, 0x01, 0x00) // ACK: largest 5, delay 0, 1 range, first 0
	payload = append(payload, 0x00, 0x02)                   // ...that range: gap 0, length 2
	payload = append(payload, 0x06, 0x00, 0x04, 'a', 'b', 'c', 'd')
	payload = append(payload, 0x06, 0x04, 0x03, 'e', 'f', 'g')
	payload = append(payload, 0x00, 0x00) // trailing padding

	frames := CryptoFrames(payload)
	if len(frames) != 2 {
		t.Fatalf("got %d crypto frames, want 2", len(frames))
	}
	if frames[0].Offset != 0 || string(frames[0].Data) != "abcd" {
		t.Errorf("frame 0 = %d/%q", frames[0].Offset, frames[0].Data)
	}
	if frames[1].Offset != 4 || string(frames[1].Data) != "efg" {
		t.Errorf("frame 1 = %d/%q", frames[1].Offset, frames[1].Data)
	}
}
