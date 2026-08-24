package quic

import (
	"encoding/hex"
	"testing"
)

// Vectors from RFC 9001 appendix A.1, for the connection whose client chose
// Destination Connection ID 0x8394c8f03e515708.
//
// These are the reason this package can be trusted at all. Every other check
// available here would compare the code against itself — encrypting with the
// same derivation that decrypts proves only that it is self-consistent. The
// RFC publishes the expected bytes, so the derivation is checked against the
// specification instead.
func TestRFC9001InitialKeys(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")

	for _, tt := range []struct {
		name        string
		server      bool
		key, iv, hp string
	}{
		{
			name: "client",
			key:  "1f369613dd76d5467730efcbe3b1a22d",
			iv:   "fa044b2f42a3fd3b46fb255c",
			hp:   "9f50449e04a0e810283a1e9933adedd2",
		},
		{
			name:   "server",
			server: true,
			key:    "cf3a5331653c364c88f0f379b6067e37",
			iv:     "0ac1493ca1905853b0bba03e",
			hp:     "c206b8d9b9f0f37644430b490eeaa314",
		},
	} {
		key, iv, hp, err := initialKeyMaterial(Version1, dcid, tt.server)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		for _, f := range []struct {
			field string
			got   []byte
			want  string
		}{
			{"key", key, tt.key},
			{"iv", iv, tt.iv},
			{"hp", hp, tt.hp},
		} {
			if got := hex.EncodeToString(f.got); got != f.want {
				t.Errorf("%s %s = %s, want %s", tt.name, f.field, got, f.want)
			}
		}
	}
}

func TestUnsupportedVersion(t *testing.T) {
	// draft versions used a different salt, so deriving with the v1 salt
	// would produce keys that fail to authenticate — worse than refusing.
	if _, err := DeriveInitialKeys(0xff00001d, []byte{1, 2, 3, 4}, false); err != ErrUnsupportedVersion {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}
	if Supported(0xff00001d) {
		t.Error("a draft version reported as supported")
	}
	for _, v := range []uint32{Version1, Version2} {
		if !Supported(v) {
			t.Errorf("version %#x reported as unsupported", v)
		}
	}
}

func TestVarint(t *testing.T) {
	// RFC 9000 section 16 worked examples.
	for _, tt := range []struct {
		hexBytes string
		want     uint64
		wantN    int
	}{
		{"c2197c5eff14e88c", 151288809941952652, 8},
		{"9d7f3e7d", 494878333, 4},
		{"7bbd", 15293, 2},
		{"25", 37, 1},
		{"4025", 37, 2}, // the same value in a longer encoding
	} {
		b := mustHex(t, tt.hexBytes)
		got, n, ok := readVarint(b)
		if !ok {
			t.Errorf("%s: readVarint failed", tt.hexBytes)
			continue
		}
		if got != tt.want || n != tt.wantN {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", tt.hexBytes, got, n, tt.want, tt.wantN)
		}
	}
	if _, _, ok := readVarint(nil); ok {
		t.Error("readVarint accepted empty input")
	}
	if _, _, ok := readVarint([]byte{0xc0, 0x01}); ok {
		t.Error("readVarint accepted a truncated 8-byte encoding")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
