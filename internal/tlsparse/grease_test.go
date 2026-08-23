package tlsparse

import "testing"

func TestIsGREASE(t *testing.T) {
	// The complete set from RFC 8701 section 1.
	all := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range all {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = false, want true", v)
		}
	}
	// Real codepoints that are close enough to catch a sloppy predicate.
	for _, v := range []uint16{0x1301, 0x0a0b, 0x0b0a, 0x1a1b, 0xc02f, 0x11ec, 0x0000} {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = true, want false", v)
		}
	}
}

func TestStripGREASE(t *testing.T) {
	in := []uint16{0x1a1a, 0x1301, 0x1302, 0xdada, 0x1303}
	out, found := stripGREASE(in)
	if !found {
		t.Fatal("found = false, want true")
	}
	want := []uint16{0x1301, 0x1302, 0x1303}
	if len(out) != len(want) {
		t.Fatalf("got %#04x, want %#04x", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("got %#04x, want %#04x", out, want)
		}
	}
	// No GREASE: must return the input untouched and allocate nothing.
	clean := []uint16{0x1301, 0x1302}
	out, found = stripGREASE(clean)
	if found {
		t.Error("found = true on a clean list")
	}
	if &out[0] != &clean[0] {
		t.Error("stripGREASE allocated for a clean list")
	}
}
