//go:build windows

package capture

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// These assertions are the whole reason this file exists.
//
// Every bug that reached a green CI run on the other two platforms lived in
// a struct definition that could not be checked from the machine it was
// written on: the BSD ioctl calling convention, and a bh_hdrlen compared
// against sizeof rather than the field size. The equivalent trap here is
// LLP64 — Windows keeps `long` at 32 bits where Unix widens it to 64 — so
// `struct timeval` inside `struct pcap_pkthdr` is 8 bytes on Windows and 16
// on 64-bit Unix.
//
// Getting that wrong shifts caplen and len by eight bytes, which does not
// crash: it silently yields absurd lengths and no usable packets. Unlike a
// hand-written parser there is nothing to unit-test, so the layout itself is
// asserted, and CI runs this on a real Windows machine.
func TestPcapStructLayout(t *testing.T) {
	// struct timeval on Windows: two 32-bit longs, on every architecture.
	if got := unsafe.Sizeof(pcapTimeval{}); got != 8 {
		t.Errorf("sizeof(struct timeval) = %d, want 8 — Windows `long` is 32-bit under LLP64", got)
	}
	// struct pcap_pkthdr { timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
	if got := unsafe.Sizeof(pcapPkthdr{}); got != 16 {
		t.Errorf("sizeof(struct pcap_pkthdr) = %d, want 16", got)
	}
	var h pcapPkthdr
	base := uintptr(unsafe.Pointer(&h))
	for _, tt := range []struct {
		field string
		ptr   unsafe.Pointer
		want  uintptr
	}{
		{"ts", unsafe.Pointer(&h.Ts), 0},
		{"caplen", unsafe.Pointer(&h.Caplen), 8},
		{"len", unsafe.Pointer(&h.Len), 12},
	} {
		if got := uintptr(tt.ptr) - base; got != tt.want {
			t.Errorf("offsetof(pcap_pkthdr.%s) = %d, want %d", tt.field, got, tt.want)
		}
	}

	// struct bpf_insn { u_short code; u_char jt; u_char jf; bpf_u_int32 k; }
	if got := unsafe.Sizeof(bpfInsn{}); got != 8 {
		t.Errorf("sizeof(struct bpf_insn) = %d, want 8", got)
	}

	// struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }
	// The pointer is aligned, so the struct is 16 bytes on amd64 and 8 on
	// 386 — Go inserts the same padding the C compiler does.
	var p bpfProgram
	wantSize := 2 * unsafe.Sizeof(uintptr(0))
	if got := unsafe.Sizeof(p); got != wantSize {
		t.Errorf("sizeof(struct bpf_program) = %d, want %d", got, wantSize)
	}
	if got := uintptr(unsafe.Pointer(&p.Insns)) - uintptr(unsafe.Pointer(&p)); got != unsafe.Sizeof(uintptr(0)) {
		t.Errorf("offsetof(bpf_program.bf_insns) = %d, want %d", got, unsafe.Sizeof(uintptr(0)))
	}
}

// pcap_findalldevs walks a linked list of these, so a wrong layout means
// reading a pointer out of the middle of another field.
func TestPcapIfLayout(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))
	if got, want := unsafe.Sizeof(pcapIf{}), 4*ptr+ptr; got != want {
		// four pointers plus a uint32 padded to pointer alignment
		t.Errorf("sizeof(struct pcap_if) = %d, want %d", got, want)
	}
	var d pcapIf
	base := uintptr(unsafe.Pointer(&d))
	for _, tt := range []struct {
		field string
		ptr   unsafe.Pointer
		want  uintptr
	}{
		{"next", unsafe.Pointer(&d.Next), 0},
		{"name", unsafe.Pointer(&d.Name), ptr},
		{"description", unsafe.Pointer(&d.Description), 2 * ptr},
		{"addresses", unsafe.Pointer(&d.Addresses), 3 * ptr},
		{"flags", unsafe.Pointer(&d.Flags), 4 * ptr},
	} {
		if got := uintptr(tt.ptr) - base; got != tt.want {
			t.Errorf("offsetof(pcap_if.%s) = %d, want %d", tt.field, got, tt.want)
		}
	}
}

// A machine without Npcap must get an explanation, not a crash and not a
// bare "file not found". CI runs on exactly such a machine, which makes this
// the one live-capture path that is genuinely covered automatically.
func TestWithoutNpcapExplainsHow(t *testing.T) {
	_, err := loadWpcap()
	if err == nil {
		t.Skip("Npcap is installed on this machine; nothing to check")
	}

	var perr *PermissionError
	if !errors.As(err, &perr) {
		t.Fatalf("error is %T, want *PermissionError so the hint is shown: %v", err, err)
	}
	for _, want := range []string{"npcap.com", "does not bundle", "tlscensus read"} {
		if !strings.Contains(perr.Hint, want) {
			t.Errorf("hint does not mention %q:\n%s", want, perr.Hint)
		}
	}

	// OpenLive must surface the same thing rather than panicking on a nil
	// DLL handle.
	if _, err := OpenLive("", LiveOptions{}); err == nil {
		t.Error("OpenLive succeeded with no Npcap installed")
	}
}

// Listing interfaces must work with or without Npcap: it is what a user runs
// first, and erroring there tells them nothing.
func TestInterfacesWithoutNpcap(t *testing.T) {
	if _, err := Interfaces(); err != nil {
		t.Errorf("Interfaces() failed: %v", err)
	}
}
