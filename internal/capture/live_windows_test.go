//go:build windows

package capture

import (
	"errors"
	"path/filepath"
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

	var serr *SetupError
	if !errors.As(err, &serr) {
		t.Fatalf("error is %T, want *SetupError so the hint is shown: %v", err, err)
	}
	for _, want := range []string{"npcap.com", "does not bundle", "tlscensus read"} {
		if !strings.Contains(serr.Hint, want) {
			t.Errorf("hint does not mention %q:\n%s", want, serr.Hint)
		}
	}

	// A missing driver is not a refused one. The message the user actually
	// reads is Error(), and asserting only on the hint is what let it say
	// "permission denied" to a machine that had simply never installed
	// Npcap — sending them after an elevated prompt that cannot help.
	if msg := err.Error(); strings.Contains(strings.ToLower(msg), "permission denied") {
		t.Errorf("missing-Npcap error reads as a permission failure:\n%s", msg)
	}

	// The two must stay distinguishable at a glance, since the install hint
	// and the permission hint are otherwise adjacent prose.
	var perr *PermissionError
	if errors.As(err, &perr) {
		t.Error("missing Npcap reported as *PermissionError")
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

// Interface selection is pure over the device list, which is the only reason
// it can be tested at all here: no Npcap, no adapters, no privilege.
//
// The cases below are the two ways the original first-wins matching went
// wrong silently — the failure mode that matters, because a capture on the
// wrong adapter looks exactly like a capture on the right one.
func TestPickDevice(t *testing.T) {
	devs := []winDevice{
		{InterfaceInfo: InterfaceInfo{Name: "Ethernet", Up: true, Addresses: []string{"10.0.0.2"}},
			device: `\Device\NPF_{AAAA1111-0000-0000-0000-000000000001}`},
		{InterfaceInfo: InterfaceInfo{Name: "Ethernet 2", Up: true, Addresses: []string{"10.0.0.3"}},
			device: `\Device\NPF_{BBBB2222-0000-0000-0000-000000000002}`},
		{InterfaceInfo: InterfaceInfo{Name: "Loopback", Up: true, Loopback: true, Addresses: []string{"127.0.0.1"}},
			device: `\Device\NPF_Loopback`},
	}

	for _, tt := range []struct {
		name    string
		want    string
		device  string
		wantErr string
	}{
		{name: "exact device path", want: devs[1].device, device: devs[1].device},
		// "Ethernet" is a whole adapter name and a prefix of another. The
		// name printed by `tlscensus interfaces` must resolve to the
		// adapter it was printed for.
		{name: "exact name beats substring", want: "Ethernet", device: devs[0].device},
		{name: "exact name is case-insensitive", want: "ethernet 2", device: devs[1].device},
		{name: "unambiguous substring", want: "net 2", device: devs[1].device},
		// Matches both Ethernet adapters: refuse rather than pick one.
		{name: "ambiguous substring", want: "ether", wantErr: "matches 2 interfaces"},
		// Every device path contains \Device\NPF_, so a Linux habit or a
		// short string must not resolve to an arbitrary GUID.
		{name: "device path fragment is ambiguous", want: "NPF_", wantErr: "matches 3 interfaces"},
		{name: "no match", want: "wlan0", wantErr: "no interface matching"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := pickDevice(devs, tt.want)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("pickDevice(%q) = %q, want an error", tt.want, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("pickDevice(%q) error = %q, want it to mention %q", tt.want, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("pickDevice(%q): %v", tt.want, err)
			}
			if got != tt.device {
				t.Errorf("pickDevice(%q) = %q, want %q", tt.want, got, tt.device)
			}
		})
	}
}

// An unnamed interface used to fall back to devs[0] — usually loopback or a
// WAN Miniport — producing a capture that runs forever and reports nothing.
func TestPickDefaultDevice(t *testing.T) {
	real := winDevice{
		InterfaceInfo: InterfaceInfo{Name: "Wi-Fi", Up: true, Addresses: []string{"192.168.1.5"}},
		device:        `\Device\NPF_{CCCC3333-0000-0000-0000-000000000003}`,
	}
	loop := winDevice{
		InterfaceInfo: InterfaceInfo{Name: "Loopback", Up: true, Loopback: true, Addresses: []string{"127.0.0.1"}},
		device:        `\Device\NPF_Loopback`,
	}
	unaddressed := winDevice{
		InterfaceInfo: InterfaceInfo{Name: "WAN Miniport", Up: true},
		device:        `\Device\NPF_{DDDD4444-0000-0000-0000-000000000004}`,
	}

	t.Run("skips loopback and unaddressed", func(t *testing.T) {
		got, _, err := pickDevice([]winDevice{loop, unaddressed, real}, "")
		if err != nil {
			t.Fatalf("pickDevice: %v", err)
		}
		if got != real.device {
			t.Errorf("default device = %q, want %q", got, real.device)
		}
	})

	// PCAP_IF_UP is the one flag not yet confirmed against a real Npcap. If
	// it is never set, requiring it would fail every unnamed capture, so the
	// second pass drops that check alone.
	t.Run("falls back when no device reports up", func(t *testing.T) {
		down := real
		down.Up = false
		got, _, err := pickDevice([]winDevice{loop, down}, "")
		if err != nil {
			t.Fatalf("pickDevice: %v", err)
		}
		if got != down.device {
			t.Errorf("default device = %q, want %q", got, down.device)
		}
	})

	// An adapter can be up and addressed and still be useless. A real
	// Windows laptop lists a Bluetooth PAN adapter, two Wi-Fi Direct
	// virtual adapters and an unplugged Ethernet port — all up, all
	// carrying a 169.254 and an fe80:: address — ahead of the Wi-Fi
	// adapter that has the route. "First with an address" picked the
	// Bluetooth one, and the capture reported nothing.
	t.Run("skips link-local-only adapters", func(t *testing.T) {
		linkLocal := winDevice{
			InterfaceInfo: InterfaceInfo{
				Name: "Bluetooth Device (Personal Area Network)", Up: true,
				Addresses: []string{"169.254.215.45", "fe80::3b91:dec9:531c:3b25"},
			},
			device: `\Device\NPF_{EEEE5555-0000-0000-0000-000000000005}`,
		}
		got, _, err := pickDevice([]winDevice{linkLocal, real}, "")
		if err != nil {
			t.Fatalf("pickDevice: %v", err)
		}
		if got != real.device {
			t.Errorf("default device = %q, want the routable adapter %q", got, real.device)
		}
	})

	t.Run("errors rather than picking a useless adapter", func(t *testing.T) {
		_, _, err := pickDevice([]winDevice{loop, unaddressed}, "")
		if err == nil {
			t.Fatal("pickDevice with no usable interface returned no error")
		}
		if !strings.Contains(err.Error(), "-i") {
			t.Errorf("error does not say how to proceed: %v", err)
		}
	})
}

// The two places Npcap can put its DLL, as absolute paths.
//
// Absolute is the point: loading by bare name searches the executable's own
// directory first, which would let a wpcap.dll sitting beside tlscensus.exe
// win over the real driver in a process users are told to run elevated.
func TestWpcapPathsAreAbsoluteAndBothLocations(t *testing.T) {
	paths := wpcapPaths()
	if len(paths) != 2 {
		t.Fatalf("wpcapPaths() = %v, want the two install locations", paths)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("%q is not absolute", p)
		}
		if strings.ToLower(filepath.Base(p)) != "wpcap.dll" {
			t.Errorf("%q does not name wpcap.dll", p)
		}
	}
	// The default install location must be preferred over the WinPcap
	// compatibility copy, and both must be offered.
	if got := filepath.Base(filepath.Dir(paths[0])); !strings.EqualFold(got, "Npcap") {
		t.Errorf("first candidate is in %q, want the Npcap directory first", got)
	}
	if got := filepath.Base(filepath.Dir(paths[1])); !strings.EqualFold(got, "System32") {
		t.Errorf("second candidate is in %q, want System32", got)
	}
}

// When nothing is found, the message has to name what was looked for. The
// os.Stat failure it replaced put "GetFileAttributesEx" and a single path in
// front of a user whose real problem was that Npcap was never installed.
func TestMissingNpcapNamesBothLocations(t *testing.T) {
	_, err := loadWpcap()
	if err == nil {
		t.Skip("Npcap is installed on this machine; nothing to check")
	}
	msg := err.Error()
	if strings.Contains(msg, "GetFileAttributesEx") {
		t.Errorf("error leaks a syscall name:\n%s", msg)
	}
	for _, p := range wpcapPaths() {
		if !strings.Contains(msg, p) {
			t.Errorf("error does not mention candidate %q:\n%s", p, msg)
		}
	}
}
