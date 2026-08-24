package capture

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// The filter is hand-assembled, so its jump offsets are exactly the kind of
// thing that is wrong in a way no compiler catches and no ordinary test
// exercises. x/net/bpf ships a VM, so the real kernel program can be run
// against real packet bytes here, with no privileges and no interface.
func TestCaptureFilter(t *testing.T) {
	raw, err := CaptureFilter(layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("no program produced for Ethernet")
	}

	insns := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		insns[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("filter is not a valid BPF program: %v", err)
	}

	tests := []struct {
		name   string
		packet []byte
		accept bool
	}{
		{"ipv4 tcp", ethFrame(0x0800, ipv4(6)), true},
		// UDP is accepted for QUIC; the cheap first-byte check that
		// separates QUIC from DNS and everything else runs in userspace.
		{"ipv4 udp", ethFrame(0x0800, ipv4(17)), true},
		{"ipv4 icmp", ethFrame(0x0800, ipv4(1)), false},
		// Accepted wholesale so extension-header chains are never dropped.
		{"ipv6 tcp", ethFrame(0x86dd, ipv6(6)), true},
		{"ipv6 hop-by-hop", ethFrame(0x86dd, ipv6(0)), true},
		{"arp", ethFrame(0x0806, make([]byte, 28)), false},
		{"runt", []byte{0, 1, 2, 3}, false},
	}
	for _, tt := range tests {
		n, err := vm.Run(tt.packet)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got := n > 0; got != tt.accept {
			t.Errorf("%s: accepted = %v, want %v", tt.name, got, tt.accept)
		}
	}
}

// Every real TCP packet in the sample capture must survive the filter. If
// the offsets are wrong this is what notices.
func TestCaptureFilterPassesSampleCapture(t *testing.T) {
	raw, err := CaptureFilter(layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	insns := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		insns[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatal(err)
	}

	src, err := OpenFile("../../testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	var total, passed int
	for {
		data, _, err := src.Next()
		if err != nil {
			break
		}
		total++
		n, err := vm.Run(data)
		if err != nil {
			t.Fatalf("packet %d: %v", total, err)
		}
		if n > 0 {
			passed++
		}
	}
	if total == 0 {
		t.Fatal("read no packets")
	}
	// The sample capture is TCP end to end, IPv4 and IPv6.
	if passed != total {
		t.Errorf("filter passed %d of %d packets; every one is TCP", passed, total)
	}
}

func TestCaptureFilterUnknownLinkTypeIsUnfiltered(t *testing.T) {
	// A nil program means "no kernel filter", which is slower but never
	// drops anything. Returning an error here would break capture on
	// loopback and pktap.
	raw, err := CaptureFilter(layers.LinkTypeNull, 65535)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != nil {
		t.Error("expected no program for an unhandled link type")
	}
}

func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(f[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	f[12] = byte(etherType >> 8)
	f[13] = byte(etherType)
	return append(f, payload...)
}

func ipv4(proto byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[9] = proto // offset 23 in the frame
	return h
}

func ipv6(nextHeader byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = nextHeader // offset 20 in the frame
	return h
}

var _ = gopacket.CaptureInfo{}
