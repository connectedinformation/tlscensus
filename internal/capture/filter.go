package capture

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// CaptureFilter returns a kernel BPF program that keeps the traffic a TLS
// inventory can learn from — TCP and UDP — and drops everything else.
//
// UDP is here for QUIC. Restricting it to port 443 would be the same mistake
// as restricting TCP to 443, and the userspace check that follows is cheap:
// a QUIC Initial has the top two bits of its first byte set, so almost all
// other UDP traffic is rejected on one byte.
//
// The filter runs in the kernel, so what it rejects costs nothing. What it
// accepts is deliberately wider than strictly necessary:
//
// IPv6 is accepted wholesale rather than checked for next_header == TCP. A
// packet carrying a Hop-by-Hop or Routing extension header has a next_header
// that is not 6, and a filter that tested that byte would silently drop
// every such flow. Walking an extension header chain in BPF is possible and
// not worth it; gopacket decodes them correctly a few microseconds later.
// Undercounting is the failure mode this tool exists to avoid, and IPv6 is a
// minority of traffic on the hosts it will run on.
//
// IPv4 fragments are also accepted: a non-first fragment carries protocol 6
// with no TCP header, and is discarded harmlessly during decode.
//
// An unsupported link type returns a nil program, meaning no kernel filter.
// That is correct but slower, never wrong.
func CaptureFilter(lt layers.LinkType, snaplen int) ([]bpf.RawInstruction, error) {
	var insns []bpf.Instruction

	switch lt {
	case layers.LinkTypeEthernet:
		insns = []bpf.Instruction{
			// 0: ethertype
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// 1: IPv6 -> accept (7)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 5, SkipFalse: 0},
			// 2: IPv4 -> 3, else drop (6)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 3},
			// 3: IPv4 protocol byte
			bpf.LoadAbsolute{Off: 23, Size: 1},
			// 4: TCP -> accept (7), else 5
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 2, SkipFalse: 0},
			// 5: UDP -> accept (7), else drop (6)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 1, SkipFalse: 0},
			// 6: drop
			bpf.RetConstant{Val: 0},
			// 7: accept
			bpf.RetConstant{Val: uint32(snaplen)},
		}
	default:
		// Raw IP, loopback (DLT_NULL), pktap and friends all use different
		// offsets. Filtering in userspace is correct for all of them.
		return nil, nil
	}

	raw, err := bpf.Assemble(insns)
	if err != nil {
		return nil, fmt.Errorf("assembling BPF filter: %w", err)
	}
	return raw, nil
}
