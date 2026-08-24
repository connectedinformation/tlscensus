package capture

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// TCPFilter returns a kernel BPF program that keeps TCP traffic and drops
// everything else, for the given link type.
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
func TCPFilter(lt layers.LinkType, snaplen int) ([]bpf.RawInstruction, error) {
	var insns []bpf.Instruction

	switch lt {
	case layers.LinkTypeEthernet:
		insns = []bpf.Instruction{
			// 0: ethertype
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// 1: IPv6 -> accept (6)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 4, SkipFalse: 0},
			// 2: IPv4 -> 3, else drop (5)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 2},
			// 3: IPv4 protocol byte
			bpf.LoadAbsolute{Off: 23, Size: 1},
			// 4: TCP -> accept (6), else drop (5)
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 1, SkipFalse: 0},
			// 5: drop
			bpf.RetConstant{Val: 0},
			// 6: accept
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
