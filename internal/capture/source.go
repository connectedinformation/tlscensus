// Package capture provides packet sources.
//
// Everything downstream consumes the Source interface, so an offline pcap
// file, a live libpcap handle and a future eBPF or ETW backend are
// interchangeable. Offline reading is not only a test convenience: it is how
// the tool is used against captures taken elsewhere, and it is the reason
// the entire pipeline can be exercised in CI without privileges.
package capture

import (
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Source yields packets until it is exhausted or closed.
type Source interface {
	// Next returns the next packet. It returns io.EOF when the source is
	// exhausted. Data is only valid until the following call.
	Next() (data []byte, ci gopacket.CaptureInfo, err error)
	// LinkType reports the link layer of the packets this source yields.
	LinkType() layers.LinkType
	// Name identifies the source in logs and reports.
	Name() string
	Close() error
}

// Done reports whether err signals normal exhaustion rather than a fault.
func Done(err error) bool { return err == io.EOF }
