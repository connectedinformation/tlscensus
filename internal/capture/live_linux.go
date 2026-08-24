//go:build linux

package capture

import (
	"errors"
	"fmt"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Linux capture uses pcapgo's AF_PACKET handle, which is pure Go. That keeps
// the whole binary cgo-free: one build runner produces every release target,
// `go install` works with no libpcap headers, and the capture path has no
// C in it at all.
//
// Requires CAP_NET_RAW. Prefer granting that capability to the binary over
// running the whole process as root — see docs/permissions.md.

type linuxSource struct {
	h        *pcapgo.EthernetHandle
	iface    string
	linkType layers.LinkType
}

// OpenLive begins capturing on iface. An empty iface selects the default.
func OpenLive(iface string, opts LiveOptions) (Source, error) {
	opts.setDefaults()

	if iface == "" {
		var err error
		if iface, err = DefaultInterface(); err != nil {
			return nil, err
		}
	}

	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, &PermissionError{Op: "open AF_PACKET socket", Err: err, Hint: linuxPermissionHint()}
		}
		return nil, fmt.Errorf("capturing on %s: %w", iface, err)
	}

	if err := h.SetCaptureLength(opts.Snaplen); err != nil {
		h.Close()
		return nil, fmt.Errorf("setting snaplen: %w", err)
	}
	if opts.Promiscuous {
		if err := h.SetPromiscuous(true); err != nil {
			h.Close()
			return nil, fmt.Errorf("enabling promiscuous mode on %s: %w", iface, err)
		}
	}

	// AF_PACKET always delivers Ethernet frames.
	linkType := layers.LinkTypeEthernet
	if !opts.NoFilter {
		filter, err := TCPFilter(linkType, opts.Snaplen)
		if err != nil {
			h.Close()
			return nil, err
		}
		if filter != nil {
			if err := h.SetBPF(filter); err != nil {
				h.Close()
				return nil, fmt.Errorf("installing BPF filter: %w", err)
			}
		}
	}

	return &linuxSource{h: h, iface: iface, linkType: linkType}, nil
}

func (s *linuxSource) Next() ([]byte, gopacket.CaptureInfo, error) {
	return s.h.ReadPacketData()
}

func (s *linuxSource) LinkType() layers.LinkType { return s.linkType }
func (s *linuxSource) Name() string              { return s.iface }

func (s *linuxSource) Close() error {
	s.h.Close()
	return nil
}

func linuxPermissionHint() string {
	return `Packet capture needs CAP_NET_RAW.

Grant it to the binary once, rather than running the whole tool as root:

    sudo setcap cap_net_raw,cap_net_admin=eip $(which tlscensus)

Or run a single capture with:

    sudo tlscensus watch

CAP_NET_ADMIN is only needed for promiscuous mode (-promisc), which is off
by default.`
}
