//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
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
		if permissionDenied(iface) {
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
		filter, err := CaptureFilter(linkType, opts.Snaplen)
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

// permissionDenied reports whether OpenLive failed for lack of CAP_NET_RAW.
//
// It cannot be answered from the error pcapgo returns. NewEthernetHandle
// formats the errno with %s rather than %w, so the syscall error is not in
// the chain and errors.Is(err, os.ErrPermission) is always false — which
// silently cost every unprivileged user the hint below, the single most
// common first experience of this tool. The darwin path opens its BPF device
// itself and checks unix.EPERM directly; here the only way to learn the same
// thing is to make the failing syscall again and read its errno.
//
// A missing interface is not a permission problem, and unprivileged callers
// hit EPERM whatever they name, so the interface is checked first.
func permissionDenied(iface string) bool {
	if _, err := net.InterfaceByName(iface); err != nil {
		return false
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
	}
	unix.Close(fd)
	return false
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
