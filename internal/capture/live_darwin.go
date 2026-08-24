//go:build darwin

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

// macOS capture talks to a /dev/bpf device directly rather than through
// libpcap. That keeps the binary cgo-free, which is what lets one build
// runner produce every release target and `go install` work with no
// libpcap headers present.
//
// Requires read access to a BPF device, which is root-only by default. See
// docs/permissions.md for the group-based alternative to running as root.

const (
	// Darwin defines BPF_ALIGNMENT as sizeof(int32_t).
	bpfAlignment = 4
	// Bytes of actual fields in struct bpf_hdr: an 8-byte timeval32, two
	// uint32 lengths and a uint16 header length.
	//
	// Note this is 18, not sizeof(struct bpf_hdr). The C struct is padded
	// to 20 for alignment, but the kernel sets bh_hdrlen to the unpadded
	// field size and places the packet data at that offset. Requiring 20
	// here rejects every real packet as malformed — and does so silently,
	// because the caller simply discards the read buffer and loops. The
	// symptom is a capture that runs forever and reports nothing.
	//
	// bh_hdrlen remains authoritative for where the data starts; this is
	// only the minimum that must be present to read the header fields.
	bpfHdrLen = 18
	// Number of /dev/bpfN devices to try. They are exclusive-open, so a
	// busy device means someone else is capturing, not a failure.
	bpfDeviceCount = 256
)

func bpfWordAlign(x int) int {
	return (x + bpfAlignment - 1) &^ (bpfAlignment - 1)
}

type darwinSource struct {
	fd       int
	iface    string
	device   string
	linkType layers.LinkType
	buf      []byte
	pending  []byte
	closed   atomic.Bool
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

	fd, device, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	s := &darwinSource{fd: fd, iface: iface, device: device}
	if err := s.configure(iface, opts); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// openBPFDevice claims the first free /dev/bpfN.
func openBPFDevice() (fd int, device string, err error) {
	var firstErr error
	for i := 0; i < bpfDeviceCount; i++ {
		device = fmt.Sprintf("/dev/bpf%d", i)
		fd, err = unix.Open(device, unix.O_RDONLY, 0)
		if err == nil {
			return fd, device, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		// EBUSY means another process holds this device; keep looking.
		// EACCES/EPERM will be the same for every device, so stop early
		// and report the permission problem rather than 256 of them.
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return -1, device, &PermissionError{
				Op: "open BPF device", Path: device, Err: err, Hint: darwinPermissionHint(),
			}
		}
	}
	return -1, "", fmt.Errorf("no free BPF device: %w", firstErr)
}

func (s *darwinSource) configure(iface string, opts LiveOptions) error {
	// Buffer length must be set before the interface is attached.
	if err := ioctlSetU32(s.fd, unix.BIOCSBLEN, uint32(opts.BufferBytes)); err != nil {
		return fmt.Errorf("setting BPF buffer length: %w", err)
	}

	// BIOCSETIF takes a struct ifreq: 16 bytes of name plus a 16-byte
	// union. The kernel reads all 32, so the buffer must be that long
	// regardless of how short the interface name is.
	var ifr [unix.IFNAMSIZ + 16]byte
	if len(iface) >= unix.IFNAMSIZ {
		return fmt.Errorf("interface name %q is too long", iface)
	}
	copy(ifr[:], iface)
	if err := ioctlPtr(s.fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return &PermissionError{Op: "attach to " + iface, Err: err, Hint: darwinPermissionHint()}
		}
		return fmt.Errorf("attaching BPF to %s: %w", iface, err)
	}

	// Immediate mode: deliver each packet as it arrives instead of waiting
	// for the buffer to fill. Without it a quiet interface reports nothing
	// for minutes at a time.
	if err := ioctlSetU32(s.fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fmt.Errorf("enabling immediate mode: %w", err)
	}

	// A read timeout is what makes shutdown responsive: reads return empty
	// periodically so Close can be noticed. Closing the fd under a blocked
	// read would work too, and would race with descriptor reuse.
	tv := unix.NsecToTimeval(int64(opts.ReadTimeout))
	if err := ioctlPtr(s.fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("setting read timeout: %w", err)
	}

	if opts.Promiscuous {
		// BIOCPROMISC is IOC_VOID: it takes no argument at all.
		if err := ioctlVoid(s.fd, unix.BIOCPROMISC); err != nil {
			return fmt.Errorf("enabling promiscuous mode: %w", err)
		}
	}

	dlt, err := ioctlGetU32(s.fd, unix.BIOCGDLT)
	if err != nil {
		return fmt.Errorf("reading link type: %w", err)
	}
	s.linkType = layers.LinkType(dlt)
	switch s.linkType {
	case layers.LinkTypeEthernet, layers.LinkTypeNull, layers.LinkTypeLoop, layers.LinkTypeRaw:
	default:
		// Notably this rejects pktap (Apple's per-process pseudo-device).
		// Returning zero flows because nothing decodes would be a much
		// worse failure than saying so.
		return fmt.Errorf("interface %s has link type %d, which is not decoded yet "+
			"(pktap support is M6; see docs/roadmap.md)", iface, dlt)
	}

	if !opts.NoFilter {
		if err := s.setFilter(opts.Snaplen); err != nil {
			return err
		}
	}

	// The kernel may have rounded the buffer length; always allocate what
	// it actually chose, or reads will be truncated.
	blen, err := ioctlGetU32(s.fd, unix.BIOCGBLEN)
	if err != nil {
		return fmt.Errorf("reading BPF buffer length: %w", err)
	}
	if blen == 0 {
		return errors.New("kernel reported a zero-length BPF buffer")
	}
	s.buf = make([]byte, blen)
	return nil
}

func (s *darwinSource) setFilter(snaplen int) error {
	raw, err := CaptureFilter(s.linkType, snaplen)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	insns := make([]unix.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	if err := ioctlPtr(s.fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil {
		return fmt.Errorf("installing BPF filter: %w", err)
	}
	// insns must outlive the ioctl; the kernel copies it, but keep the
	// slice reachable until then regardless.
	runtimeKeepAlive(insns)
	return nil
}

func (s *darwinSource) Next() ([]byte, gopacket.CaptureInfo, error) {
	for {
		if s.closed.Load() {
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
		if len(s.pending) > 0 {
			data, ci, rest, err := nextBPFPacket(s.pending)
			s.pending = rest
			if err == nil {
				return data, ci, nil
			}
			// A malformed or partial trailer ends this read buffer; the
			// next read starts cleanly at a packet boundary.
			s.pending = nil
			continue
		}

		n, err := unix.Read(s.fd, s.buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			if s.closed.Load() {
				return nil, gopacket.CaptureInfo{}, io.EOF
			}
			return nil, gopacket.CaptureInfo{}, err
		}
		if n <= 0 {
			// Read timeout expired with nothing captured.
			continue
		}
		s.pending = s.buf[:n]
	}
}

func (s *darwinSource) LinkType() layers.LinkType { return s.linkType }
func (s *darwinSource) Name() string              { return s.iface }

func (s *darwinSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return unix.Close(s.fd)
}

// errBPFBufferEnd means the remaining bytes do not hold a complete packet.
var errBPFBufferEnd = errors.New("capture: end of BPF read buffer")

// nextBPFPacket splits one packet off the front of a BPF read buffer.
//
// A single read() returns many packets, each preceded by a struct bpf_hdr
// and padded so the next header is word-aligned. bh_hdrlen is authoritative
// for where the data starts: it includes alignment padding that varies by
// architecture, so computing it from the Go struct size would be wrong on
// some platforms and right on others, which is the worst kind of bug.
//
// This is a pure function over bytes precisely so it can be tested without
// a BPF device, and therefore without root.
func nextBPFPacket(buf []byte) (data []byte, ci gopacket.CaptureInfo, rest []byte, err error) {
	if len(buf) < bpfHdrLen {
		return nil, ci, nil, errBPFBufferEnd
	}
	e := binary.NativeEndian
	var (
		tsSec   = int64(int32(e.Uint32(buf[0:4])))
		tsUsec  = int64(int32(e.Uint32(buf[4:8])))
		capLen  = int(e.Uint32(buf[8:12]))
		dataLen = int(e.Uint32(buf[12:16]))
		hdrLen  = int(e.Uint16(buf[16:18]))
	)

	if hdrLen < bpfHdrLen || capLen < 0 || dataLen < 0 {
		return nil, ci, nil, errBPFBufferEnd
	}
	end := hdrLen + capLen
	if end > len(buf) {
		return nil, ci, nil, errBPFBufferEnd
	}

	ci = gopacket.CaptureInfo{
		Timestamp:      time.Unix(tsSec, tsUsec*1000),
		CaptureLength:  capLen,
		Length:         dataLen,
		InterfaceIndex: 0,
	}

	next := bpfWordAlign(end)
	if next >= len(buf) {
		rest = nil
	} else {
		rest = buf[next:]
	}
	return buf[hdrLen:end], ci, rest, nil
}

// BSD ioctls encoded with _IOW or _IOR take a *pointer* to their argument.
// This is the opposite of the Linux convention, where an int argument is
// commonly passed by value — and it is why x/sys/unix's IoctlSetInt, which
// passes uintptr(value) directly, cannot be used for any of the BPF calls.
// Doing so makes the kernel dereference the value as an address and return
// EFAULT, which reads like a memory bug rather than a calling-convention
// mismatch. Every BPF ioctl argument here is a u_int, so these helpers are
// explicitly 32-bit rather than relying on a Go int happening to alias
// correctly on little-endian.

func ioctlSetU32(fd int, req uint, v uint32) error {
	return ioctlPtr(fd, req, unsafe.Pointer(&v))
}

func ioctlGetU32(fd int, req uint) (uint32, error) {
	var v uint32
	err := ioctlPtr(fd, req, unsafe.Pointer(&v))
	return v, err
}

// ioctlVoid issues an IOC_VOID request, which carries no argument.
func ioctlVoid(fd int, req uint) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), 0); e != 0 {
		return e
	}
	return nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func darwinPermissionHint() string {
	return `Packet capture reads /dev/bpf*, which is root-only by default.

Quickest:

    sudo tlscensus watch

Better, and what Wireshark installs for the same reason — grant a group
access to the BPF devices instead of running the whole tool as root:

    sudo dseditgroup -o create -q access_bpf
    sudo dseditgroup -o edit -a "$USER" -t user access_bpf
    sudo chgrp access_bpf /dev/bpf*
    sudo chmod g+r /dev/bpf*

The device permissions reset on reboot; Wireshark ships a launch daemon
(ChmodBPF) to reapply them. Log out and back in for the group to take
effect.`
}
