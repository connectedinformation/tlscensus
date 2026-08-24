package capture

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"
)

// LiveOptions configures a live capture. The zero value is usable.
type LiveOptions struct {
	// Snaplen is the maximum bytes captured per packet.
	Snaplen int

	// Promiscuous puts the interface into promiscuous mode.
	//
	// Off by default, deliberately. This is an endpoint inventory: the
	// question is what *this host* negotiates, and promiscuous mode answers
	// a different and much more invasive one — it captures the neighbours'
	// traffic too, on any network where that is still possible. Defaulting
	// to on would make a tool that reads hostnames quietly collect other
	// people's.
	Promiscuous bool

	// BufferBytes is the kernel capture buffer size. Larger buffers lose
	// fewer packets in bursts at the cost of latency.
	BufferBytes int

	// ReadTimeout bounds how long a read blocks before returning empty, so
	// that shutdown is responsive on a quiet interface.
	ReadTimeout time.Duration

	// NoFilter disables the kernel BPF filter and passes every packet to
	// userspace. Useful when a link type has no filter or when debugging a
	// suspected filter bug.
	NoFilter bool
}

const (
	defaultSnaplen     = 65535
	defaultBufferBytes = 4 << 20
	defaultReadTimeout = 500 * time.Millisecond
)

func (o *LiveOptions) setDefaults() {
	if o.Snaplen <= 0 {
		o.Snaplen = defaultSnaplen
	}
	if o.BufferBytes <= 0 {
		o.BufferBytes = defaultBufferBytes
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = defaultReadTimeout
	}
}

// ErrUnsupportedPlatform is returned by OpenLive where live capture is not
// implemented. Reading capture files still works everywhere.
var ErrUnsupportedPlatform = errors.New("live capture is not supported on this platform")

// PermissionError reports that capture was refused for lack of privilege,
// and carries the platform-specific way to fix it.
//
// This is worth a dedicated type because "operation not permitted" is the
// single most common first experience of a packet capture tool, and a bare
// errno teaches the user nothing.
type PermissionError struct {
	Op   string
	Path string
	Err  error
	Hint string
}

func (e *PermissionError) Error() string {
	s := fmt.Sprintf("%s: permission denied", e.Op)
	if e.Path != "" {
		s = fmt.Sprintf("%s (%s): permission denied", e.Op, e.Path)
	}
	if e.Hint != "" {
		s += "\n\n" + e.Hint
	}
	return s
}

func (e *PermissionError) Unwrap() error { return e.Err }

// InterfaceInfo describes a capturable network interface.
type InterfaceInfo struct {
	Name      string
	Up        bool
	Loopback  bool
	Addresses []string
}

// Interfaces lists the network interfaces on this host. It uses the standard
// library, so it needs no privileges and works identically everywhere.
func Interfaces() ([]InterfaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(ifs))
	for _, i := range ifs {
		info := InterfaceInfo{
			Name:     i.Name,
			Up:       i.Flags&net.FlagUp != 0,
			Loopback: i.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				info.Addresses = append(info.Addresses, a.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// DefaultInterface picks the interface to capture on when none was named:
// the first one that is up, is not loopback, and has an address.
func DefaultInterface() (string, error) {
	ifs, err := Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Up && !i.Loopback && len(i.Addresses) > 0 {
			return i.Name, nil
		}
	}
	return "", errors.New("no suitable interface found; name one with -i")
}

// LiveSupported reports whether this build can capture live traffic.
func LiveSupported() bool {
	switch runtime.GOOS {
	case "linux", "darwin":
		return true
	}
	return false
}
