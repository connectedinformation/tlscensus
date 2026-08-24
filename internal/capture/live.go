package capture

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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

// SetupError reports that capture cannot start because a prerequisite is
// missing, as distinct from privilege being refused.
//
// It exists so that the two are not conflated. PermissionError prints
// "permission denied" unconditionally, which is right for its case and
// actively misleading for this one: a Windows machine with no Npcap
// installed would otherwise be told it lacked administrator rights, and
// sent looking for an elevated prompt that cannot help.
type SetupError struct {
	Op   string
	Err  error
	Hint string
}

func (e *SetupError) Error() string {
	s := fmt.Sprintf("%s: %v", e.Op, e.Err)
	if e.Hint != "" {
		s += "\n\n" + e.Hint
	}
	return s
}

func (e *SetupError) Unwrap() error { return e.Err }

// InterfaceInfo describes a capturable network interface.
type InterfaceInfo struct {
	Name      string
	Up        bool
	Loopback  bool
	Addresses []string
}

// Interfaces lists the network interfaces capture can be opened on.
//
// The names it returns are the names `watch -i` accepts, which is why this
// is not simply net.Interfaces() everywhere: on Windows the capture device
// is an Npcap GUID path, and listing the friendly adapter names would print
// names that cannot be used.
func Interfaces() ([]InterfaceInfo, error) {
	return platformInterfaces()
}

// stdlibInterfaces is the portable listing, used wherever the capture
// backend takes the same names the operating system uses.
func stdlibInterfaces() ([]InterfaceInfo, error) {
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
// the first one that is up, is not loopback, and has a routable address.
func DefaultInterface() (string, error) {
	ifs, err := Interfaces()
	if err != nil {
		return "", err
	}
	// Preferring an interface that is up, then settling for one that is
	// not, so a machine whose driver never reports the flag still gets a
	// sensible answer rather than none.
	for _, requireUp := range []bool{true, false} {
		for _, i := range ifs {
			if i.Loopback || !hasRoutableAddress(i.Addresses) {
				continue
			}
			if requireUp && !i.Up {
				continue
			}
			return i.Name, nil
		}
	}
	return "", errors.New("no suitable interface found; name one with -i")
}

// hasRoutableAddress reports whether any address is one a host actually
// communicates through.
//
// "Has an address" is not the same question, and answering it instead picks
// the wrong adapter on a normal Windows machine: a Bluetooth PAN adapter, a
// Wi-Fi Direct virtual adapter and an Ethernet port with no cable all carry
// a 169.254 autoconfiguration address and an fe80:: link-local one, all
// report themselves up, and all sort ahead of the Wi-Fi adapter that has
// the actual route. Capturing there runs forever and reports nothing.
//
// Addresses arrive either bare (from Npcap) or in CIDR form (from the
// standard library listing), so both are accepted.
func hasRoutableAddress(addrs []string) bool {
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			prefix, perr := netip.ParsePrefix(a)
			if perr != nil {
				continue
			}
			addr = prefix.Addr()
		}
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
			addr.IsUnspecified() || addr.IsLoopback() {
			continue
		}
		return true
	}
	return false
}

// LiveSupported reports whether this build can capture live traffic.
func LiveSupported() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return true
	}
	return false
}
