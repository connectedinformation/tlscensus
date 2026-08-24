//go:build windows

package capture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/windows"
)

// Windows capture drives Npcap's wpcap.dll through runtime DLL loading
// rather than linking libpcap with cgo.
//
// That keeps the binary cgo-free like the other two platforms, so one build
// runner still produces every release target and `go install` needs no C
// toolchain or Npcap SDK headers. It also means the binary runs on a machine
// that has never had Npcap installed: the DLL is only opened when capture is
// actually requested, so `tlscensus read` works everywhere and only `watch`
// asks for a driver.
//
// Npcap must be installed by the user. Its licence does not permit
// redistribution, and telling people to install it themselves is the normal
// arrangement for an open-source tool — Wireshark has trained the market on
// it for twenty years. See docs/permissions.md.

const (
	pcapErrbufSize = 256

	// pcap_next_ex return values.
	pcapNextOK      = 1
	pcapNextTimeout = 0
	pcapNextError   = -1
	pcapNextEOF     = -2
)

// pcapTimeval is the timestamp inside struct pcap_pkthdr.
//
// Both fields are 32-bit **even on 64-bit Windows**, because Windows keeps
// `long` at 32 bits under LLP64 while Unix LP64 widens it to 64. Declaring
// this with int64 fields would misread every timestamp and every length that
// follows it — the same class of mistake as assuming sizeof(struct bpf_hdr)
// on Darwin, which silently rejected every packet until it was found on real
// hardware.
type pcapTimeval struct {
	Sec  int32
	Usec int32
}

// pcapPkthdr mirrors struct pcap_pkthdr: 16 bytes on Windows.
type pcapPkthdr struct {
	Ts     pcapTimeval
	Caplen uint32
	Len    uint32
}

// bpfInsn and bpfProgram mirror the filter structures. Go inserts the same
// alignment padding the C compiler does, so no explicit pad member is needed
// on either 386 or amd64.
type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type bpfProgram struct {
	Len   uint32
	Insns *bpfInsn
}

// pcapIf mirrors struct pcap_if, the linked list pcap_findalldevs returns.
type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   *pcapAddr
	Flags       uint32
}

type wpcapDLL struct {
	dll *windows.DLL

	openLive     *windows.Proc
	nextEx       *windows.Proc
	setFilter    *windows.Proc
	datalink     *windows.Proc
	close        *windows.Proc
	findAllDevs  *windows.Proc
	freeAllDevs  *windows.Proc
	libVersion   *windows.Proc
	setMinToCopy *windows.Proc // Npcap extension; absent on plain WinPcap
}

var (
	wpcapOnce sync.Once
	wpcap     *wpcapDLL
	wpcapErr  error
)

// loadWpcap opens wpcap.dll, trying both places Npcap can put it.
//
// Npcap installs its DLLs to %SystemRoot%\System32\Npcap by default, which
// is not on the standard search path. Only when the installer's "WinPcap API
// compatible mode" is selected does wpcap.dll also land in System32. Both
// are common, so both are tried — and the Npcap directory is added to the
// search path first, because wpcap.dll loads packet.dll from beside itself.
func loadWpcap() (*wpcapDLL, error) {
	wpcapOnce.Do(func() {
		dll, err := windows.LoadDLL("wpcap.dll")
		if err != nil {
			if root := os.Getenv("SystemRoot"); root != "" {
				dir := filepath.Join(root, "System32", "Npcap")
				if _, statErr := os.Stat(filepath.Join(dir, "wpcap.dll")); statErr == nil {
					// Process-wide, and what Wireshark does for the same
					// reason: wpcap.dll's own dependencies must resolve
					// from the Npcap directory.
					if setErr := windows.SetDllDirectory(dir); setErr == nil {
						dll, err = windows.LoadDLL("wpcap.dll")
						windows.SetDllDirectory("")
					}
				}
			}
		}
		if err != nil {
			wpcapErr = &PermissionError{
				Op: "load wpcap.dll", Err: err, Hint: windowsInstallHint(),
			}
			return
		}

		w := &wpcapDLL{dll: dll}
		must := func(name string) *windows.Proc {
			p, perr := dll.FindProc(name)
			if perr != nil && err == nil {
				err = fmt.Errorf("wpcap.dll is missing %s: %w", name, perr)
			}
			return p
		}
		w.openLive = must("pcap_open_live")
		w.nextEx = must("pcap_next_ex")
		w.setFilter = must("pcap_setfilter")
		w.datalink = must("pcap_datalink")
		w.close = must("pcap_close")
		w.findAllDevs = must("pcap_findalldevs")
		w.freeAllDevs = must("pcap_freealldevs")
		w.libVersion = must("pcap_lib_version")
		// Optional: Npcap only. Absence is not an error.
		w.setMinToCopy, _ = dll.FindProc("pcap_setmintocopy")

		if err != nil {
			wpcapErr = err
			return
		}
		wpcap = w
	})
	return wpcap, wpcapErr
}

type windowsSource struct {
	w        *wpcapDLL
	handle   uintptr
	device   string
	friendly string
	linkType layers.LinkType
	closed   bool
}

// OpenLive begins capturing on iface, which may be an Npcap device name
// (\Device\NPF_{...}) or any unique substring of an adapter's description.
// An empty iface selects the first non-loopback device with an address.
func OpenLive(iface string, opts LiveOptions) (Source, error) {
	opts.setDefaults()

	w, err := loadWpcap()
	if err != nil {
		return nil, err
	}

	device, friendly, err := resolveDevice(w, iface)
	if err != nil {
		return nil, err
	}

	name, err := windows.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	promisc := 0
	if opts.Promiscuous {
		promisc = 1
	}
	errbuf := make([]byte, pcapErrbufSize)

	handle, _, _ := w.openLive.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(opts.Snaplen),
		uintptr(promisc),
		uintptr(opts.ReadTimeout.Milliseconds()),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		msg := cstring(&errbuf[0])
		// Npcap can be installed with access restricted to Administrators,
		// which is the usual cause here and is not distinguishable from the
		// error string alone.
		if strings.Contains(strings.ToLower(msg), "access is denied") ||
			strings.Contains(strings.ToLower(msg), "permission") {
			return nil, &PermissionError{
				Op: "open " + device, Err: errors.New(msg), Hint: windowsPermissionHint(),
			}
		}
		return nil, fmt.Errorf("opening %s: %s", device, msg)
	}

	s := &windowsSource{w: w, handle: handle, device: device, friendly: friendly}

	// Npcap buffers until it has this many bytes or the read timeout fires.
	// The default is large enough that a quiet interface reports nothing for
	// a long time, which reads as a hung capture.
	if w.setMinToCopy != nil {
		w.setMinToCopy.Call(handle, 0)
	}

	dlt, _, _ := w.datalink.Call(handle)
	s.linkType = layers.LinkType(int32(dlt))
	switch s.linkType {
	case layers.LinkTypeEthernet, layers.LinkTypeNull, layers.LinkTypeLoop, layers.LinkTypeRaw:
	default:
		s.Close()
		return nil, fmt.Errorf("interface %s has link type %d, which is not decoded yet",
			friendly, int32(dlt))
	}

	if !opts.NoFilter {
		if err := s.setFilter(opts.Snaplen); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *windowsSource) setFilter(snaplen int) error {
	raw, err := TCPFilter(s.linkType, snaplen)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	insns := make([]bpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = bpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := bpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}

	ret, _, _ := s.w.setFilter.Call(s.handle, uintptr(unsafe.Pointer(&prog)))
	// insns must stay reachable until the driver has copied the program.
	keepAlive(insns)
	if int32(ret) != 0 {
		return fmt.Errorf("installing BPF filter: pcap_setfilter returned %d", int32(ret))
	}
	return nil
}

func (s *windowsSource) Next() ([]byte, gopacket.CaptureInfo, error) {
	var hdr *pcapPkthdr
	var data *byte

	for {
		if s.closed {
			return nil, gopacket.CaptureInfo{}, errClosed
		}
		ret, _, _ := s.w.nextEx.Call(
			s.handle,
			uintptr(unsafe.Pointer(&hdr)),
			uintptr(unsafe.Pointer(&data)),
		)
		switch int32(ret) {
		case pcapNextOK:
			if hdr == nil || data == nil {
				continue
			}
			n := int(hdr.Caplen)
			// The driver reuses this buffer on the next call, so the bytes
			// must be copied out before returning.
			buf := make([]byte, n)
			copy(buf, unsafe.Slice(data, n))
			return buf, gopacket.CaptureInfo{
				Timestamp:     timeFromPcap(hdr.Ts),
				CaptureLength: n,
				Length:        int(hdr.Len),
			}, nil
		case pcapNextTimeout:
			// Read timeout with nothing captured. Loop so Close is noticed.
			continue
		case pcapNextEOF:
			return nil, gopacket.CaptureInfo{}, errClosed
		default:
			if s.closed {
				return nil, gopacket.CaptureInfo{}, errClosed
			}
			return nil, gopacket.CaptureInfo{},
				fmt.Errorf("reading from %s: pcap_next_ex returned %d", s.friendly, int32(ret))
		}
	}
}

func (s *windowsSource) LinkType() layers.LinkType { return s.linkType }

func (s *windowsSource) Name() string {
	if s.friendly != "" {
		return s.friendly
	}
	return s.device
}

func (s *windowsSource) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.handle != 0 {
		s.w.close.Call(s.handle)
		s.handle = 0
	}
	return nil
}

// resolveDevice turns a user-supplied interface name into an Npcap device
// name. Windows device names are GUID paths that nobody can be expected to
// type, so a substring of the adapter description is accepted too.
func resolveDevice(w *wpcapDLL, want string) (device, friendly string, err error) {
	devs, err := listDevices(w)
	if err != nil {
		return "", "", err
	}
	if len(devs) == 0 {
		return "", "", errors.New("Npcap reported no capturable interfaces")
	}

	if want == "" {
		for _, d := range devs {
			if !d.Loopback && len(d.Addresses) > 0 && d.Up {
				return d.device, d.Name, nil
			}
		}
		return devs[0].device, devs[0].Name, nil
	}

	lower := strings.ToLower(want)
	for _, d := range devs {
		if d.device == want {
			return d.device, d.Name, nil
		}
	}
	for _, d := range devs {
		if strings.Contains(strings.ToLower(d.Name), lower) ||
			strings.Contains(strings.ToLower(d.device), lower) {
			return d.device, d.Name, nil
		}
	}
	return "", "", fmt.Errorf("no interface matching %q; run `tlscensus interfaces` to list them", want)
}

type winDevice struct {
	InterfaceInfo
	device string
}

func listDevices(w *wpcapDLL) ([]winDevice, error) {
	var head *pcapIf
	errbuf := make([]byte, pcapErrbufSize)
	ret, _, _ := w.findAllDevs.Call(
		uintptr(unsafe.Pointer(&head)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if int32(ret) != 0 {
		return nil, fmt.Errorf("enumerating interfaces: %s", cstring(&errbuf[0]))
	}
	defer w.freeAllDevs.Call(uintptr(unsafe.Pointer(head)))

	const pcapIfLoopback = 0x00000001
	const pcapIfUp = 0x00000002

	var out []winDevice
	for d := head; d != nil; d = d.Next {
		name := cstring(d.Name)
		desc := cstring(d.Description)
		friendly := desc
		if friendly == "" {
			friendly = name
		}
		out = append(out, winDevice{
			InterfaceInfo: InterfaceInfo{
				Name:      friendly,
				Up:        d.Flags&pcapIfUp != 0,
				Loopback:  d.Flags&pcapIfLoopback != 0,
				Addresses: addressesOf(d.Addresses),
			},
			device: name,
		})
	}
	return out, nil
}

func timeFromPcap(tv pcapTimeval) time.Time {
	return time.Unix(int64(tv.Sec), int64(tv.Usec)*1000)
}

func cstring(p *byte) string {
	if p == nil {
		return ""
	}
	return windows.BytePtrToString(p)
}

func keepAlive(v any) { runtime.KeepAlive(v) }

var errClosed = errors.New("capture: source closed")

func windowsInstallHint() string {
	return `Live capture on Windows needs Npcap.

Install it from https://npcap.com and re-run. tlscensus does not bundle it:
Npcap's licence does not permit redistribution, so it has to be installed
separately. If Wireshark is already installed, Npcap almost certainly is too.

Reading a capture file needs none of this:

    tlscensus read capture.pcap`
}

func windowsPermissionHint() string {
	return `Npcap is installed but refused access to the adapter.

Npcap can be installed with "Restrict Npcap driver's access to
Administrators only". If that option was selected, capture requires an
elevated prompt:

    Run PowerShell or Terminal as Administrator, then: tlscensus watch

Otherwise re-run the Npcap installer and clear that option.`
}
