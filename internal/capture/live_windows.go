//go:build windows

package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	openLive    *windows.Proc
	nextEx      *windows.Proc
	setFilter   *windows.Proc
	datalink    *windows.Proc
	close       *windows.Proc
	findAllDevs *windows.Proc
	freeAllDevs *windows.Proc

	// WinPcap/Npcap extensions. Absent on some builds, so their absence is
	// not a load failure — the capture works without them, with the
	// driver's own defaults.
	setMinToCopy *windows.Proc
	setBuff      *windows.Proc
}

var (
	wpcapOnce sync.Once
	wpcap     *wpcapDLL
	wpcapErr  error
)

// wpcapPaths lists the absolute paths wpcap.dll can legitimately live at,
// in preference order.
//
// Npcap installs its DLLs to %SystemRoot%\System32\Npcap by default, which
// is not on the standard search path. Only when the installer's "WinPcap API
// compatible mode" is selected does wpcap.dll also land in System32. Both
// are common, so both are tried.
//
// These are absolute deliberately. Loading by bare name searches the
// executable's own directory first, so a wpcap.dll dropped beside
// tlscensus.exe — in a downloads folder, on a network share — would be
// preferred over the real driver, in a process users are told to run
// elevated. On a 32-bit process the file system redirector maps System32 to
// SysWOW64, where the 32-bit Npcap DLLs are, so this stays correct there.
func wpcapPaths() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	sys32 := filepath.Join(root, "System32")
	return []string{
		filepath.Join(sys32, "Npcap", "wpcap.dll"),
		filepath.Join(sys32, "wpcap.dll"),
	}
}

// loadWpcap opens wpcap.dll from one of the two places Npcap can put it.
func loadWpcap() (*wpcapDLL, error) {
	wpcapOnce.Do(func() {
		var (
			dll   *windows.DLL
			err   error
			paths = wpcapPaths()
		)
		for _, path := range paths {
			// Absent candidates are not an error worth reporting: the
			// default install populates one of these directories and not
			// the other, so one miss is the normal case. Reporting the
			// os.Stat failure would put "GetFileAttributesEx" and a single
			// path in front of a user whose actual problem is that Npcap
			// is not installed at all.
			if _, statErr := os.Stat(path); statErr != nil {
				continue
			}
			// Process-wide, and what Wireshark does for the same reason:
			// wpcap.dll resolves packet.dll from beside itself, so its
			// directory has to be searchable while it loads. Setting a
			// directory also drops the current directory from the search
			// order, which is the safer state regardless.
			if setErr := windows.SetDllDirectory(filepath.Dir(path)); setErr == nil {
				dll, err = windows.LoadDLL(path)
				windows.SetDllDirectory("")
			} else {
				dll, err = windows.LoadDLL(path)
			}
			if err == nil {
				break
			}
		}
		if dll == nil {
			if err == nil {
				err = fmt.Errorf("not found in %s", strings.Join(paths, " or "))
			}
			// Not a PermissionError: nothing here was refused, the driver
			// is simply absent, and saying "permission denied" would send
			// the user hunting for an elevated prompt that cannot help.
			wpcapErr = &SetupError{
				Op: "load wpcap.dll", Err: err, Hint: windowsInstallHint(),
			}
			return
		}
		err = nil

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
		// Optional extensions. Absence is not an error.
		w.setMinToCopy, _ = dll.FindProc("pcap_setmintocopy")
		w.setBuff, _ = dll.FindProc("pcap_setbuff")

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
	device   string
	friendly string
	linkType layers.LinkType
	snaplen  int

	// closed is read by Next to tell our own shutdown from a driver error.
	closed atomic.Bool

	// mu guards handle for the whole duration of every libpcap call on it.
	//
	// A pcap_t is not thread-safe, and Close runs on the signal goroutine
	// while Next is blocked inside pcap_next_ex on the capture goroutine.
	// pcap_close frees the pcap_t *and the buffer pcap_next_ex is filling*,
	// so an unsynchronised close is a use-after-free on every Ctrl-C rather
	// than a clean stop. The darwin path gets away with the same shape only
	// because closing a POSIX fd under a read is defined behaviour.
	//
	// Holding the lock across the call delays Close by at most one read
	// timeout: pcap_next_ex returns 0 when it expires, which the loop below
	// uses as its chance to notice closed.
	mu     sync.Mutex
	handle uintptr
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
	// Both buffers are heap-allocated and passed as uintptr, so nothing in
	// the argument list keeps them reachable. The compiler's retain rule for
	// unsafe.Pointer->uintptr covers the syscall.Syscall family only, and
	// (*Proc).Call is an ordinary variadic Go function — without this the
	// device name can be collected out from under pcap_open_live.
	keepAlive(name)
	keepAlive(errbuf)
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

	s := &windowsSource{
		w: w, handle: handle, device: device, friendly: friendly,
		snaplen: opts.Snaplen,
	}

	// Npcap buffers until it has this many bytes or the read timeout fires.
	// The default is large enough that a quiet interface reports nothing for
	// a long time, which reads as a hung capture.
	if w.setMinToCopy != nil {
		w.setMinToCopy.Call(handle, 0)
	}

	// The kernel capture buffer. Without this the documented BufferBytes
	// knob does nothing on Windows and a burst on a busy adapter drops
	// packets at the driver's default size with no way to raise it.
	//
	// A failure here is not fatal: the driver keeps its own default, which
	// is a smaller buffer rather than a broken capture.
	if w.setBuff != nil && opts.BufferBytes > 0 {
		w.setBuff.Call(handle, uintptr(opts.BufferBytes))
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
	for {
		if s.closed.Load() {
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
		buf, ci, done, err := s.nextOnce()
		switch {
		case err != nil:
			// A close racing with the read surfaces as a driver error;
			// that is our own shutdown, not a capture failure.
			if s.closed.Load() {
				return nil, gopacket.CaptureInfo{}, io.EOF
			}
			return nil, gopacket.CaptureInfo{}, err
		case done:
			return nil, gopacket.CaptureInfo{}, io.EOF
		case buf != nil:
			return buf, ci, nil
		}
		// Read timeout, or an OK with no packet attached. Loop, which is
		// also what gives Close its chance to be noticed.
	}
}

// nextOnce makes a single pcap_next_ex call and copies any packet out, all
// under the handle lock. The copy has to happen here: the driver owns that
// buffer and reuses it, and releasing the lock first would let Close free it
// while the copy is in flight.
func (s *windowsSource) nextOnce() (buf []byte, ci gopacket.CaptureInfo, done bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return nil, ci, true, nil
	}

	var hdr *pcapPkthdr
	var data *byte
	ret, _, _ := s.w.nextEx.Call(
		s.handle,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data)),
	)
	switch int32(ret) {
	case pcapNextOK:
		if hdr == nil || data == nil {
			return nil, ci, false, nil
		}
		n := int(hdr.Caplen)
		// caplen is the field a wrong pcap_pkthdr layout corrupts, and it
		// arrives as an arbitrary 32-bit value: unchecked it is a multi-GB
		// allocation and an out-of-bounds read on amd64, and a negative
		// length that panics make on 386. The driver cannot legitimately
		// return more than the snaplen it was opened with.
		if n < 0 || n > s.snaplen {
			return nil, ci, false, fmt.Errorf(
				"reading from %s: driver reported a %d-byte packet with a snaplen of %d, "+
					"which means struct pcap_pkthdr is being read wrongly", s.friendly, n, s.snaplen)
		}
		buf = make([]byte, n)
		copy(buf, unsafe.Slice(data, n))
		return buf, gopacket.CaptureInfo{
			Timestamp:     timeFromPcap(hdr.Ts),
			CaptureLength: n,
			Length:        int(hdr.Len),
		}, false, nil
	case pcapNextTimeout:
		return nil, ci, false, nil
	case pcapNextEOF:
		return nil, ci, true, nil
	default:
		return nil, ci, false,
			fmt.Errorf("reading from %s: pcap_next_ex returned %d", s.friendly, int32(ret))
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
	if s.closed.Swap(true) {
		return nil
	}
	// Setting closed first means an in-flight read returns at its next
	// timeout instead of starting another; taking the lock then waits for
	// it to actually be out of libpcap before the pcap_t is freed.
	s.mu.Lock()
	defer s.mu.Unlock()
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
	return pickDevice(devs, want)
}

// pickDevice is the matching itself, split out from the enumeration so it
// can be tested on a machine with no Npcap — which is every CI runner, and
// was the whole argument for this file's other tests.
func pickDevice(devs []winDevice, want string) (device, friendly string, err error) {
	if len(devs) == 0 {
		return "", "", errors.New("Npcap reported no capturable interfaces")
	}

	if want == "" {
		return defaultDevice(devs)
	}

	// Exact device path. GUID paths are unique, so first match wins.
	for _, d := range devs {
		if d.device == want {
			return d.device, d.Name, nil
		}
	}

	lower := strings.ToLower(want)
	// Exact adapter description, which is what `tlscensus interfaces`
	// prints and therefore what a user is most likely to paste back. It has
	// to be tried before any substring match: "Ethernet" is both a whole
	// adapter name and a prefix of "Ethernet 2", and matching by substring
	// first would resolve the name shown for one adapter to another.
	if matches := filterDevices(devs, func(d winDevice) bool {
		return strings.ToLower(d.Name) == lower
	}); len(matches) == 1 {
		return matches[0].device, matches[0].Name, nil
	} else if len(matches) > 1 {
		return "", "", ambiguous(want, matches)
	}

	// Substring of the description, then of the device path. The two are
	// separate tiers rather than one combined test because every device
	// path contains \Device\NPF_, so a short value — or a Linux habit like
	// "eth" — would otherwise match a GUID by accident and silently capture
	// on an arbitrary adapter.
	for _, match := range []func(winDevice) bool{
		func(d winDevice) bool { return strings.Contains(strings.ToLower(d.Name), lower) },
		func(d winDevice) bool { return strings.Contains(strings.ToLower(d.device), lower) },
	} {
		switch matches := filterDevices(devs, match); len(matches) {
		case 0:
			continue
		case 1:
			return matches[0].device, matches[0].Name, nil
		default:
			return "", "", ambiguous(want, matches)
		}
	}
	return "", "", fmt.Errorf("no interface matching %q; run `tlscensus interfaces` to list them", want)
}

// defaultDevice picks an interface when none was named.
func defaultDevice(devs []winDevice) (device, friendly string, err error) {
	// A routable address, not merely an address. Npcap lists a Bluetooth
	// PAN adapter, two Wi-Fi Direct virtual adapters and an unplugged
	// Ethernet port ahead of the real Wi-Fi adapter on an ordinary laptop;
	// every one of them is up and carries a 169.254 and an fe80:: address,
	// so "first with an address" reliably picks a link that carries no
	// traffic. See hasRoutableAddress.
	//
	// Two passes because PCAP_IF_UP, though confirmed set by Npcap 1.88, is
	// a driver-reported flag: if some build never sets it the first pass
	// matches nothing, and the second still applies every check that keeps
	// this off a useless adapter.
	for _, requireUp := range []bool{true, false} {
		for _, d := range devs {
			if d.Loopback || !hasRoutableAddress(d.Addresses) {
				continue
			}
			if requireUp && !d.Up {
				continue
			}
			return d.device, d.Name, nil
		}
	}
	// Previously this fell back to devs[0], typically loopback or a WAN
	// Miniport: a capture that runs forever, reports nothing and says
	// nothing. The other two platforms error here, and so does this.
	return "", "", errors.New("no suitable interface found; name one with -i " +
		"(run `tlscensus interfaces` to list them)")
}

func filterDevices(devs []winDevice, match func(winDevice) bool) []winDevice {
	var out []winDevice
	for _, d := range devs {
		if match(d) {
			out = append(out, d)
		}
	}
	return out
}

// ambiguous reports a name that matched more than one adapter.
//
// Silently taking the first is the failure this exists to prevent: adapters
// routinely differ only by a suffix ("Ethernet" and "Ethernet 2", or an
// Intel Wi-Fi adapter and its "#2" sibling), so first-wins captures on the
// wrong one and looks like it worked.
func ambiguous(want string, matches []winDevice) error {
	names := make([]string, 0, len(matches))
	for _, d := range matches {
		names = append(names, strconv.Quote(d.Name))
	}
	return fmt.Errorf("%q matches %d interfaces (%s); name one of them exactly",
		want, len(matches), strings.Join(names, ", "))
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
