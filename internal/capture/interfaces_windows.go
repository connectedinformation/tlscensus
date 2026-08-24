//go:build windows

package capture

import (
	"fmt"
	"net/netip"
	"unsafe"
)

// On Windows the capturable device is an Npcap name like
// \Device\NPF_{XXXXXXXX-...}, which is what pcap_open_live expects and which
// bears no resemblance to the adapter name Windows shows. Listing
// net.Interfaces() here would print "Wi-Fi" and "Ethernet" — names that then
// fail to open. The list therefore comes from Npcap itself, with the adapter
// description as the display name and the addresses parsed out so an
// interface can be picked by its IP.
//
// If Npcap cannot be used there is nothing to capture on, but `tlscensus
// interfaces` should still say something useful rather than error, so it
// falls back to the standard library listing.
//
// That covers two distinct failures, not one. The driver may be absent, and
// it may be installed with its NPF service stopped — a common state, since
// some install options leave the service set to start on demand — in which
// case the DLL loads and pcap_findalldevs is what fails. Listing interfaces
// is the first thing a user runs, so both fall back rather than error. The
// names printed then are the operating system's rather than capture device
// names; `watch` is where the missing driver gets reported properly, with
// the hint attached.
func platformInterfaces() ([]InterfaceInfo, error) {
	w, err := loadWpcap()
	if err != nil {
		return stdlibInterfaces()
	}
	devs, err := listDevices(w)
	if err != nil {
		return stdlibInterfaces()
	}
	out := make([]InterfaceInfo, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.InterfaceInfo)
	}
	return out, nil
}

// Windows socket address families. AF_INET6 is 23 here, not the 10 it is on
// Linux — a difference that silently drops every IPv6 address if assumed.
const (
	afInet  = 2
	afInet6 = 23
)

type pcapAddr struct {
	Next      *pcapAddr
	Addr      *rawSockaddr
	Netmask   *rawSockaddr
	Broadaddr *rawSockaddr
	Dstaddr   *rawSockaddr
}

type rawSockaddr struct {
	Family uint16
	Data   [26]byte
}

// addressesOf walks a pcap_addr list and renders the addresses it can.
func addressesOf(head *pcapAddr) []string {
	var out []string
	for a := head; a != nil; a = a.Next {
		if a.Addr == nil {
			continue
		}
		switch a.Addr.Family {
		case afInet:
			// sockaddr_in: family, port, then four address bytes.
			b := (*[4]byte)(unsafe.Pointer(&a.Addr.Data[2]))
			out = append(out, netip.AddrFrom4(*b).String())
		case afInet6:
			// sockaddr_in6: family, port, flowinfo, then sixteen bytes.
			b := (*[16]byte)(unsafe.Pointer(&a.Addr.Data[6]))
			addr := netip.AddrFrom16(*b)
			out = append(out, addr.Unmap().String())
		default:
			out = append(out, fmt.Sprintf("(family %d)", a.Addr.Family))
		}
	}
	return out
}
