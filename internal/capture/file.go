package capture

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// pcap and pcapng file magic. pcapng is byte-order agnostic in its first
// four bytes; classic pcap encodes endianness and timestamp resolution.
var (
	magicPcapNg     = [4]byte{0x0a, 0x0d, 0x0d, 0x0a}
	magicPcap       = [4]byte{0xa1, 0xb2, 0xc3, 0xd4}
	magicPcapSwap   = [4]byte{0xd4, 0xc3, 0xb2, 0xa1}
	magicPcapNano   = [4]byte{0xa1, 0xb2, 0x3c, 0x4d}
	magicPcapNanoSw = [4]byte{0x4d, 0x3c, 0xb2, 0xa1}
)

type reader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type fileSource struct {
	f    *os.File
	r    reader
	name string
}

// OpenFile opens a capture file, detecting pcap or pcapng from its magic
// rather than from the filename, since both extensions are used for both
// formats in the wild.
//
// This path uses pcapgo, which is pure Go. Reading a capture therefore needs
// neither cgo nor libpcap nor any privilege.
func OpenFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: reading magic: %w", path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	buf := bufio.NewReaderSize(f, 1<<20)
	var r reader
	switch magic {
	case magicPcapNg:
		ng, err := pcapgo.NewNgReader(buf, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r = ng
	case magicPcap, magicPcapSwap, magicPcapNano, magicPcapNanoSw:
		p, err := pcapgo.NewReader(buf)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r = p
	default:
		f.Close()
		return nil, fmt.Errorf("%s: not a pcap or pcapng file (magic %x)", path, magic)
	}

	return &fileSource{f: f, r: r, name: path}, nil
}

func (s *fileSource) Next() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}

func (s *fileSource) LinkType() layers.LinkType { return s.r.LinkType() }
func (s *fileSource) Name() string              { return s.name }
func (s *fileSource) Close() error              { return s.f.Close() }
