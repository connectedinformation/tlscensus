package assemble_test

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/tlscensus/tlscensus/internal/assemble"
)

// pktgen builds Ethernet/IPv4/TCP packets in memory, so a test can express a
// packet sequence a capture file cannot hold — a close with its final ACK, or
// a permanent sequence gap.
type pktgen struct{ now time.Time }

type flags struct{ syn, ack, psh, fin bool }

func (g *pktgen) packet(src, dst string, sport, dport uint16, seq, ack uint32, fl flags, payload []byte) ([]byte, gopacket.CaptureInfo) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport),
		Seq: seq, Ack: ack, Window: 65535,
		SYN: fl.syn, ACK: fl.ack, PSH: fl.psh, FIN: fl.fin,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	b := buf.Bytes()
	g.now = g.now.Add(250 * time.Microsecond)
	return b, gopacket.CaptureInfo{Timestamp: g.now, CaptureLength: len(b), Length: len(b)}
}

// The final ACK of a four-way close must not register a second stream.
//
// Once flows complete on FIN, reassembly removes the connection on the second
// FIN — and the client's closing ACK then arrives for a connection that no
// longer exists. Registering a stream for it inflates Streams, holds a
// MaxStreams slot until the idle sweep, and makes LiveStreams never settle on
// a host with high close churn. The committed captures end at the second FIN,
// so only a synthetic close shows this.
func TestFinalAckDoesNotCreatePhantomStream(t *testing.T) {
	var g pktgen
	asm := assemble.New(func(f *assemble.Flow) {}, assemble.Options{})

	const c, s = "192.168.1.50", "10.20.0.22"
	const sport, dport = 51700, 443
	var cSeq, sSeq uint32 = 1000, 5000

	feed := func(src, dst string, sp, dp uint16, seq, ack uint32, fl flags, payload []byte) {
		data, ci := g.packet(src, dst, sp, dp, seq, ack, fl, payload)
		asm.Packet(data, ci, layers.LinkTypeEthernet)
	}

	feed(c, s, sport, dport, cSeq, 0, flags{syn: true}, nil)
	cSeq++
	feed(s, c, dport, sport, sSeq, cSeq, flags{syn: true, ack: true}, nil)
	sSeq++
	feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true}, nil)

	body := []byte("not tls, but a real connection")
	feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true, psh: true}, body)
	cSeq += uint32(len(body))

	// Four-way close, including the final ACK a capture file omits.
	feed(c, s, sport, dport, cSeq, sSeq, flags{fin: true, ack: true}, nil)
	cSeq++
	feed(s, c, dport, sport, sSeq, cSeq, flags{fin: true, ack: true}, nil)
	sSeq++
	feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true}, nil)

	if got := asm.Stats().Streams; got != 1 {
		t.Errorf("Streams = %d after one connection closed, want 1; "+
			"the trailing ACK registered a phantom stream", got)
	}
	if got := asm.Stats().LiveStreams; got != 0 {
		t.Errorf("LiveStreams = %d after close, want 0", got)
	}
}

// Out-of-order payload must not be buffered without bound.
//
// gopacket queues segments that arrive ahead of a gap until the gap is
// filled. Live, a gap can be permanent: a kernel buffer overrun drops a
// segment the receiver already acked, so it is never retransmitted. With
// gopacket's default options that queue is unlimited, so every later segment
// of the connection accumulates until the idle sweep — for a flow whose bytes
// this package discards on arrival anyway.
func TestBufferedPagesAreBounded(t *testing.T) {
	var g pktgen
	asm := assemble.New(func(f *assemble.Flow) {}, assemble.Options{})

	const c, s = "192.168.1.60", "10.20.0.30"
	const sport, dport = 51800, 22
	var cSeq, sSeq uint32 = 1000, 5000

	feed := func(src, dst string, sp, dp uint16, seq, ack uint32, fl flags, payload []byte) {
		data, ci := g.packet(src, dst, sp, dp, seq, ack, fl, payload)
		asm.Packet(data, ci, layers.LinkTypeEthernet)
	}

	feed(c, s, sport, dport, cSeq, 0, flags{syn: true}, nil)
	cSeq++
	feed(s, c, dport, sport, sSeq, cSeq, flags{syn: true, ack: true}, nil)
	sSeq++
	feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true}, nil)

	// Rule the flow out as non-TLS, so nothing about it is worth retaining.
	banner := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true, psh: true}, banner)
	cSeq += uint32(len(banner))

	// Open a gap that is never filled, then keep sending behind it.
	const seg, count = 1400, 30000
	cSeq += seg
	payload := make([]byte, seg)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	for i := 0; i < count; i++ {
		feed(c, s, sport, dport, cSeq, sSeq, flags{ack: true}, payload)
		cSeq += seg
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// Without this the assembler is unreachable by now, so the GC above
	// frees the very pages this test is trying to measure.
	runtime.KeepAlive(asm)

	var grew int64 = int64(after.HeapAlloc) - int64(before.HeapAlloc)
	sent := int64(seg) * count
	// The total page cap is a little under 8 MiB; allow generous headroom
	// while staying far below the ~40 MiB an unbounded queue would retain.
	const limit = 16 << 20
	if grew > limit {
		t.Errorf("heap grew %d MiB after %d MiB of payload behind a permanent gap, want under %d MiB; "+
			"out-of-order queueing is unbounded",
			grew>>20, sent>>20, limit>>20)
	}
	t.Logf("heap grew %d KiB after %d MiB sent behind a gap", grew>>10, sent>>20)
}
