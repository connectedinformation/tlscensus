// Package assemble turns a packet stream into completed TLS handshake
// observations.
//
// It exists because a naive "parse the ClientHello out of one packet"
// approach is wrong in exactly the case that matters most. A post-quantum
// key share is over a kilobyte on its own, so a ClientHello offering
// X25519MLKEM768 routinely exceeds a single TCP segment. A parser that does
// not reassemble silently drops the handshakes a post-quantum inventory
// exists to count, and reports a cleaner, more classical world than the one
// on the wire.
//
// TCP reassembly is delegated to gopacket's reassembly package, which
// handles retransmission, overlap and reordering. What this package adds is
// a bounded prefix per direction, content-based TLS detection, and the
// pairing of the two directions into one observation.
package assemble

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/tlscensus/tlscensus/internal/tlsparse"
)

// Defaults chosen for endpoint inventory rather than for bulk capture.
const (
	// DefaultMaxStreamPrefix bounds how much of each direction is retained.
	// A handshake is decided in the first few kilobytes; beyond that is
	// application data of no inventory interest. 32 KiB comfortably holds a
	// post-quantum ClientHello and a TLS 1.2 certificate chain with a long
	// intermediate list, which an 8 KiB cap would truncate.
	DefaultMaxStreamPrefix = 32 << 10

	// DefaultCloseTimeout is how long a quiet stream is kept before it is
	// flushed and reported with whatever was seen.
	DefaultCloseTimeout = 2 * time.Minute

	// minBytesBeforeReject is how much of a direction must be seen before
	// concluding it is not TLS. One TLS record header is five bytes; a
	// little more avoids rejecting a flow on a tiny first segment.
	minBytesBeforeReject = 16

	// DefaultMaxStreams caps concurrently tracked connections.
	//
	// M1 bounded memory per stream but not the number of streams, which is
	// fine for a capture file and not fine for a live host: a SYN flood, a
	// port scan, or simply a busy server multiplies the per-stream prefix
	// by an unbounded factor. At this cap the worst case is roughly
	// MaxStreams * MaxStreamPrefix * 2, so 64Ki * 32KiB * 2 would be far
	// too much — hence a cap chosen for an endpoint, not a tap.
	DefaultMaxStreams = 8192

	// pageBytes mirrors the page size in gopacket's reassembly package,
	// which does not export it. Only used to size the caps below, so an
	// upstream change costs accuracy, not correctness.
	pageBytes = 1900

	// maxBufferedPagesTotal bounds out-of-order queueing across every
	// connection, at roughly 8 MiB of payload.
	//
	// gopacket holds a segment that arrives ahead of a gap until the gap
	// is filled, and DefaultAssemblerOptions leaves that unlimited. Offline
	// the gap is always filled or the file ends; live it need not be. A
	// kernel buffer overrun drops a segment the receiver already acked, so
	// it is never retransmitted and the capture-side gap is permanent —
	// every later segment of that connection then queues until the idle
	// sweep, which at line rate is gigabytes for a single flow, and it
	// happens to flows that were ruled out as non-TLS long before.
	//
	// Capping loses nothing: on overflow reassembly delivers what it holds
	// and skips the gap, which ReassembledSG already handles.
	maxBufferedPagesTotal = 4096

	// minBufferedPagesPerConn floors the per-connection cap, which is
	// otherwise derived from MaxStreamPrefix.
	minBufferedPagesPerConn = 8
)

// Flow is one observed TCP connection and whatever of its TLS handshake was
// visible. Server is nil when the response was never captured; Client is
// never nil in an emitted flow.
type Flow struct {
	ClientIP   netip.Addr
	ServerIP   netip.Addr
	ClientPort uint16
	ServerPort uint16
	FirstSeen  time.Time
	LastSeen   time.Time

	Client *tlsparse.ClientHello
	Server *tlsparse.ServerHello

	// PrefixTruncated is set when a direction hit MaxStreamPrefix, meaning
	// later handshake messages may have been dropped.
	PrefixTruncated bool
}

// Handler receives each completed flow exactly once.
type Handler func(*Flow)

// Options configures an Assembler. The zero value is usable.
type Options struct {
	MaxStreamPrefix int
	CloseTimeout    time.Duration
	// MaxStreams caps concurrently tracked connections. Beyond it, new
	// connections are counted and ignored rather than tracked.
	MaxStreams int
}

func (o *Options) setDefaults() {
	if o.MaxStreamPrefix <= 0 {
		o.MaxStreamPrefix = DefaultMaxStreamPrefix
	}
	if o.CloseTimeout <= 0 {
		o.CloseTimeout = DefaultCloseTimeout
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = DefaultMaxStreams
	}
}

// Stats reports what the assembler saw. Streams counts every TCP connection
// examined; TLSFlows counts those that yielded a ClientHello.
type Stats struct {
	Packets     int64
	TCPPackets  int64
	Streams     int64
	TLSFlows    int64
	RejectedTCP int64
	// StreamsDropped counts connections ignored because MaxStreams was
	// already reached. A non-zero value means the inventory is incomplete,
	// so it is reported rather than silently absorbed.
	StreamsDropped int64
	// LiveStreams is the number currently tracked.
	LiveStreams int64
}

// Assembler feeds packets through TCP reassembly and reports TLS flows.
// It is not safe for concurrent use.
type Assembler struct {
	asm     *reassembly.Assembler
	opts    Options
	handler Handler
	stats   Stats

	lastTS    time.Time
	lastFlush time.Time
}

// New returns an Assembler that calls h for every flow carrying a
// ClientHello.
func New(h Handler, opts Options) *Assembler {
	opts.setDefaults()
	a := &Assembler{handler: h, opts: opts}
	a.asm = reassembly.NewAssembler(reassembly.NewStreamPool(&factory{a: a}))

	// The per-connection cap applies per direction, and payload past the
	// prefix is discarded on arrival, so the prefix is the natural size for
	// it. See maxBufferedPagesTotal for why the defaults are unusable live.
	perConn := opts.MaxStreamPrefix/pageBytes + 2
	if perConn < minBufferedPagesPerConn {
		perConn = minBufferedPagesPerConn
	}
	a.asm.MaxBufferedPagesPerConnection = perConn
	a.asm.MaxBufferedPagesTotal = maxBufferedPagesTotal

	return a
}

// Packet feeds one captured packet.
//
// Every TCP port is examined, not just 443. Restricting an inventory to the
// well-known port is how STARTTLS on 587, a database on 5432 and an internal
// service on 8443 all end up invisible, and "we found no weak ciphers" then
// means "we did not look". Non-TLS flows are rejected cheaply by content, on
// the first few bytes of each direction.
func (a *Assembler) Packet(data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType) {
	a.stats.Packets++

	// NoCopy is deliberately not set: reassembly retains references to
	// payload bytes, while a Source may reuse its buffer between calls.
	pkt := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true})

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	a.stats.TCPPackets++

	ts := ci.Timestamp
	if ts.After(a.lastTS) {
		a.lastTS = ts
	}
	a.asm.AssembleWithContext(netLayer.NetworkFlow(), tcpLayer.(*layers.TCP), &context{ci: ci})

	// Flush on capture time, not wall time, so replaying a file behaves the
	// same as watching a live interface.
	if a.lastFlush.IsZero() {
		a.lastFlush = ts
	}
	if ts.Sub(a.lastFlush) >= a.opts.CloseTimeout {
		a.asm.FlushCloseOlderThan(ts.Add(-a.opts.CloseTimeout))
		a.lastFlush = ts
	}
}

// FlushOlderThan closes streams idle since before t, emitting whatever they
// yielded.
//
// Live capture needs this on a timer rather than on packet arrival: a flow
// that completes on a quiet interface would otherwise sit unreported until
// the next packet from anyone, which on an idle host can be minutes.
func (a *Assembler) FlushOlderThan(t time.Time) {
	a.asm.FlushCloseOlderThan(t)
}

// Close flushes every remaining stream, emitting partial handshakes.
func (a *Assembler) Close() {
	a.asm.FlushAll()
}

// Stats returns a snapshot of the counters.
func (a *Assembler) Stats() Stats { return a.stats }

// context carries capture metadata through reassembly.
type context struct{ ci gopacket.CaptureInfo }

func (c *context) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

type factory struct{ a *Assembler }

func (f *factory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	// Decline a payload-free packet that is not a SYN.
	//
	// Now that connections complete on FIN, the pool removes them on the
	// second FIN — and the final ACK of the four-way close arrives after
	// that, for a connection that no longer exists. Registering a stream
	// for it creates a phantom that never completes, inflating Streams and
	// holding a MaxStreams slot until the idle sweep minutes later.
	// Returning nil is how reassembly is told not to track a connection.
	//
	// A connection whose SYN was missed is unaffected: it is registered by
	// the first packet that carries payload.
	if tcp != nil && !tcp.SYN && len(tcp.Payload) == 0 {
		return nil
	}

	f.a.stats.Streams++
	ts := ac.GetCaptureInfo().Timestamp
	src, dst := netFlow.Endpoints()
	sport, dport := tcpFlow.Endpoints()

	// Over the cap, the connection is acknowledged but nothing is retained
	// for it. The alternative — evicting an existing stream — would drop a
	// handshake already half-read in favour of one that may never be TLS.
	over := f.a.stats.LiveStreams >= int64(f.a.opts.MaxStreams)
	if over {
		f.a.stats.StreamsDropped++
	} else {
		f.a.stats.LiveStreams++
	}

	return &stream{
		a:        f.a,
		rejected: over,
		counted:  !over,
		flow: &Flow{
			ClientIP:   addrOf(src),
			ServerIP:   addrOf(dst),
			ClientPort: portOf(sport),
			ServerPort: portOf(dport),
			FirstSeen:  ts,
			LastSeen:   ts,
		},
	}
}

type stream struct {
	a    *Assembler
	flow *Flow

	// buf holds a bounded prefix of each direction, indexed by dirIndex.
	buf  [2][]byte
	full [2]bool

	clientIdx      int
	haveCH, haveSH bool
	rejected       bool
	emitted        bool
	// counted records whether this stream incremented LiveStreams, so the
	// decrement on completion stays balanced.
	counted bool
}

func (s *stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// Always accept.
	//
	// It is tempting to return false once the handshake is understood or
	// the flow ruled out, since no further payload is wanted. That is
	// wrong: reassembly consults Accept *before* it processes FIN and RST,
	// so refusing a packet also refuses the close. The connection then
	// never completes, ReassemblyComplete never runs, and the flow is only
	// emitted by the idle sweep minutes later — while its slot counts
	// against MaxStreams the whole time.
	//
	// Offline this is invisible, because Close flushes everything at end of
	// file. Live it means a handshake that finished a second ago is not
	// reported for two minutes.
	//
	// Unwanted payload is dropped in ReassembledSG instead, which costs a
	// function call per segment and retains nothing.
	return true
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	available, _ := sg.Lengths()
	// Nothing is retained once the flow is understood or ruled out; the
	// stream stays registered only so its close is still processed.
	if available == 0 || s.rejected || (s.haveCH && s.haveSH) {
		return
	}
	i := dirIndex(dir)

	if ts := ac.GetCaptureInfo().Timestamp; ts.After(s.flow.LastSeen) {
		s.flow.LastSeen = ts
	}

	if room := s.a.opts.MaxStreamPrefix - len(s.buf[i]); room > 0 {
		data := sg.Fetch(available)
		if len(data) > room {
			data = data[:room]
			s.full[i] = true
			s.flow.PrefixTruncated = true
		}
		// ScatterGather reuses its buffer, so this append must copy.
		s.buf[i] = append(s.buf[i], data...)
	} else {
		s.full[i] = true
		s.flow.PrefixTruncated = true
	}

	s.parse()
}

// parse re-reads both direction buffers after every append. Re-parsing is
// cheap next to the bounded prefix, and it keeps the logic free of any
// assumption about which message lands in which segment.
func (s *stream) parse() {
	if !s.haveCH {
		for i := range s.buf {
			ch, err := tlsparse.FindClientHello(s.buf[i])
			if err == nil && ch != nil {
				s.haveCH, s.clientIdx, s.flow.Client = true, i, ch
				if i != 0 {
					// The capture began with the server's side, so the
					// endpoints recorded at stream creation are reversed.
					s.flow.ClientIP, s.flow.ServerIP = s.flow.ServerIP, s.flow.ClientIP
					s.flow.ClientPort, s.flow.ServerPort = s.flow.ServerPort, s.flow.ClientPort
				}
				break
			}
		}
	}

	if s.haveCH && !s.haveSH {
		j := 1 - s.clientIdx
		if sh, err := tlsparse.FindServerHello(s.buf[j]); err == nil && sh != nil {
			s.haveSH, s.flow.Server = true, sh
		}
	}

	if s.haveCH {
		return
	}

	// Both directions filled the prefix without yielding a handshake. This
	// is the hard upper bound: whatever this flow is, no further bytes will
	// make it parse, so stop retaining and re-parsing them.
	if s.full[0] && s.full[1] {
		s.reject()
		return
	}

	// Neither direction looks like a handshake once enough bytes have
	// arrived to tell. Drop the buffers; this is what makes scanning every
	// port affordable.
	for i := range s.buf {
		if len(s.buf[i]) < minBytesBeforeReject {
			return
		}
		if _, err := tlsparse.FindClientHello(s.buf[i]); err != tlsparse.ErrNotTLS {
			return
		}
	}
	s.reject()
}

func (s *stream) reject() {
	s.rejected = true
	s.buf[0], s.buf[1] = nil, nil
	s.a.stats.RejectedTCP++
}

func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.emit()
	if s.counted {
		s.counted = false
		s.a.stats.LiveStreams--
	}
	return true
}

func (s *stream) emit() {
	if s.emitted || s.flow.Client == nil {
		return
	}
	s.emitted = true
	s.a.stats.TLSFlows++
	s.a.handler(s.flow)
}

func dirIndex(d reassembly.TCPFlowDirection) int {
	if d == reassembly.TCPDirClientToServer {
		return 0
	}
	return 1
}

func addrOf(ep gopacket.Endpoint) netip.Addr {
	a, _ := netip.AddrFromSlice(ep.Raw())
	return a.Unmap()
}

func portOf(ep gopacket.Endpoint) uint16 {
	b := ep.Raw()
	if len(b) != 2 {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}
