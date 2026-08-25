package assemble

import (
	"net/netip"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/connectedinformation/tlscensus/internal/quic"
	"github.com/connectedinformation/tlscensus/internal/tlsparse"
)

// QUIC carries the same TLS handshake as TCP does, so the same parser reads
// it — only the transport below differs. What changes is where the bytes
// come from: they arrive as CRYPTO frames inside packets encrypted with keys
// derived from a connection ID that travels in the clear.
//
// Leaving this out was not a neutral gap. Providers who deployed hybrid
// post-quantum key exchange early are the same ones who deployed HTTP/3
// early, so a TCP-only inventory systematically under-reports exactly the
// traffic it is meant to measure.

const (
	// maxCryptoBytes bounds the reassembled handshake per direction. A
	// post-quantum ClientHello runs to a few kilobytes across several
	// Initial packets; far beyond that is not a handshake.
	maxCryptoBytes = 16 << 10
	// maxCryptoFrames bounds how many out-of-order pieces are retained
	// before the flow is abandoned.
	maxCryptoFrames = 64
)

type quicKey struct {
	loAddr netip.Addr
	hiAddr netip.Addr
	loPort uint16
	hiPort uint16
}

func makeQUICKey(a netip.Addr, ap uint16, b netip.Addr, bp uint16) quicKey {
	if a.Compare(b) > 0 || (a == b && ap > bp) {
		a, b, ap, bp = b, a, bp, ap
	}
	return quicKey{loAddr: a, hiAddr: b, loPort: ap, hiPort: bp}
}

// cryptoStream reassembles CRYPTO frames, which carry offsets and can arrive
// out of order across several datagrams — the same problem TCP sequence
// numbers pose, for the same reason.
type cryptoStream struct {
	segments map[uint64][]byte
	total    int
}

func (c *cryptoStream) add(offset uint64, data []byte) {
	if len(data) == 0 || c.total >= maxCryptoBytes || len(c.segments) >= maxCryptoFrames {
		return
	}
	if offset > maxCryptoBytes {
		return
	}
	if c.segments == nil {
		c.segments = make(map[uint64][]byte, 4)
	}
	if _, seen := c.segments[offset]; seen {
		return
	}
	if room := maxCryptoBytes - c.total; len(data) > room {
		data = data[:room]
	}
	c.segments[offset] = append([]byte(nil), data...)
	c.total += len(data)
}

// prefix returns the contiguous run starting at offset zero. A gap ends it:
// a handshake cannot be parsed past a hole any more than a TCP stream can.
func (c *cryptoStream) prefix() []byte {
	if len(c.segments) == 0 {
		return nil
	}
	offsets := make([]uint64, 0, len(c.segments))
	for off := range c.segments {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	var out []byte
	var want uint64
	for _, off := range offsets {
		seg := c.segments[off]
		if off > want {
			break // gap
		}
		if end := off + uint64(len(seg)); end <= want {
			continue // already covered
		}
		out = append(out, seg[want-off:]...)
		want = off + uint64(len(seg))
	}
	return out
}

type quicFlow struct {
	flow     *Flow
	version  uint32
	origDCID []byte
	client   cryptoStream
	server   cryptoStream
	// clientAddr identifies which endpoint sent the first Initial.
	clientAddr netip.Addr
	clientPort uint16

	haveCH, haveSH bool
	emitted        bool
	rejected       bool
}

// quicPacket routes one UDP payload into QUIC handling.
func (a *Assembler) quicPacket(src, dst netip.Addr, sport, dport uint16, payload []byte, ts time.Time) {
	// One byte rejects nearly all non-QUIC UDP: DNS, mDNS, NTP, WireGuard
	// and the short-header packets that carry a connection's data once its
	// handshake is done.
	if !quic.IsLongHeader(payload) {
		return
	}
	h, err := quic.ParseLongHeader(payload)
	if err != nil || h.Type != quic.TypeInitial || !quic.Supported(h.Version) {
		return
	}

	key := makeQUICKey(src, sport, dst, dport)
	f, ok := a.quicFlows[key]
	if !ok {
		if len(a.quicFlows) >= a.opts.MaxStreams {
			a.stats.StreamsDropped++
			return
		}
		// The endpoint that sends the first Initial is the client, and the
		// connection ID it chose derives the keys for both directions.
		f = &quicFlow{
			version:    h.Version,
			origDCID:   append([]byte(nil), h.DCID...),
			clientAddr: src,
			clientPort: sport,
			flow: &Flow{
				Transport:  TransportQUIC,
				ClientIP:   src,
				ClientPort: sport,
				ServerIP:   dst,
				ServerPort: dport,
				FirstSeen:  ts,
				LastSeen:   ts,
			},
		}
		a.quicFlows[key] = f
		a.stats.Streams++
		a.stats.LiveStreams++
	}
	if f.rejected || f.emitted {
		return
	}
	if ts.After(f.flow.LastSeen) {
		f.flow.LastSeen = ts
	}

	fromClient := src == f.clientAddr && sport == f.clientPort
	keys, err := quic.DeriveInitialKeys(f.version, f.origDCID, !fromClient)
	if err != nil {
		f.rejected = true
		return
	}

	// A datagram can carry several packets; only the Initial is readable.
	_, plaintext, err := quic.Open(payload, h, keys)
	if err != nil {
		// Almost always a Retry has changed the connection ID, so the keys
		// no longer apply. Nothing further can be read from this flow.
		return
	}

	stream := &f.server
	if fromClient {
		stream = &f.client
	}
	for _, fr := range quic.CryptoFrames(plaintext) {
		stream.add(fr.Offset, fr.Data)
	}
	a.quicParse(f)
}

func (a *Assembler) quicParse(f *quicFlow) {
	if !f.haveCH {
		if ch, err := tlsparse.FindClientHelloRaw(f.client.prefix()); err == nil && ch != nil {
			f.haveCH, f.flow.Client = true, ch
		}
	}
	if f.haveCH && !f.haveSH {
		if sh, err := tlsparse.FindServerHelloRaw(f.server.prefix()); err == nil && sh != nil {
			f.haveSH, f.flow.Server = true, sh
			// Over QUIC every handshake is TLS 1.3, so the ServerHello is
			// the end of what is visible: EncryptedExtensions and the
			// certificate move to the Handshake level, under keys derived
			// from a secret this observer never sees.
			if sh.FlightComplete {
				a.emitQUIC(f)
			}
		}
	}
}

func (a *Assembler) emitQUIC(f *quicFlow) {
	if f.emitted || f.flow.Client == nil {
		return
	}
	f.emitted = true
	a.stats.TLSFlows++
	a.handler(f.flow)
}

// flushQUIC reports and removes QUIC flows idle since before t. There is no
// connection close to key on — QUIC's is encrypted — so a timer is the only
// thing that ends a flow.
func (a *Assembler) flushQUIC(t time.Time) {
	for key, f := range a.quicFlows {
		if f.flow.LastSeen.After(t) {
			continue
		}
		a.emitQUIC(f)
		delete(a.quicFlows, key)
		a.stats.LiveStreams--
	}
}

// udpPayload extracts the UDP payload and endpoints from a decoded packet.
func udpPayload(netLayer gopacket.NetworkLayer, udp *layers.UDP) (src, dst netip.Addr, sport, dport uint16, payload []byte) {
	s, d := netLayer.NetworkFlow().Endpoints()
	src = addrOf(s)
	dst = addrOf(d)
	return src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload
}
