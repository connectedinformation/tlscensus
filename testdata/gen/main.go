// Command gen writes testdata/sample.pcap: a synthetic capture covering the
// handshake shapes the inventory has to get right.
//
// Synthetic rather than recorded, on purpose. A committed capture of real
// traffic carries real hostnames and real addresses, which is not something
// to put in a public repository for a tool whose whole subject is that
// hostnames are sensitive. It is also not reproducible. Every flow here is
// built from the RFC encodings in internal/tlssynth.
//
// Regenerate with: go run ./testdata/gen
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/tlscensus/tlscensus/internal/tlssynth"
)

// Named groups and cipher suites, spelled out so the generator reads as a
// description of the traffic rather than as a table of magic numbers.
const (
	x25519         = 29
	secp256r1      = 23
	secp384r1      = 24
	x25519MLKEM768 = 0x11ec

	tlsAES128GCMSHA256       = 0x1301
	tlsAES256GCMSHA384       = 0x1302
	tlsChaCha20Poly1305      = 0x1303
	ecdheRSAAES128GCMSHA256  = 0xc02f
	ecdheECDSAAES128GCMSHA25 = 0xc02b
	rsaWithRC4128SHA         = 0x0005
	rsaWith3DESEDECBCSHA     = 0x000a
	rsaWithAES128CBCSHA      = 0x002f

	tls10 = 0x0301
	tls12 = 0x0303
	tls13 = 0x0304
)

// mss is the payload each TCP segment carries. 1460 is the usual Ethernet
// value, which is what makes a post-quantum ClientHello span two segments.
const mss = 1460

var baseTime = time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)

func main() {
	writeSample()
	writeConcurrent()
}

// newCapture creates a pcap file and a generator writing into it.
func newCapture(path string) (*gen, func()) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}
	return &gen{w: w, now: baseTime}, func() { f.Close() }
}

// writeConcurrent produces a capture of many connections open at once and
// never closed.
//
// The sample capture writes each connection start to finish before the next
// begins, so at most one is ever in flight. That is the wrong shape for
// testing the concurrent-stream cap: with connection close handled properly
// the tracked count returns to zero between flows and no cap is ever
// reached. Interleaving the segments, and omitting the FINs, models the case
// the cap exists for — a busy host where connections accumulate.
func writeConcurrent() {
	const flows = 12
	out := "testdata/concurrent.pcap"
	g, closeFile := newCapture(out)
	defer closeFile()

	type conn struct {
		cIP, sIP net.IP
		sport    uint16
		payload  []byte
		cSeq     uint32
		sSeq     uint32
	}
	conns := make([]*conn, flows)
	for i := range conns {
		ch := tlssynth.ClientHelloSpec{
			Ciphers:           []uint16{tlsAES128GCMSHA256, tlsAES256GCMSHA384},
			SNI:               fmt.Sprintf("host%02d.example", i),
			ALPN:              []string{"h2"},
			SupportedVersions: []uint16{tls13},
			Groups:            []uint16{x25519MLKEM768, x25519},
			KeyShares:         []uint16{x25519MLKEM768},
			SigAlgs:           []uint16{0x0403, 0x0804},
		}
		conns[i] = &conn{
			cIP:   net.ParseIP("192.168.1.60"),
			sIP:   net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1)),
			sport: uint16(52000 + i),
			payload: tlssynth.Records(tlssynth.RecordHandshake,
				tlssynth.HandshakeMsg(tlssynth.MsgClientHello, tlssynth.ClientHello(ch)), mss),
			cSeq: 1000,
			sSeq: 5000,
		}
		g.flows++
	}

	// Open every connection first, so all of them are in flight before any
	// payload arrives.
	for _, c := range conns {
		g.emit(c.cIP, c.sIP, c.sport, 443, c.cSeq, 0, tcpFlags{syn: true}, nil)
		c.cSeq++
		g.emit(c.sIP, c.cIP, 443, c.sport, c.sSeq, c.cSeq, tcpFlags{syn: true, ack: true}, nil)
		c.sSeq++
		g.emit(c.cIP, c.sIP, c.sport, 443, c.cSeq, c.sSeq, tcpFlags{ack: true}, nil)
	}

	// Then interleave one segment per connection per round. No FIN: these
	// connections stay open for the life of the capture.
	for more := true; more; {
		more = false
		for _, c := range conns {
			if len(c.payload) == 0 {
				continue
			}
			n := min(mss, len(c.payload))
			g.emit(c.cIP, c.sIP, c.sport, 443, c.cSeq, c.sSeq,
				tcpFlags{ack: true, psh: n == len(c.payload)}, c.payload[:n])
			c.cSeq += uint32(n)
			c.payload = c.payload[n:]
			more = more || len(c.payload) > 0
		}
	}

	fmt.Printf("wrote %s (%d packets, %d concurrent flows)\n", out, g.packets, g.flows)
}

func writeSample() {
	out := "testdata/sample.pcap"
	g, closeFile := newCapture(out)
	defer closeFile()

	modernCiphers := []uint16{tlsAES128GCMSHA256, tlsAES256GCMSHA384, tlsChaCha20Poly1305,
		ecdheECDSAAES128GCMSHA25, ecdheRSAAES128GCMSHA256}
	modernSigAlgs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501}

	// 1. A post-quantum handshake that completes. The ClientHello exceeds
	//    one segment because of the 1216-byte hybrid key share, which is
	//    the case a non-reassembling parser drops.
	g.tlsFlow(flow{
		client: "192.168.1.50", server: "104.18.32.7", sport: 51420, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "www.cloudflare.com",
			ALPN: []string{"h2", "http/1.1"}, SupportedVersions: []uint16{tls13, tls12},
			Groups:    []uint16{x25519MLKEM768, x25519, secp256r1, secp384r1},
			KeyShares: []uint16{x25519MLKEM768, x25519}, SigAlgs: modernSigAlgs,
		},
		sh: &tlssynth.ServerHelloSpec{
			Cipher: tlsAES128GCMSHA256, SelectedVersion: tls13,
			Group: x25519MLKEM768, ALPN: "h2",
		},
	})

	// 2. Client offers a post-quantum key share; server selects classical.
	//    The client is ready, the server is not — a distinction a readiness
	//    report has to keep.
	g.tlsFlow(flow{
		client: "192.168.1.50", server: "93.184.216.34", sport: 51421, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "example.com",
			ALPN: []string{"h2", "http/1.1"}, SupportedVersions: []uint16{tls13, tls12},
			Groups:    []uint16{x25519MLKEM768, x25519, secp256r1},
			KeyShares: []uint16{x25519MLKEM768, x25519}, SigAlgs: modernSigAlgs,
		},
		sh: &tlssynth.ServerHelloSpec{
			Cipher: tlsAES128GCMSHA256, SelectedVersion: tls13, Group: x25519, ALPN: "h2",
		},
	})

	// 3. Post-quantum advertised in supported_groups but never key-shared.
	//    Nothing post-quantum can happen; counting this as ready is the
	//    most common way a migration dashboard flatters itself.
	g.tlsFlow(flow{
		client: "192.168.1.51", server: "142.250.185.78", sport: 44100, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "www.google.com",
			ALPN: []string{"h2"}, SupportedVersions: []uint16{tls13, tls12},
			Groups:    []uint16{x25519MLKEM768, x25519, secp256r1},
			KeyShares: []uint16{x25519}, SigAlgs: modernSigAlgs,
		},
		sh: &tlssynth.ServerHelloSpec{
			Cipher: tlsChaCha20Poly1305, SelectedVersion: tls13, Group: x25519, ALPN: "h2",
		},
	})

	// 4. TLS 1.2 with a real certificate chain. Under 1.3 this would all be
	//    encrypted, so certificate inventory is a 1.2-and-below story.
	leaf2048 := selfSigned("legacy.internal.example", 2048)
	g.tlsFlow(flow{
		client: "192.168.1.52", server: "10.20.0.9", sport: 39004, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			LegacyVersion: tls12,
			Ciphers:       []uint16{ecdheRSAAES128GCMSHA256, rsaWithAES128CBCSHA},
			SNI:           "legacy.internal.example", ALPN: []string{"http/1.1"},
			Groups: []uint16{secp256r1, x25519}, SigAlgs: modernSigAlgs,
		},
		sh:    &tlssynth.ServerHelloSpec{Cipher: ecdheRSAAES128GCMSHA256, ALPN: "http/1.1"},
		ske:   secp256r1,
		certs: [][]byte{leaf2048},
	})

	// 5. A TLS 1.2 server on a 1024-bit RSA key, negotiating a suite with
	//    no forward secrecy.
	leaf1024 := selfSigned("old-appliance.internal.example", 1024)
	g.tlsFlow(flow{
		client: "192.168.1.52", server: "10.20.0.14", sport: 39010, dport: 8443,
		ch: tlssynth.ClientHelloSpec{
			LegacyVersion: tls12, NoGREASE: true,
			Ciphers: []uint16{rsaWithAES128CBCSHA, rsaWith3DESEDECBCSHA},
			SNI:     "old-appliance.internal.example",
			Groups:  []uint16{secp256r1},
		},
		sh:    &tlssynth.ServerHelloSpec{Cipher: rsaWithAES128CBCSHA},
		certs: [][]byte{leaf1024},
	})

	// 6. SSL-era client on a non-standard port. Restricting capture to 443
	//    is how this stays invisible.
	g.tlsFlow(flow{
		client: "192.168.1.53", server: "10.20.0.31", sport: 40222, dport: 9443,
		ch: tlssynth.ClientHelloSpec{
			LegacyVersion: tls10, NoGREASE: true, OmitExtensions: true,
			Ciphers: []uint16{rsaWithRC4128SHA, rsaWith3DESEDECBCSHA},
		},
		sh: &tlssynth.ServerHelloSpec{LegacyVersion: tls10, Cipher: rsaWithRC4128SHA},
	})

	// 7. Encrypted ClientHello. The visible server_name is the provider's
	//    public name, so this hostname is not a destination.
	g.tlsFlow(flow{
		client: "192.168.1.50", server: "104.18.32.7", sport: 51500, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "cloudflare-ech.com", ECH: true,
			ALPN: []string{"h2"}, SupportedVersions: []uint16{tls13},
			Groups: []uint16{x25519MLKEM768, x25519}, KeyShares: []uint16{x25519MLKEM768},
			SigAlgs: modernSigAlgs,
		},
		sh: &tlssynth.ServerHelloSpec{
			Cipher: tlsAES128GCMSHA256, SelectedVersion: tls13, Group: x25519MLKEM768, ALPN: "h2",
		},
	})

	// 8. A client whose server never answered. Still worth reporting: it
	//    says what this client is willing to negotiate.
	g.tlsFlow(flow{
		client: "192.168.1.54", server: "203.0.113.9", sport: 55001, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "unreachable.example",
			SupportedVersions: []uint16{tls13, tls12},
			Groups:            []uint16{x25519, secp256r1}, KeyShares: []uint16{x25519},
			SigAlgs: modernSigAlgs,
		},
	})

	// 9. IPv6, to exercise that decode path.
	g.tlsFlow(flow{
		client: "2001:db8::50", server: "2606:4700::6810:2007", sport: 51600, dport: 443,
		ch: tlssynth.ClientHelloSpec{
			Ciphers: modernCiphers, SNI: "ipv6.example.com",
			ALPN: []string{"h2"}, SupportedVersions: []uint16{tls13},
			Groups: []uint16{x25519MLKEM768, x25519}, KeyShares: []uint16{x25519MLKEM768},
			SigAlgs: modernSigAlgs,
		},
		sh: &tlssynth.ServerHelloSpec{
			Cipher: tlsAES256GCMSHA384, SelectedVersion: tls13, Group: x25519MLKEM768, ALPN: "h2",
		},
	})

	// 10. Plain HTTP, which must be rejected on content rather than by port.
	g.rawFlow("192.168.1.50", "10.20.0.80", 51700, 8080,
		[]byte("GET /health HTTP/1.1\r\nHost: 10.20.0.80\r\nUser-Agent: curl/8.6.0\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

	// 11. SSH, likewise.
	g.rawFlow("192.168.1.50", "10.20.0.22", 51701, 22,
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"), []byte("SSH-2.0-OpenSSH_9.3\r\n"))

	fmt.Printf("wrote %s (%d packets, %d flows)\n", out, g.packets, g.flows)
}

type flow struct {
	client, server string
	sport, dport   uint16
	ch             tlssynth.ClientHelloSpec
	sh             *tlssynth.ServerHelloSpec
	ske            uint16   // TLS 1.2 ServerKeyExchange named curve, 0 to omit
	certs          [][]byte // TLS 1.2 certificate chain, nil to omit
}

type gen struct {
	w       *pcapgo.Writer
	now     time.Time
	packets int
	flows   int
}

// tlsFlow writes a complete TCP connection carrying a TLS handshake.
func (g *gen) tlsFlow(f flow) {
	c2s := tlssynth.Records(tlssynth.RecordHandshake,
		tlssynth.HandshakeMsg(tlssynth.MsgClientHello, tlssynth.ClientHello(f.ch)), mss)

	var s2c []byte
	if f.sh != nil {
		var msgs []byte
		msgs = append(msgs, tlssynth.HandshakeMsg(tlssynth.MsgServerHello,
			tlssynth.ServerHello(*f.sh))...)
		if f.certs != nil {
			msgs = append(msgs, tlssynth.HandshakeMsg(tlssynth.MsgCertificate,
				tlssynth.CertificateMsg(f.certs))...)
		}
		if f.ske != 0 {
			msgs = append(msgs, tlssynth.HandshakeMsg(tlssynth.MsgServerKeyExchange,
				tlssynth.ServerKeyExchangeECDHE(f.ske))...)
			msgs = append(msgs, tlssynth.HandshakeMsg(tlssynth.MsgServerHelloDone, nil)...)
		}
		s2c = tlssynth.Records(tlssynth.RecordHandshake, msgs, mss)
	}
	g.rawFlow(f.client, f.server, f.sport, f.dport, c2s, s2c)
}

// rawFlow writes a TCP connection: handshake, one direction of payload, the
// other, then a clean close.
func (g *gen) rawFlow(client, server string, sport, dport uint16, c2s, s2c []byte) {
	g.flows++
	cIP, sIP := net.ParseIP(client), net.ParseIP(server)
	var cSeq, sSeq uint32 = 1000, 5000

	g.emit(cIP, sIP, sport, dport, cSeq, 0, tcpFlags{syn: true}, nil)
	cSeq++
	g.emit(sIP, cIP, dport, sport, sSeq, cSeq, tcpFlags{syn: true, ack: true}, nil)
	sSeq++
	g.emit(cIP, sIP, sport, dport, cSeq, sSeq, tcpFlags{ack: true}, nil)

	for len(c2s) > 0 {
		n := min(mss, len(c2s))
		g.emit(cIP, sIP, sport, dport, cSeq, sSeq, tcpFlags{ack: true, psh: n == len(c2s)}, c2s[:n])
		cSeq += uint32(n)
		c2s = c2s[n:]
	}
	for len(s2c) > 0 {
		n := min(mss, len(s2c))
		g.emit(sIP, cIP, dport, sport, sSeq, cSeq, tcpFlags{ack: true, psh: n == len(s2c)}, s2c[:n])
		sSeq += uint32(n)
		s2c = s2c[n:]
	}

	g.emit(cIP, sIP, sport, dport, cSeq, sSeq, tcpFlags{fin: true, ack: true}, nil)
	cSeq++
	g.emit(sIP, cIP, dport, sport, sSeq, cSeq, tcpFlags{fin: true, ack: true}, nil)
}

type tcpFlags struct{ syn, ack, psh, fin bool }

func (g *gen) emit(src, dst net.IP, sport, dport uint16, seq, ack uint32, fl tcpFlags, payload []byte) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport),
		Seq: seq, Ack: ack, Window: 65535,
		SYN: fl.syn, ACK: fl.ack, PSH: fl.psh, FIN: fl.fin,
	}

	var netLayer gopacket.SerializableLayer
	if v4 := src.To4(); v4 != nil {
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64,
			Protocol: layers.IPProtocolTCP, SrcIP: v4, DstIP: dst.To4(),
		}
		tcp.SetNetworkLayerForChecksum(ip)
		netLayer = ip
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{
			Version: 6, HopLimit: 64,
			NextHeader: layers.IPProtocolTCP, SrcIP: src, DstIP: dst,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		netLayer = ip
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, netLayer, tcp, gopacket.Payload(payload)); err != nil {
		log.Fatalf("serialize: %v", err)
	}
	b := buf.Bytes()

	g.now = g.now.Add(250 * time.Microsecond)
	ci := gopacket.CaptureInfo{Timestamp: g.now, CaptureLength: len(b), Length: len(b)}
	if err := g.w.WritePacket(ci, b); err != nil {
		log.Fatalf("write: %v", err)
	}
	g.packets++
}

// selfSigned returns a DER certificate with an RSA key of the given size.
func selfSigned(cn string, bits int) []byte {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    baseTime.Add(-365 * 24 * time.Hour),
		NotAfter:     baseTime.Add(365 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return der
}
