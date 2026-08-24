package assemble_test

import (
	"io"
	"testing"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/capture"
	"github.com/tlscensus/tlscensus/internal/inventory"
)

// End-to-end over the committed sample capture. Regenerate the capture with
// `go run ./testdata/gen` if these expectations change.
const samplePcap = "../../testdata/sample.pcap"

func readSample(t *testing.T) ([]*inventory.Record, assemble.Stats) {
	t.Helper()

	var records []*inventory.Record
	asm := assemble.New(func(f *assemble.Flow) {
		records = append(records, inventory.Analyze(f))
	}, assemble.Options{})

	src, err := capture.OpenFile(samplePcap)
	if err != nil {
		t.Fatalf("open %s: %v", samplePcap, err)
	}
	defer src.Close()

	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		asm.Packet(data, ci, src.LinkType())
	}
	asm.Close()
	return records, asm.Stats()
}

func byServerName(records []*inventory.Record, name string) *inventory.Record {
	for _, r := range records {
		if r.ServerName == name {
			return r
		}
	}
	return nil
}

func TestSampleCapture(t *testing.T) {
	records, stats := readSample(t)

	if got, want := len(records), 9; got != want {
		t.Fatalf("got %d TLS flows, want %d", got, want)
	}
	// HTTP and SSH must be discarded on content, having been examined
	// despite not being on port 443.
	if got, want := stats.RejectedTCP, int64(2); got != want {
		t.Errorf("RejectedTCP = %d, want %d", got, want)
	}
	if stats.Streams != 11 {
		t.Errorf("Streams = %d, want 11", stats.Streams)
	}
}

// The ClientHello offering X25519MLKEM768 is over 1400 bytes and therefore
// spans two TCP segments. If reassembly regresses, this flow disappears —
// and it is exactly the flow a post-quantum inventory exists to find.
func TestPostQuantumFlowSurvivesSegmentation(t *testing.T) {
	records, _ := readSample(t)

	r := byServerName(records, "www.cloudflare.com")
	if r == nil {
		t.Fatal("the post-quantum flow was not reported at all")
	}
	if r.PQ != inventory.PQNegotiated {
		t.Errorf("PQ = %q, want %q", r.PQ, inventory.PQNegotiated)
	}
	if r.Group != "X25519MLKEM768" {
		t.Errorf("Group = %q, want X25519MLKEM768", r.Group)
	}
	if r.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want TLS 1.3", r.Version)
	}
	if len(r.KeyShareGroups) != 2 || r.KeyShareGroups[0] != "X25519MLKEM768" {
		t.Errorf("KeyShareGroups = %v, want [X25519MLKEM768 x25519]", r.KeyShareGroups)
	}
	if r.Truncated {
		t.Error("Truncated = true on a fully captured handshake")
	}
}

// Advertising a post-quantum group is not the same as sending a key share
// for it. Collapsing the two is how a readiness number flatters itself.
func TestPQLadderDistinguishesOfferedFromAdvertised(t *testing.T) {
	records, _ := readSample(t)

	for name, want := range map[string]inventory.PQStatus{
		"www.cloudflare.com":  inventory.PQNegotiated,
		"example.com":         inventory.PQOffered,
		"www.google.com":      inventory.PQAdvertised,
		"unreachable.example": inventory.PQClassical,
	} {
		r := byServerName(records, name)
		if r == nil {
			t.Errorf("%s: flow missing", name)
			continue
		}
		if r.PQ != want {
			t.Errorf("%s: PQ = %q, want %q", name, r.PQ, want)
		}
	}
}

// A handshake on 8443 or 9443 is still a handshake. Port-based filtering is
// how an inventory concludes there are no weak ciphers by not looking.
func TestNonStandardPorts(t *testing.T) {
	records, _ := readSample(t)

	for _, tc := range []struct {
		name string
		port uint16
	}{
		{"old-appliance.internal.example", 8443},
		{"", 9443}, // the TLS 1.0 flow sends no SNI
	} {
		var found *inventory.Record
		for _, r := range records {
			if r.ServerPort == tc.port {
				found = r
				break
			}
		}
		if found == nil {
			t.Errorf("no flow found on port %d", tc.port)
			continue
		}
		if found.ServerName != tc.name {
			t.Errorf("port %d: ServerName = %q, want %q", tc.port, found.ServerName, tc.name)
		}
	}
}

func TestFindingsOnLegacyFlow(t *testing.T) {
	records, _ := readSample(t)

	var legacy *inventory.Record
	for _, r := range records {
		if r.CipherSuite == "TLS_RSA_WITH_RC4_128_SHA" {
			legacy = r
		}
	}
	if legacy == nil {
		t.Fatal("the TLS 1.0 / RC4 flow was not reported")
	}
	if got := legacy.MaxSeverity(); got != inventory.SevCritical {
		t.Errorf("MaxSeverity = %q, want critical", got)
	}

	want := map[string]bool{
		inventory.FindingObsoleteProtocol: false,
		inventory.FindingBrokenCipher:     false,
		inventory.FindingNoForwardSecrecy: false,
	}
	for _, f := range legacy.Findings {
		if _, ok := want[f.ID]; ok {
			want[f.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("finding %q not reported", id)
		}
	}
}

// Under ECH the visible name belongs to the provider, not the destination.
// It must be flagged so no consumer counts it as a hostname.
func TestECHIsFlagged(t *testing.T) {
	records, _ := readSample(t)

	r := byServerName(records, "cloudflare-ech.com")
	if r == nil {
		t.Fatal("the ECH flow was not reported")
	}
	if !r.ECH {
		t.Error("ECH = false, want true")
	}

	acc := inventory.NewAccumulator()
	for _, rec := range records {
		acc.Add(rec)
	}
	s := acc.Summary(0)
	if s.ECHFlows != 1 {
		t.Errorf("Summary.ECHFlows = %d, want 1", s.ECHFlows)
	}
	for _, c := range s.ServerName {
		if c.Name == "cloudflare-ech.com" {
			t.Error("an ECH outer name leaked into the server name distribution")
		}
	}
}

// TLS 1.2 states its group only in ServerKeyExchange, and is the only
// version where the certificate is visible at all.
func TestTLS12CertificateAndGroup(t *testing.T) {
	records, _ := readSample(t)

	r := byServerName(records, "legacy.internal.example")
	if r == nil {
		t.Fatal("the TLS 1.2 flow was not reported")
	}
	if r.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2", r.Version)
	}
	if r.Group != "secp256r1" || r.GroupSource != "server_key_exchange" {
		t.Errorf("Group = %q from %q, want secp256r1 from server_key_exchange", r.Group, r.GroupSource)
	}
	if len(r.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(r.Certificates))
	}
	if got := r.Certificates[0].KeyBits; got != 2048 {
		t.Errorf("KeyBits = %d, want 2048", got)
	}
}

// A TLS 1.3 flow must report no certificates: the message is encrypted, and
// reporting an empty chain as "no certificate" would be a different claim.
func TestTLS13HasNoVisibleCertificate(t *testing.T) {
	records, _ := readSample(t)

	r := byServerName(records, "www.cloudflare.com")
	if r == nil {
		t.Fatal("flow missing")
	}
	if len(r.Certificates) != 0 {
		t.Errorf("got %d certificates on a TLS 1.3 flow, want 0", len(r.Certificates))
	}
}

func TestSummaryReadiness(t *testing.T) {
	records, _ := readSample(t)

	acc := inventory.NewAccumulator()
	for _, r := range records {
		acc.Add(r)
	}
	s := acc.Summary(0)

	if s.Flows != 9 {
		t.Errorf("Flows = %d, want 9", s.Flows)
	}
	// Eight flows had a captured response; three negotiated a PQ group.
	if s.ServerObserved != 8 {
		t.Errorf("ServerObserved = %d, want 8", s.ServerObserved)
	}
	if want := 3.0 / 8.0; s.PQReadiness != want {
		t.Errorf("PQReadiness = %v, want %v", s.PQReadiness, want)
	}
}

// concurrentPcap holds many connections open at once and never closes them.
// The sample capture writes each connection start to finish before the next
// begins, so with connection close handled properly no more than one is ever
// in flight — the wrong shape for exercising the cap.
const concurrentPcap = "../../testdata/concurrent.pcap"

func readCapture(t *testing.T, path string, opts assemble.Options) ([]*inventory.Record, assemble.Stats) {
	t.Helper()

	var records []*inventory.Record
	asm := assemble.New(func(f *assemble.Flow) {
		records = append(records, inventory.Analyze(f))
	}, opts)

	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer src.Close()
	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		asm.Packet(data, ci, src.LinkType())
	}
	asm.Close()
	return records, asm.Stats()
}

// The stream cap is what stops a busy host from multiplying the per-stream
// prefix by an unbounded factor. When it bites, the shortfall must be
// visible in Stats rather than silently absorbed — an inventory that
// quietly stops counting is the failure this tool exists to avoid.
func TestMaxStreamsIsEnforcedAndReported(t *testing.T) {
	records, stats := readCapture(t, concurrentPcap, assemble.Options{MaxStreams: 4})

	if stats.Streams != 12 {
		t.Errorf("Streams = %d, want 12 — dropped streams must still be counted", stats.Streams)
	}
	if stats.StreamsDropped != 8 {
		t.Errorf("StreamsDropped = %d, want 8 (12 concurrent, cap 4)", stats.StreamsDropped)
	}
	if len(records) > 4 {
		t.Errorf("emitted %d flows, want at most the cap of 4", len(records))
	}
	// Whatever was tracked must be reported, not lost.
	if len(records) != 4 {
		t.Errorf("emitted %d flows, want exactly the 4 that were tracked", len(records))
	}
}

// At the default cap the same capture must be reported in full.
func TestConcurrentCaptureFullyReported(t *testing.T) {
	records, stats := readCapture(t, concurrentPcap, assemble.Options{})

	if stats.StreamsDropped != 0 {
		t.Errorf("StreamsDropped = %d at the default cap, want 0", stats.StreamsDropped)
	}
	if len(records) != 12 {
		t.Fatalf("emitted %d flows, want 12", len(records))
	}
	// These connections never close, so they are released by the shutdown
	// flush with client data only.
	for _, r := range records {
		if r.ServerObserved {
			t.Errorf("%s: ServerObserved = true, but no response was captured", r.ServerName)
		}
		if r.PQ != inventory.PQOffered {
			t.Errorf("%s: PQ = %q, want %q", r.ServerName, r.PQ, inventory.PQOffered)
		}
	}
}

// Without a cap the sample capture must be fully reported, and the live
// count must still unwind.
func TestLiveStreamAccountingUnwinds(t *testing.T) {
	_, stats := readSample(t)
	if stats.LiveStreams != 0 {
		t.Errorf("LiveStreams = %d after close, want 0", stats.LiveStreams)
	}
	if stats.StreamsDropped != 0 {
		t.Errorf("StreamsDropped = %d at the default cap, want 0", stats.StreamsDropped)
	}
}

// Flows must be emitted when the connection closes, not held until the
// assembler is shut down.
//
// This is the regression test for a bug that offline analysis cannot see.
// reassembly consults Accept before handling FIN, so a stream that stops
// accepting packets also stops seeing its own close: the flow is then only
// released by the idle sweep, two minutes later. Reading a capture file hid
// it entirely, because Close flushes everything at EOF. On a live interface
// it meant a handshake that completed a second ago went unreported.
func TestFlowsEmitOnCloseNotOnShutdown(t *testing.T) {
	var duringRun int
	var closed bool

	asm := assemble.New(func(f *assemble.Flow) {
		if !closed {
			duringRun++
		}
	}, assemble.Options{})

	src, err := capture.OpenFile(samplePcap)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		asm.Packet(data, ci, src.LinkType())
	}

	closed = true
	asm.Close()

	// Every connection in the sample capture closes with FIN, so every
	// flow must already have been reported before Close was called.
	if want := 9; duringRun != want {
		t.Errorf("%d of %d flows emitted on connection close; the rest waited "+
			"for shutdown, which live capture cannot do", duringRun, want)
	}
}

// keepalivePcap holds completed TLS 1.3 handshakes on connections that are
// never closed — the shape of a browser keep-alive.
const keepalivePcap = "../../testdata/keepalive.pcap"

// An observation must be reported when the handshake is complete, not when
// the connection closes.
//
// This is the regression test for a bug that only live capture reveals.
// Reporting on close is invisible offline, because Close flushes everything
// at end of file and every synthetic connection ends. On a real interface a
// browser holds connections open for minutes, so a site visited a second ago
// stayed absent from the report — the capture looked like it was working and
// was silently minutes behind.
func TestHandshakeReportedBeforeConnectionCloses(t *testing.T) {
	var duringRun int
	closed := false

	asm := assemble.New(func(f *assemble.Flow) {
		if !closed {
			duringRun++
		}
	}, assemble.Options{})

	src, err := capture.OpenFile(keepalivePcap)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		asm.Packet(data, ci, src.LinkType())
	}

	closed = true
	asm.Close()

	if want := 4; duringRun != want {
		t.Errorf("%d of %d handshakes reported before their connections closed; "+
			"the rest waited, which on a live interface means minutes of silence",
			duringRun, want)
	}
}

// The early report must be complete, not a placeholder filled in later.
func TestEarlyReportIsComplete(t *testing.T) {
	records, _ := readCapture(t, keepalivePcap, assemble.Options{})
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4", len(records))
	}
	for _, r := range records {
		if !r.ServerObserved {
			t.Errorf("%s: ServerObserved = false", r.ServerName)
		}
		if r.PQ != inventory.PQNegotiated {
			t.Errorf("%s: PQ = %q, want %q", r.ServerName, r.PQ, inventory.PQNegotiated)
		}
		if r.Group != "X25519MLKEM768" {
			t.Errorf("%s: Group = %q", r.ServerName, r.Group)
		}
		if r.CipherSuite != "TLS_AES_128_GCM_SHA256" {
			t.Errorf("%s: CipherSuite = %q", r.ServerName, r.CipherSuite)
		}
	}
}
