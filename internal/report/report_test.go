package report_test

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
	"github.com/connectedinformation/tlscensus/internal/inventory"
	"github.com/connectedinformation/tlscensus/internal/report"
)

func sampleReport(t *testing.T) (*report.Report, []*inventory.Record) {
	t.Helper()

	var records []*inventory.Record
	acc := inventory.NewAccumulator()
	asm := assemble.New(func(f *assemble.Flow) {
		rec := inventory.Analyze(f)
		acc.Add(rec)
		records = append(records, rec)
	}, assemble.Options{})

	src, err := capture.OpenFile("../../testdata/sample.pcap")
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
	asm.Close()

	return &report.Report{
		Tool: "tlscensus", Version: "test",
		GeneratedAt: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Sources:     []string{"sample.pcap"},
		Stats:       asm.Stats(),
		Summary:     acc.Summary(15),
		Aggregates:  acc.Aggregates(0),
	}, records
}

func TestCBOMStructure(t *testing.T) {
	rep, records := sampleReport(t)
	var buf strings.Builder
	if err := report.WriteCBOM(&buf, rep, records); err != nil {
		t.Fatal(err)
	}

	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			Type             string `json:"type"`
			Name             string `json:"name"`
			CryptoProperties struct {
				AssetType           string `json:"assetType"`
				AlgorithmProperties struct {
					Primitive string `json:"primitive"`
					NISTLevel *int   `json:"nistQuantumSecurityLevel"`
				} `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		t.Errorf("got %s %s, want CycloneDX 1.6", bom.BOMFormat, bom.SpecVersion)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want a urn:uuid", bom.SerialNumber)
	}

	byName := map[string]int{}
	for _, c := range bom.Components {
		if c.Type != "cryptographic-asset" {
			t.Errorf("%s: type = %q, want cryptographic-asset", c.Name, c.Type)
		}
		byName[c.Name] = *new(int)
		switch c.Name {
		case "X25519MLKEM768":
			p := c.CryptoProperties.AlgorithmProperties
			// A hybrid combines classical key agreement with a KEM.
			if p.Primitive != "combiner" {
				t.Errorf("X25519MLKEM768 primitive = %q, want combiner", p.Primitive)
			}
			if p.NISTLevel == nil || *p.NISTLevel != 3 {
				t.Errorf("X25519MLKEM768 NIST level = %v, want 3", p.NISTLevel)
			}
		case "x25519":
			p := c.CryptoProperties.AlgorithmProperties
			if p.Primitive != "key-agree" {
				t.Errorf("x25519 primitive = %q, want key-agree", p.Primitive)
			}
			// Classical groups have no post-quantum security, and saying
			// otherwise is the one number a CBOM must not get wrong.
			if p.NISTLevel == nil || *p.NISTLevel != 0 {
				t.Errorf("x25519 NIST level = %v, want 0", p.NISTLevel)
			}
		case "TLS_RSA_WITH_RC4_128_SHA":
			if p := c.CryptoProperties.AlgorithmProperties.Primitive; p != "stream-cipher" {
				t.Errorf("RC4 primitive = %q, want stream-cipher", p)
			}
		}
	}
	for _, want := range []string{"X25519MLKEM768", "x25519", "TLS 1.3", "TLS 1.2"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("no component named %q", want)
		}
	}
}

// The serial number is derived from the asset set, not from randomness, so
// two runs over the same inventory produce the same document.
func TestCBOMIsDeterministic(t *testing.T) {
	rep, records := sampleReport(t)
	var a, b strings.Builder
	if err := report.WriteCBOM(&a, rep, records); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteCBOM(&b, rep, records); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("two renders of the same inventory differ")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	rep, records := sampleReport(t)
	var buf strings.Builder
	if err := report.WriteHTML(&buf, rep, records); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// The page names every host the traffic contacted. Fetching anything
	// while rendering would leak that to whoever serves the asset.
	for _, bad := range []string{"src=\"http", "href=\"http", "@import", "fonts.googleapis", "cdn."} {
		if strings.Contains(out, bad) {
			t.Errorf("page references an external resource: %q", bad)
		}
	}
	for _, want := range []string{
		"Post-quantum readiness",
		"X25519MLKEM768",
		"prefers-color-scheme", // dark mode is defined, not inherited
		`data-theme="dark"`,    // and the explicit toggle wins too
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// Server names come off the network and the report is opened in a browser.
// Anything reflected into the page has to be escaped, or a hostile SNI
// becomes script execution on the analyst's machine.
func TestHTMLEscapesHostileServerName(t *testing.T) {
	hostile := `<script>alert('xss')</script>`
	rec := &inventory.Record{
		FirstSeen: time.Now(), LastSeen: time.Now(),
		ClientIP: netip.MustParseAddr("192.0.2.1"), ClientPort: 1234,
		ServerIP: netip.MustParseAddr("192.0.2.2"), ServerPort: 443,
		ServerName: hostile, ServerObserved: true,
		Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
		Group: "x25519", PQ: inventory.PQClassical,
		JA4: `"><img src=x onerror=alert(1)>`,
	}
	acc := inventory.NewAccumulator()
	acc.Add(rec)

	var buf strings.Builder
	err := report.WriteHTML(&buf, &report.Report{
		Tool: "tlscensus", Version: "test", GeneratedAt: time.Now(),
		Sources: []string{"x"}, Summary: acc.Summary(15),
	}, []*inventory.Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Check for unescaped tag *structure*, not for scary substrings.
	// "onerror=alert(1)" survives escaping as inert text — only the angle
	// brackets and quotes decide whether it can execute.
	for _, bad := range []string{"<script>alert", "<img src=x", `"><img`} {
		if strings.Contains(out, bad) {
			t.Errorf("hostile input reached the page unescaped: %q", bad)
		}
	}
	// And it must still be *shown*, escaped — dropping it silently would
	// hide the very connection worth looking at.
	for _, want := range []string{"&lt;script&gt;", "&#34;&gt;&lt;img"} {
		if !strings.Contains(out, want) {
			t.Errorf("hostile input was dropped rather than escaped: expected %q", want)
		}
	}
}

// An inventory is a set, not a log: handshakes that differ only in client
// port and millisecond are one finding, not many.
func TestAggregationCollapsesRepeats(t *testing.T) {
	rep, records := sampleReport(t)
	if len(rep.Aggregates) == 0 {
		t.Fatal("no aggregates produced")
	}
	if len(rep.Aggregates) > len(records) {
		t.Errorf("%d aggregates from %d records", len(rep.Aggregates), len(records))
	}

	total := 0
	for _, a := range rep.Aggregates {
		total += a.Count
		if a.Count < 1 {
			t.Errorf("%s: Count = %d", a.ServerName, a.Count)
		}
		if a.LastSeen.Before(a.FirstSeen) {
			t.Errorf("%s: LastSeen before FirstSeen", a.ServerName)
		}
	}
	// Every handshake must be accounted for by exactly one aggregate;
	// an inventory that loses events while collapsing them is worse than
	// one that does not collapse at all.
	if total != len(records) {
		t.Errorf("aggregate counts sum to %d, want %d", total, len(records))
	}
}

// JA4 must not split the key. It did once, and a host reached with several
// client configurations produced a separate single-count row for each,
// identical in every displayed column because the fingerprints differed
// invisibly.
func TestClientFingerprintDoesNotSplitFindings(t *testing.T) {
	base := func(ja4 string, port uint16) *inventory.Record {
		return &inventory.Record{
			Transport: "tcp", FirstSeen: time.Now(), LastSeen: time.Now(),
			ClientIP: netip.MustParseAddr("192.0.2.1"), ClientPort: port,
			ServerIP: netip.MustParseAddr("192.0.2.2"), ServerPort: 443,
			ServerName: "example.com", ServerObserved: true,
			Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
			Group: "X25519MLKEM768", ALPN: "h2",
			PQ: inventory.PQNegotiated, JA4: ja4,
		}
	}
	acc := inventory.NewAccumulator()
	acc.Add(base("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", 1001))
	acc.Add(base("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", 1002))
	acc.Add(base("t13d0507h2_cccccccccccc_dddddddddddd", 1003))

	aggs := acc.Aggregates(0)
	if len(aggs) != 1 {
		t.Fatalf("got %d findings, want 1 — differing JA4 must not split a finding", len(aggs))
	}
	if aggs[0].Count != 3 {
		t.Errorf("Count = %d, want 3", aggs[0].Count)
	}
	// The diversity is still reported, just not as separate rows.
	if got := len(aggs[0].JA4s); got != 2 {
		t.Errorf("distinct client fingerprints = %d, want 2", got)
	}
}

// Different cryptography to the same host is a different finding.
func TestDifferentCryptoSplitsFindings(t *testing.T) {
	base := func(group string, pq inventory.PQStatus) *inventory.Record {
		return &inventory.Record{
			Transport: "tcp", FirstSeen: time.Now(), LastSeen: time.Now(),
			ClientIP: netip.MustParseAddr("192.0.2.1"),
			ServerIP: netip.MustParseAddr("192.0.2.2"), ServerPort: 443,
			ServerName: "example.com", ServerObserved: true,
			Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
			Group: group, PQ: pq,
		}
	}
	acc := inventory.NewAccumulator()
	acc.Add(base("X25519MLKEM768", inventory.PQNegotiated))
	acc.Add(base("x25519", inventory.PQClassical))

	if got := len(acc.Aggregates(0)); got != 2 {
		t.Errorf("got %d findings, want 2 — a different group is a different finding", got)
	}
}
