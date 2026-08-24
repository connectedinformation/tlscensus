package report_test

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/capture"
	"github.com/tlscensus/tlscensus/internal/inventory"
	"github.com/tlscensus/tlscensus/internal/report"
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
