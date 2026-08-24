package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/tlscensus/tlscensus/internal/inventory"
)

//go:embed report.html.tmpl
var htmlTemplate string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(f float64) string { return fmt.Sprintf("%.1f", f) },
}).Parse(htmlTemplate))

// The page is self-contained by design: inline CSS, no external fonts, no
// scripts beyond a table filter. A crypto inventory names every host a
// machine contacted, so it must be readable from a laptop with no network
// and must not fetch anything that would leak what it contains.

type htmlTile struct {
	Label string
	Value string
	Note  string
}

type htmlSeg struct {
	Label  string
	Count  int
	Pct    float64
	Width  float64
	Class  string
	Direct bool // direct-label this segment rather than rely on the legend
}

type htmlBar struct {
	Name  string
	Count int
	Pct   float64
	Width float64
}

type htmlSection struct {
	Title string
	Note  string
	Rows  []htmlBar
}

type htmlFinding struct {
	Severity string
	Class    string
	Icon     string
	ID       string
	Count    int
	Detail   string
}

type htmlView struct {
	Report      *Report
	Generated   string
	Window      string
	HeroValue   string
	HeroLabel   string
	HeroNote    string
	HasHero     bool
	Tiles       []htmlTile
	Ladder      []htmlSeg
	LadderTotal int
	Findings    []htmlFinding
	Sections    []htmlSection
	Records     []*inventory.Record
	Truncated   int
	// Refresh, when non-zero, emits a meta refresh so a live capture's page
	// updates itself. A meta tag rather than script: the page must stay
	// readable with JavaScript disabled.
	Refresh int
	Live    bool
}

// maxHTMLRows bounds the flow table. A busy host produces tens of thousands
// of handshakes and a browser will not render them usefully; the count of
// what was dropped is shown rather than silently truncating.
const maxHTMLRows = 2000

// pqLadder is the readiness ladder in order, worst to best. Rendering it as
// an ordered ramp rather than as unrelated categories is the point: these
// are stages of one migration, not five separate things.
var pqLadder = []struct {
	status inventory.PQStatus
	label  string
	class  string
}{
	{inventory.PQUnknown, "Unknown", "pq-unknown"},
	{inventory.PQClassical, "Classical only", "pq-0"},
	{inventory.PQAdvertised, "Advertised, not offered", "pq-1"},
	{inventory.PQOffered, "Offered, not selected", "pq-2"},
	{inventory.PQNegotiated, "Post-quantum", "pq-3"},
}

var severityClass = map[inventory.Severity]struct{ class, icon string }{
	inventory.SevCritical: {"sev-critical", "✕"},
	inventory.SevHigh:     {"sev-high", "▲"},
	inventory.SevMedium:   {"sev-medium", "◆"},
	inventory.SevLow:      {"sev-low", "●"},
	inventory.SevInfo:     {"sev-info", "○"},
}

// WriteHTML renders a self-contained report page.
func WriteHTML(w io.Writer, r *Report, records []*inventory.Record) error {
	return htmlTmpl.Execute(w, buildView(r, records))
}

// WriteLiveHTML renders the page with a refresh interval, for a capture
// still in progress.
func WriteLiveHTML(w io.Writer, r *Report, records []*inventory.Record, refreshSeconds int) error {
	v := buildView(r, records)
	v.Refresh = refreshSeconds
	v.Live = true
	return htmlTmpl.Execute(w, v)
}

func buildView(r *Report, records []*inventory.Record) *htmlView {
	s := r.Summary
	v := &htmlView{
		Report:    r,
		Generated: r.GeneratedAt.Format(time.RFC1123),
		Records:   records,
	}
	if !s.FirstSeen.IsZero() {
		v.Window = fmt.Sprintf("%s — %s",
			s.FirstSeen.UTC().Format("2006-01-02 15:04:05"),
			s.LastSeen.UTC().Format("15:04:05 MST"))
	}
	if len(records) > maxHTMLRows {
		v.Truncated = len(records) - maxHTMLRows
		v.Records = records[:maxHTMLRows]
	}

	// Exactly one hero figure. Readiness is the number this tool exists to
	// produce, and it is deliberately computed over negotiations that were
	// actually observed — a flow whose server never answered is excluded
	// rather than counted as a failure.
	if s.ServerObserved > 0 {
		v.HasHero = true
		v.HeroValue = fmt.Sprintf("%.1f%%", s.PQReadiness*100)
		v.HeroLabel = "Post-quantum readiness"
		v.HeroNote = fmt.Sprintf("of %d observed negotiations used a post-quantum key exchange",
			s.ServerObserved)
	}

	// The note only earns its place when there actually is a remainder;
	// "the rest report only what the client offered" beneath a number equal
	// to the total is noise that reads as a contradiction.
	responsesNote := ""
	if s.Flows > s.ServerObserved {
		responsesNote = fmt.Sprintf("%d report only what the client offered",
			s.Flows-s.ServerObserved)
	}
	v.Tiles = []htmlTile{
		{Label: "TLS handshakes", Value: compact(s.Flows)},
		{Label: "Server responses seen", Value: compact(s.ServerObserved), Note: responsesNote},
		{Label: "Connections examined", Value: compact(int(r.Stats.Streams)),
			Note: fmt.Sprintf("%s discarded as non-TLS", compact(int(r.Stats.RejectedTCP)))},
	}
	if s.ECHFlows > 0 {
		v.Tiles = append(v.Tiles, htmlTile{
			Label: "Encrypted ClientHello", Value: compact(s.ECHFlows),
			Note: "server names are the provider's, not the destination's",
		})
	}

	counts := map[inventory.PQStatus]int{}
	for _, c := range s.PQ {
		counts[inventory.PQStatus(c.Name)] = c.Count
	}
	for _, step := range pqLadder {
		n := counts[step.status]
		if n == 0 {
			continue
		}
		width := 0.0
		if s.Flows > 0 {
			width = float64(n) / float64(s.Flows) * 100
		}
		v.Ladder = append(v.Ladder, htmlSeg{
			Label: step.label, Count: n, Pct: width, Width: width,
			Class: step.class, Direct: width >= 12,
		})
	}
	v.LadderTotal = s.Flows

	for _, f := range s.Findings {
		sc := severityClass[f.Severity]
		v.Findings = append(v.Findings, htmlFinding{
			Severity: string(f.Severity), Class: sc.class, Icon: sc.icon,
			ID: f.ID, Count: f.Count, Detail: f.Example,
		})
	}

	v.Sections = []htmlSection{
		distSection("Protocol version", "", s.Versions, s.Flows),
		distSection("Cipher suite", "negotiated", s.Ciphers, s.ServerObserved),
		distSection("Key exchange group", "negotiated", s.Groups, s.ServerObserved),
		distSection("ALPN", "", s.ALPN, s.Flows),
		distSection("Server name", "ECH flows excluded — their names are not destinations",
			s.ServerName, s.Flows),
		distSection("Client fingerprint", "JA4", s.JA4, s.Flows),
	}
	return v
}

func distSection(title, note string, counts []inventory.Count, total int) htmlSection {
	sec := htmlSection{Title: title, Note: note}
	max := 0
	for _, c := range counts {
		if c.Count > max {
			max = c.Count
		}
	}
	for _, c := range counts {
		bar := htmlBar{Name: c.Name, Count: c.Count}
		if total > 0 {
			bar.Pct = float64(c.Count) / float64(total) * 100
		}
		// Bar length is relative to the largest row, so a long tail stays
		// readable; the printed percentage remains relative to the total.
		if max > 0 {
			bar.Width = float64(c.Count) / float64(max) * 100
		}
		sec.Rows = append(sec.Rows, bar)
	}
	return sec
}

// compact renders a count the way a stat tile should read.
func compact(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}
