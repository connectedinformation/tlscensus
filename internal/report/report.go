// Package report renders an inventory as text, JSON or NDJSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/inventory"
)

// Report is the complete output of one run.
type Report struct {
	Tool        string              `json:"tool"`
	Version     string              `json:"version"`
	GeneratedAt time.Time           `json:"generated_at"`
	Sources     []string            `json:"sources"`
	Stats       assemble.Stats      `json:"stats"`
	Summary     inventory.Summary   `json:"summary"`
	Records     []*inventory.Record `json:"records,omitempty"`
}

// WriteJSON renders the whole report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteNDJSON renders one record per line. This is the streaming form: it
// can be written as flows complete, and it pipes into jq or a log shipper
// without the consumer holding the whole run in memory.
func WriteNDJSON(w io.Writer, records []*inventory.Record) error {
	enc := json.NewEncoder(w)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// WriteText renders a human-readable summary.
func WriteText(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "tlscensus %s\n", r.Version)
	if len(r.Sources) > 0 {
		fmt.Fprintf(w, "source:   %s\n", strings.Join(r.Sources, ", "))
	}
	if !r.Summary.FirstSeen.IsZero() {
		fmt.Fprintf(w, "captured: %s .. %s\n",
			r.Summary.FirstSeen.UTC().Format(time.RFC3339),
			r.Summary.LastSeen.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "packets:  %d (%d TCP), streams: %d, TLS flows: %d, non-TLS discarded: %d\n\n",
		r.Stats.Packets, r.Stats.TCPPackets, r.Stats.Streams, r.Stats.TLSFlows, r.Stats.RejectedTCP)

	if r.Summary.Flows == 0 {
		fmt.Fprintln(w, "No TLS handshakes found.")
		return nil
	}

	s := r.Summary
	fmt.Fprintf(w, "TLS handshakes:   %d (%d with a captured server response)\n",
		s.Flows, s.ServerObserved)
	if s.ServerObserved > 0 {
		fmt.Fprintf(w, "PQ readiness:     %.1f%% of observed negotiations used a post-quantum group\n",
			s.PQReadiness*100)
	}
	if s.ECHFlows > 0 {
		fmt.Fprintf(w, "ECH in use:       %d flows (server_name is a public outer name, not the destination)\n",
			s.ECHFlows)
	}
	fmt.Fprintln(w)

	section(w, "POST-QUANTUM STATUS", s.PQ, s.Flows)
	section(w, "PROTOCOL VERSION", s.Versions, s.Flows)
	section(w, "CIPHER SUITE (negotiated)", s.Ciphers, s.ServerObserved)
	section(w, "KEY EXCHANGE GROUP (negotiated)", s.Groups, s.ServerObserved)
	section(w, "ALPN", s.ALPN, s.Flows)
	section(w, "SERVER NAME", s.ServerName, s.Flows)
	section(w, "CLIENT FINGERPRINT (JA4)", s.JA4, s.Flows)

	if len(s.Findings) > 0 {
		fmt.Fprintln(w, "FINDINGS")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range s.Findings {
			fmt.Fprintf(tw, "  %s\t%6d\t%s\t%s\n",
				strings.ToUpper(string(f.Severity)), f.Count, f.ID, f.Example)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}
	return nil
}

func section(w io.Writer, title string, counts []inventory.Count, total int) {
	if len(counts) == 0 {
		return
	}
	fmt.Fprintln(w, title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range counts {
		pct := ""
		if total > 0 {
			pct = fmt.Sprintf("%5.1f%%", float64(c.Count)/float64(total)*100)
		}
		fmt.Fprintf(tw, "  %s\t%6d\t%s\n", c.Name, c.Count, pct)
	}
	tw.Flush()
	fmt.Fprintln(w)
}

// SortRecords orders records by severity then by time, so the most
// alarming handshake is the first thing a reader sees.
func SortRecords(records []*inventory.Record) {
	rank := map[inventory.Severity]int{
		inventory.SevCritical: 4, inventory.SevHigh: 3,
		inventory.SevMedium: 2, inventory.SevLow: 1, inventory.SevInfo: 0,
	}
	sort.SliceStable(records, func(i, j int) bool {
		ri, rj := rank[records[i].MaxSeverity()], rank[records[j].MaxSeverity()]
		if ri != rj {
			return ri > rj
		}
		return records[i].FirstSeen.Before(records[j].FirstSeen)
	})
}
