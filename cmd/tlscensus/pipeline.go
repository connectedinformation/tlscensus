package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
	"github.com/connectedinformation/tlscensus/internal/inventory"
	"github.com/connectedinformation/tlscensus/internal/report"
)

// pipeline wires capture to inventory. Both read and watch use it, so the
// only difference between offline and live analysis is where packets come
// from — the parsing, reassembly and judgement are identical.
type pipeline struct {
	// mu guards the assembler and everything the handler touches.
	//
	// assemble.Assembler is explicitly not safe for concurrent use, and
	// live capture drives it from two goroutines: the capture loop calls
	// packet, while a ticker calls flushOlderThan. Every entry point below
	// takes mu so those two serialise against each other.
	mu      sync.Mutex
	asm     *assemble.Assembler
	acc     *inventory.Accumulator
	records []*inventory.Record

	// pending holds records emitted by the assembler call in progress.
	// The handler runs deep inside that call with mu held, so it cannot
	// deliver to onRecord itself: watch's writer takes its own output
	// lock, and a flush that already held that lock would deadlock
	// against it. Records are queued here and handed out by deliver once
	// mu is released.
	pending []*inventory.Record

	// onRecord, when set, is called as each flow completes. Live capture
	// uses it to stream; offline analysis collects and sorts instead.
	onRecord func(*inventory.Record)
	// keep controls whether records are retained for a final report.
	keep bool
}

func newPipeline(opts assemble.Options, keep bool, onRecord func(*inventory.Record)) *pipeline {
	p := &pipeline{acc: inventory.NewAccumulator(), keep: keep, onRecord: onRecord}
	p.asm = assemble.New(func(f *assemble.Flow) {
		// Runs with mu held; see the pending field.
		rec := inventory.Analyze(f)
		p.acc.Add(rec)
		if p.keep {
			p.records = append(p.records, rec)
		}
		if p.onRecord != nil {
			p.pending = append(p.pending, rec)
		}
	}, opts)
	return p
}

// takePending removes and returns the records queued by the assembler call
// in progress. It must be called with mu held.
func (p *pipeline) takePending() []*inventory.Record {
	recs := p.pending
	p.pending = nil
	return recs
}

// deliver streams records to onRecord. It must be called with mu released,
// so the writer is free to take its own output lock.
func (p *pipeline) deliver(recs []*inventory.Record) {
	for _, rec := range recs {
		p.onRecord(rec)
	}
}

// packet feeds one captured packet through reassembly.
func (p *pipeline) packet(data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType) {
	p.mu.Lock()
	p.asm.Packet(data, ci, linkType)
	recs := p.takePending()
	p.mu.Unlock()
	p.deliver(recs)
}

// flushOlderThan sweeps streams idle since t, reporting whatever they hold.
func (p *pipeline) flushOlderThan(t time.Time) {
	p.mu.Lock()
	p.asm.FlushOlderThan(t)
	recs := p.takePending()
	p.mu.Unlock()
	p.deliver(recs)
}

// run pumps every packet from src through the assembler.
func (p *pipeline) run(src capture.Source) error {
	linkType := src.LinkType()
	for {
		data, ci, err := src.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		p.packet(data, ci, linkType)
	}
}

// snapshot builds a report from a pipeline that is still running. Unlike
// finish it does not close the assembler, so flows still in flight stay in
// flight and the capture continues.
func (p *pipeline) snapshot(sources []string, top int) (*report.Report, []*inventory.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()

	records := make([]*inventory.Record, len(p.records))
	copy(records, p.records)
	report.SortRecords(records)
	return &report.Report{
		Tool:        "tlscensus",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sources:     sources,
		Stats:       p.asm.Stats(),
		Summary:     p.acc.Summary(top),
		Aggregates:  p.acc.Aggregates(0),
	}, records
}

func (p *pipeline) finish(sources []string, top int, withRecords bool) *report.Report {
	p.mu.Lock()
	p.asm.Close()
	recs := p.takePending()
	stats := p.asm.Stats()
	p.mu.Unlock()

	// Stream the last flows before the summary, not during it.
	p.deliver(recs)

	p.mu.Lock()
	defer p.mu.Unlock()
	report.SortRecords(p.records)
	rep := &report.Report{
		Tool:        "tlscensus",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sources:     sources,
		Stats:       stats,
		Summary:     p.acc.Summary(top),
		Aggregates:  p.acc.Aggregates(0),
	}
	if withRecords {
		rep.Records = p.records
	}
	return rep
}

// warnIfIncomplete tells the user when the inventory is known to be short.
//
// A dropped stream is a handshake that was never examined. Reporting the
// total without saying so would present a partial census as a complete one,
// which is the specific dishonesty this tool is meant to avoid.
func warnIfIncomplete(s assemble.Stats) {
	if s.StreamsDropped > 0 {
		fmt.Fprintf(os.Stderr,
			"tlscensus: warning: %d connections were not examined because the "+
				"stream cap was reached; this inventory is incomplete. "+
				"Raise -max-streams.\n", s.StreamsDropped)
	}
}

func writeReport(format string, rep *report.Report, records []*inventory.Record) error {
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	switch format {
	case "ndjson":
		return report.WriteNDJSON(out, records)
	case "json":
		return report.WriteJSON(out, rep)
	case "cbom":
		return report.WriteCBOM(out, rep, records)
	case "html":
		return report.WriteHTML(out, rep, records)
	default:
		return report.WriteText(out, rep)
	}
}

func validateFormat(format string) error {
	switch format {
	case "text", "json", "ndjson", "cbom", "html":
		return nil
	}
	return fmt.Errorf("unknown output format %q (want text, json, ndjson, cbom or html)", format)
}
