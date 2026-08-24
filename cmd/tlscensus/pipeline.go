package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/capture"
	"github.com/tlscensus/tlscensus/internal/inventory"
	"github.com/tlscensus/tlscensus/internal/report"
)

// pipeline wires capture to inventory. Both read and watch use it, so the
// only difference between offline and live analysis is where packets come
// from — the parsing, reassembly and judgement are identical.
type pipeline struct {
	asm     *assemble.Assembler
	acc     *inventory.Accumulator
	records []*inventory.Record

	// onRecord, when set, is called as each flow completes. Live capture
	// uses it to stream; offline analysis collects and sorts instead.
	onRecord func(*inventory.Record)
	// keep controls whether records are retained for a final report.
	keep bool
}

func newPipeline(opts assemble.Options, keep bool, onRecord func(*inventory.Record)) *pipeline {
	p := &pipeline{acc: inventory.NewAccumulator(), keep: keep, onRecord: onRecord}
	p.asm = assemble.New(func(f *assemble.Flow) {
		rec := inventory.Analyze(f)
		p.acc.Add(rec)
		if p.onRecord != nil {
			p.onRecord(rec)
		}
		if p.keep {
			p.records = append(p.records, rec)
		}
	}, opts)
	return p
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
		p.asm.Packet(data, ci, linkType)
	}
}

func (p *pipeline) finish(sources []string, top int, withRecords bool) *report.Report {
	p.asm.Close()
	report.SortRecords(p.records)
	rep := &report.Report{
		Tool:        "tlscensus",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sources:     sources,
		Stats:       p.asm.Stats(),
		Summary:     p.acc.Summary(top),
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
	default:
		return report.WriteText(out, rep)
	}
}

func validateFormat(format string) error {
	switch format {
	case "text", "json", "ndjson":
		return nil
	}
	return fmt.Errorf("unknown output format %q (want text, json or ndjson)", format)
}
