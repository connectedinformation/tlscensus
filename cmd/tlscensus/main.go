// Command tlscensus takes an inventory of the TLS cryptography in use on a
// network, passively.
//
// M1 reads capture files. Live capture arrives in M2; see docs/roadmap.md.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/capture"
	"github.com/tlscensus/tlscensus/internal/inventory"
	"github.com/tlscensus/tlscensus/internal/report"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `tlscensus — passive TLS cryptography inventory

Usage:
  tlscensus read [flags] FILE...    read pcap/pcapng capture files
  tlscensus version

Flags for read:
  -o, -output FORMAT   text, json or ndjson (default text)
  -top N               entries per distribution in text/json output (default 15)
  -records             include per-flow records in json output
  -max-prefix BYTES    bytes retained per stream direction (default 32768)

Examples:
  tlscensus read capture.pcap
  tlscensus read -o ndjson capture.pcapng | jq 'select(.pq_status=="classical")'
  tlscensus read -o json -records *.pcap > inventory.json
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "read":
		if err := runRead(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "tlscensus: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("tlscensus %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "tlscensus: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runRead(args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var format string
	fs.StringVar(&format, "o", "text", "output format: text, json, ndjson")
	fs.StringVar(&format, "output", "text", "output format: text, json, ndjson")
	top := fs.Int("top", 15, "entries per distribution")
	withRecords := fs.Bool("records", false, "include per-flow records in json output")
	maxPrefix := fs.Int("max-prefix", assemble.DefaultMaxStreamPrefix,
		"bytes retained per stream direction")

	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return errors.New("read: no capture files given")
	}
	switch format {
	case "text", "json", "ndjson":
	default:
		return fmt.Errorf("unknown output format %q", format)
	}

	var records []*inventory.Record
	acc := inventory.NewAccumulator()

	asm := assemble.New(func(f *assemble.Flow) {
		rec := inventory.Analyze(f)
		acc.Add(rec)
		// NDJSON is the streaming format, but holding records is what lets
		// text and json sort by severity. Capture files are bounded, so
		// this is affordable; live capture will stream instead.
		records = append(records, rec)
	}, assemble.Options{MaxStreamPrefix: *maxPrefix})

	for _, path := range files {
		if err := readFile(asm, path); err != nil {
			return err
		}
	}
	asm.Close()

	report.SortRecords(records)
	rep := &report.Report{
		Tool:        "tlscensus",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Sources:     files,
		Stats:       asm.Stats(),
		Summary:     acc.Summary(*top),
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	switch format {
	case "ndjson":
		return report.WriteNDJSON(out, records)
	case "json":
		if *withRecords {
			rep.Records = records
		}
		return report.WriteJSON(out, rep)
	default:
		return report.WriteText(out, rep)
	}
}

func readFile(asm *assemble.Assembler, path string) error {
	src, err := capture.OpenFile(path)
	if err != nil {
		return err
	}
	defer src.Close()

	linkType := src.LinkType()
	for {
		data, ci, err := src.Next()
		if err != nil {
			if capture.Done(err) || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		asm.Packet(data, ci, linkType)
	}
}
