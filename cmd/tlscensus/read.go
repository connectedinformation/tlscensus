package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
)

func runRead(args []string) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var format string
	fs.StringVar(&format, "o", "text", "output format")
	fs.StringVar(&format, "output", "text", "output format")
	top := fs.Int("top", 15, "entries per distribution")
	withRecords := fs.Bool("records", false, "include per-flow records in json output")
	maxPrefix := fs.Int("max-prefix", assemble.DefaultMaxStreamPrefix, "bytes per stream direction")
	maxStreams := fs.Int("max-streams", assemble.DefaultMaxStreams, "concurrent connections tracked")

	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return errors.New("read: no capture files given")
	}
	if err := validateFormat(format); err != nil {
		return err
	}

	p := newPipeline(assemble.Options{
		MaxStreamPrefix: *maxPrefix,
		MaxStreams:      *maxStreams,
	}, true, nil)

	for _, path := range files {
		src, err := capture.OpenFile(path)
		if err != nil {
			return err
		}
		err = p.run(src)
		src.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}

	rep := p.finish(files, *top, *withRecords)
	warnIfIncomplete(rep.Stats)
	return writeReport(format, rep, p.records)
}
