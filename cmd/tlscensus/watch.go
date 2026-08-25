package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
	"github.com/connectedinformation/tlscensus/internal/inventory"
	"github.com/connectedinformation/tlscensus/internal/report"
)

// flushInterval is how often idle streams are swept during live capture.
// Without it, a handshake that completed on a quiet interface would wait for
// the next packet from anyone before being reported.
const flushInterval = time.Second

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var format string
	fs.StringVar(&format, "o", "text", "output format")
	fs.StringVar(&format, "output", "text", "output format")
	iface := fs.String("i", "", "interface to capture on")
	top := fs.Int("top", 15, "entries per distribution")
	snaplen := fs.Int("snaplen", 65535, "bytes captured per packet")
	promisc := fs.Bool("promisc", false, "capture other hosts' traffic too")
	noFilter := fs.Bool("no-filter", false, "skip the kernel BPF filter")
	maxPrefix := fs.Int("max-prefix", assemble.DefaultMaxStreamPrefix, "bytes per stream direction")
	maxStreams := fs.Int("max-streams", assemble.DefaultMaxStreams, "concurrent connections tracked")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateFormat(format); err != nil {
		return err
	}
	if !capture.LiveSupported() {
		return capture.ErrUnsupportedPlatform
	}

	src, err := capture.OpenLive(*iface, capture.LiveOptions{
		Snaplen:     *snaplen,
		Promiscuous: *promisc,
		NoFilter:    *noFilter,
	})
	if err != nil {
		return err
	}
	defer src.Close()

	// Streaming writers must be serialised against the final report, since
	// flows complete on the capture goroutine while the ticker and the
	// signal handler run elsewhere.
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)

	var onRecord func(*inventory.Record)
	switch format {
	case "ndjson":
		onRecord = func(r *inventory.Record) {
			mu.Lock()
			defer mu.Unlock()
			enc.Encode(r)
		}
	case "text":
		onRecord = func(r *inventory.Record) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Println(report.FlowLine(r))
		}
	}

	p := newPipeline(assemble.Options{
		MaxStreamPrefix: *maxPrefix,
		MaxStreams:      *maxStreams,
	}, format != "ndjson", onRecord)

	if format == "text" {
		fmt.Fprintf(os.Stderr, "tlscensus: capturing on %s", src.Name())
		if *promisc {
			fmt.Fprint(os.Stderr, " (promiscuous)")
		}
		fmt.Fprintln(os.Stderr, " — press Ctrl-C to stop")
	}

	// Sweep idle streams on a timer. The sweep is serialised against the
	// capture goroutine inside the pipeline, which also defers delivery
	// until it has released the assembler lock — so the writers below can
	// take mu without deadlocking against the flush that produced them.
	stopFlush := make(chan struct{})
	var flushWG sync.WaitGroup
	flushWG.Add(1)
	go func() {
		defer flushWG.Done()
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-stopFlush:
				return
			case now := <-t.C:
				p.flushOlderThan(now.Add(-assemble.DefaultCloseTimeout))
			}
		}
	}()

	// stopping distinguishes the read error caused by our own shutdown from
	// a genuine capture failure. Closing the source is how the blocking read
	// is unblocked, so run always returns "use of closed file" on Ctrl-C —
	// reporting that as an error would end every successful capture with a
	// failure message and a non-zero exit.
	var stopping atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		stopping.Store(true)
		// Closing the source unblocks the capture read; run then returns.
		src.Close()
	}()

	runErr := p.run(src)
	if stopping.Load() {
		runErr = nil
	}

	close(stopFlush)
	flushWG.Wait()
	signal.Stop(sig)

	// The capture loop has returned and the sweeper has stopped, so this
	// is the only goroutine left; finish streams any remaining flows
	// through onRecord before the summary is built.
	rep := p.finish([]string{src.Name()}, *top, false)

	warnIfIncomplete(rep.Stats)

	// NDJSON already streamed every record; printing a summary after it
	// would corrupt the stream for anything parsing line by line.
	if format != "ndjson" {
		fmt.Println()
		if err := writeReport(format, rep, p.records); err != nil {
			return err
		}
	}
	return runErr
}

func runInterfaces(args []string) error {
	fs := flag.NewFlagSet("interfaces", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ifs, err := capture.Interfaces()
	if err != nil {
		return err
	}
	def, _ := capture.DefaultInterface()

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tADDRESSES")
	for _, i := range ifs {
		state := "down"
		if i.Up {
			state = "up"
		}
		if i.Loopback {
			state += ",loopback"
		}
		name := i.Name
		if i.Name == def {
			name += " *"
		}
		addrs := "-"
		if len(i.Addresses) > 0 {
			addrs = fmt.Sprint(i.Addresses)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, state, addrs)
	}
	tw.Flush()
	if def != "" {
		fmt.Printf("\n* default for `tlscensus watch` when -i is not given\n")
	}
	if !capture.LiveSupported() {
		fmt.Fprintln(os.Stderr, "\nNote: live capture is not supported on this platform; "+
			"`tlscensus read` works everywhere.")
	}
	return nil
}
