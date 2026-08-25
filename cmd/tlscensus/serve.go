package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
	"github.com/connectedinformation/tlscensus/internal/report"
)

// The report names every host the captured traffic contacted. That is
// browsing-history-grade data, so the server is deliberately awkward to
// expose:
//
//   - it binds 127.0.0.1 only, never a routable address, and there is no
//     flag to change that;
//   - every request needs a token minted at startup and printed once;
//   - it is off unless asked for.
//
// Loopback alone is not an authorisation boundary — every local user can
// reach it — which is why the token exists as well.

const liveRefreshSeconds = 10

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	iface := fs.String("i", "", "capture live from this interface instead of reading files")
	port := fs.Int("port", 0, "loopback port (0 picks a free one)")
	top := fs.Int("top", 15, "entries per distribution")
	snaplen := fs.Int("snaplen", 65535, "bytes captured per packet")
	promisc := fs.Bool("promisc", false, "capture other hosts' traffic too")
	maxPrefix := fs.Int("max-prefix", assemble.DefaultMaxStreamPrefix, "bytes per stream direction")
	maxStreams := fs.Int("max-streams", assemble.DefaultMaxStreams, "concurrent connections tracked")
	noToken := fs.Bool("no-token", false, "serve without a token (only for a single-user machine)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	live := *iface != "" || len(files) == 0
	if live && len(files) > 0 {
		return fmt.Errorf("serve: give capture files or -i, not both")
	}

	opts := assemble.Options{MaxStreamPrefix: *maxPrefix, MaxStreams: *maxStreams}
	// Records are deliberately not retained. serve runs indefinitely on a
	// live interface, so keeping one per handshake grows without bound —
	// and every view it renders is built from aggregates anyway.
	p := newPipeline(opts, false, nil)

	var sources []string
	var src capture.Source
	if live {
		if !capture.LiveSupported() {
			return capture.ErrUnsupportedPlatform
		}
		var err error
		src, err = capture.OpenLive(*iface, capture.LiveOptions{
			Snaplen: *snaplen, Promiscuous: *promisc,
		})
		if err != nil {
			return err
		}
		defer src.Close()
		sources = []string{src.Name()}
	} else {
		sources = files
		for _, path := range files {
			f, err := capture.OpenFile(path)
			if err != nil {
				return err
			}
			err = p.run(f)
			f.Close()
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		p.asm.Close()
	}

	token := ""
	if !*noToken {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return fmt.Errorf("generating token: %w", err)
		}
		token = hex.EncodeToString(b[:])
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return fmt.Errorf("listening on loopback: %w", err)
	}
	defer ln.Close()

	refresh := 0
	if live {
		refresh = liveRefreshSeconds
	}

	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if token != "" {
				got := r.URL.Query().Get("t")
				// Constant-time, so a wrong token cannot be narrowed down by
				// timing even on a loopback socket.
				if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
					http.Error(w, "missing or invalid token", http.StatusForbidden)
					return
				}
			}
			// The page lists hostnames; keep it out of shared caches and
			// out of any referrer sent onward.
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
			h(w, r)
		}
	}

	mux.HandleFunc("/", authed(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		rep, records := p.snapshot(sources, *top)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if live {
			// Preserve the token across the meta refresh.
			report.WriteLiveHTML(w, rep, records, refresh)
			return
		}
		report.WriteHTML(w, rep, records)
	}))
	mux.HandleFunc("/report.json", authed(func(w http.ResponseWriter, r *http.Request) {
		rep, _ := p.snapshot(sources, *top)
		w.Header().Set("Content-Type", "application/json")
		report.WriteJSON(w, rep)
	}))
	mux.HandleFunc("/report.cbom.json", authed(func(w http.ResponseWriter, r *http.Request) {
		rep, records := p.snapshot(sources, *top)
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		report.WriteCBOM(w, rep, records)
	}))

	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	if token != "" {
		url += "?t=" + token
	}
	fmt.Fprintf(os.Stderr, "tlscensus: serving on %s\n", url)
	fmt.Fprintln(os.Stderr, "  loopback only; the token is required and is not written to disk")
	if live {
		fmt.Fprintf(os.Stderr, "  capturing on %s — press Ctrl-C to stop\n", src.Name())
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)

	if live {
		stopFlush := make(chan struct{})
		go func() {
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
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; src.Close() }()
		p.run(src)
		close(stopFlush)
		return nil
	}

	// Static analysis: nothing further will change, so just wait.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}
