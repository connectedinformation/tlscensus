// Command tlscensus takes an inventory of the TLS cryptography in use on a
// network, passively.
//
// It never terminates, proxies, decrypts or modifies a connection: it reads
// handshakes as they go past and reports what was negotiated.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

// version is set at build time with -ldflags "-X main.version=..." for
// release builds. It is empty otherwise, and resolved from the build info
// the toolchain embeds.
var version = ""

func init() {
	if version == "" {
		version = resolveVersion()
	}
}

// resolveVersion recovers a useful version for a binary built without
// release ldflags.
//
// `go install github.com/tlscensus/tlscensus/cmd/tlscensus@v0.1.0` applies
// no ldflags, so without this every such build reports "dev" — and a bug
// report saying "tlscensus dev" identifies nothing. The module version is
// embedded by the toolchain and says exactly what was installed; a build
// straight from a checkout falls back to the commit, marked dirty when the
// tree had uncommitted changes.
func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		return "dev-" + revision + "-dirty"
	}
	return "dev-" + revision
}

const usage = `tlscensus — passive TLS cryptography inventory

Usage:
  tlscensus read [flags] FILE...   read pcap/pcapng capture files
  tlscensus watch [flags]          capture live from an interface
  tlscensus serve [flags] [FILE...]  serve a report on loopback
  tlscensus interfaces             list capturable interfaces
  tlscensus version

Common flags:
  -o, -output FORMAT   text, json, ndjson, cbom or html (default text)
  -top N               entries per distribution (default 15)
  -max-prefix BYTES    bytes retained per stream direction (default 32768)
  -max-streams N       concurrently tracked connections (default 8192)

read flags:
  -records             include per-flow records in json output

watch flags:
  -i IFACE             interface to capture on (default: first non-loopback)
  -snaplen BYTES       bytes captured per packet (default 65535)
  -promisc             capture other hosts' traffic too (default off)
  -no-filter           skip the kernel BPF filter

Examples:
  tlscensus read capture.pcap
  tlscensus read -o ndjson capture.pcapng | jq 'select(.pq_status=="classical")'
  sudo tlscensus watch -i en0
  sudo tlscensus watch -o ndjson | tee handshakes.ndjson
  tlscensus read -o html capture.pcap > report.html
  tlscensus read -o cbom capture.pcap > crypto.cdx.json
  tlscensus serve capture.pcap
  sudo tlscensus serve -i en0
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "read":
		err = runRead(os.Args[2:])
	case "watch":
		err = runWatch(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "interfaces":
		err = runInterfaces(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tlscensus %s\n", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "tlscensus: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "tlscensus: %v\n", err)
		os.Exit(1)
	}
}
