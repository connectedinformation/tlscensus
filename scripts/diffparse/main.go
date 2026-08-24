// Command diffparse compares tlscensus's handshake decoding against
// tshark's on the same capture.
//
// Everything is compared as raw codepoints, never as names. Mapping
// tshark's numbers through tlscensus's own registry would make the oracle
// agree with the code under test by construction — the same defect that let
// a wrong bh_hdrlen through, one layer up. GREASE is likewise stripped from
// the tshark side by a predicate written here from RFC 8701, not imported.
//
// Usage: diffparse TSHARK_JSON TLSCENSUS_PCAP
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/tlscensus/tlscensus/internal/assemble"
	"github.com/tlscensus/tlscensus/internal/capture"
)

// isGREASE is RFC 8701, written out independently of internal/tlsparse.
func isGREASE(v uint16) bool { return byte(v>>8) == byte(v) && v&0x0f == 0x0a }

// --- tshark side ------------------------------------------------------

type tsharkPacket struct {
	Source struct {
		Layers json.RawMessage `json:"layers"`
	} `json:"_source"`
}

// tshark's -e extraction flattens a field across the whole packet, and
// several extensions carry values under the same field name. In particular
// tls.handshake.sig_hash_alg appears in signature_algorithms (13),
// signature_algorithms_cert (50) and delegated_credentials (34), so -e
// returns their concatenation and any comparison against a single
// extension fails. The full dissection tree keeps them nested, so fields
// that need it are read scoped to their extension.

// strs decodes an -e extracted field: an array of strings, or occasionally a
// bare string. Order within the array is wire order, which is why -e is
// preferred wherever the field name is unambiguous.
func strs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

// walk visits every JSON object in the tree.
//
// Sibling objects are visited in Go's randomised map order, so anything
// collected across siblings is unordered. Each KeyShareEntry is its own
// object, so reading key shares this way returns them in a different order
// every run — which is exactly how this harness reported two phantom
// mismatches against a parser that was right. Order-sensitive fields come
// from -e instead; the tree is used only where a field name is ambiguous
// across extensions and must be scoped.
func walk(node any, fn func(map[string]any)) {
	switch n := node.(type) {
	case map[string]any:
		fn(n)
		for _, v := range n {
			walk(v, fn)
		}
	case []any:
		for _, v := range n {
			walk(v, fn)
		}
	}
}

// collect gathers every value of key anywhere beneath node. Values may be a
// bare string or an array of them.
func collect(node any, key string) []string {
	var out []string
	walk(node, func(obj map[string]any) {
		v, ok := obj[key]
		if !ok {
			return
		}
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	})
	return out
}

// extension returns the subtree of the TLS extension with the given type
// number, or nil if the handshake does not carry it.
func extension(node any, typ string) any {
	var found any
	walk(node, func(obj map[string]any) {
		if found != nil {
			return
		}
		if v, ok := obj["tls.handshake.extension.type"]; ok {
			if s, ok := v.(string); ok && s == typ {
				found = obj
			}
		}
	})
	return found
}

func toU16(vals []string, dropGREASE bool) []uint16 {
	var out []uint16
	for _, s := range vals {
		v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
		if err != nil {
			continue
		}
		u := uint16(v)
		if dropGREASE && isGREASE(u) {
			continue
		}
		out = append(out, u)
	}
	return out
}

// hello is one ClientHello as either tool saw it.
type hello struct {
	Port      uint16
	SNI       string
	Ciphers   []uint16
	Groups    []uint16
	KeyShares []uint16
	SigAlgs   []uint16
	ALPN      []string
	JA4       string
}

type tsharkFields struct {
	Source struct {
		Layers map[string]json.RawMessage `json:"layers"`
	} `json:"_source"`
}

// readTsharkFields reads the -e extraction, which preserves wire order.
func readTsharkFields(path string) (map[uint16]*hello, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var packets []tsharkFields
	if err := json.NewDecoder(f).Decode(&packets); err != nil {
		return nil, fmt.Errorf("decoding tshark fields json: %w", err)
	}

	out := map[uint16]*hello{}
	for _, p := range packets {
		l := p.Source.Layers
		// QUIC handshakes arrive over UDP, so the join key comes from
		// whichever transport carried them.
		ports := strs(l["tcp.srcport"])
		if len(ports) == 0 {
			ports = strs(l["udp.srcport"])
		}
		if len(ports) == 0 {
			continue
		}
		port64, err := strconv.ParseUint(ports[0], 10, 16)
		if err != nil {
			continue
		}
		port := uint16(port64)
		// A retried handshake produces a second ClientHello on the same
		// connection; keep the first, as tlscensus does.
		if _, seen := out[port]; seen {
			continue
		}
		h := &hello{Port: port}
		if sni := strs(l["tls.handshake.extensions_server_name"]); len(sni) > 0 {
			h.SNI = sni[0]
		}
		h.Ciphers = toU16(strs(l["tls.handshake.ciphersuite"]), true)
		h.Groups = toU16(strs(l["tls.handshake.extensions_supported_group"]), true)
		h.KeyShares = toU16(strs(l["tls.handshake.extensions_key_share_group"]), true)
		h.ALPN = strs(l["tls.handshake.extensions_alpn_str"])
		if ja4 := strs(l["tls.handshake.ja4"]); len(ja4) > 0 {
			h.JA4 = ja4[0]
		}
		out[port] = h
	}
	return out, nil
}

type tsharkTree struct {
	Source struct {
		Layers json.RawMessage `json:"layers"`
	} `json:"_source"`
}

// addScopedSigAlgs fills in signature_algorithms from the full dissection
// tree, scoped to extension 13.
//
// -e cannot do this: tls.handshake.sig_hash_alg is emitted by
// signature_algorithms (13), signature_algorithms_cert (50) and
// delegated_credentials (34) alike, so -e returns their concatenation. A
// Chrome ClientHello carries both 13 and 34, and comparing against the union
// reported a mismatch against a correct parse.
func addScopedSigAlgs(path string, hellos map[uint16]*hello) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var packets []tsharkTree
	if err := json.NewDecoder(f).Decode(&packets); err != nil {
		return fmt.Errorf("decoding tshark tree json: %w", err)
	}

	seen := map[uint16]bool{}
	for _, p := range packets {
		var layers any
		if err := json.Unmarshal(p.Source.Layers, &layers); err != nil {
			continue
		}
		ports := collect(layers, "tcp.srcport")
		if len(ports) == 0 {
			ports = collect(layers, "udp.srcport")
		}
		if len(ports) == 0 {
			continue
		}
		port64, err := strconv.ParseUint(ports[0], 10, 16)
		if err != nil {
			continue
		}
		port := uint16(port64)
		if seen[port] {
			continue
		}
		seen[port] = true
		h, ok := hellos[port]
		if !ok {
			continue
		}
		if ext := extension(layers, "13"); ext != nil {
			h.SigAlgs = toU16(collect(ext, "tls.handshake.sig_hash_alg"), true)
		}
	}
	return nil
}

// --- tlscensus side ---------------------------------------------------

func readOurs(path string) (map[uint16]*hello, error) {
	out := map[uint16]*hello{}
	asm := assemble.New(func(f *assemble.Flow) {
		ch := f.Client
		if ch == nil {
			return
		}
		if _, seen := out[f.ClientPort]; seen {
			return
		}
		out[f.ClientPort] = &hello{
			Port:      f.ClientPort,
			SNI:       ch.ServerName,
			Ciphers:   ch.CipherSuites,
			Groups:    ch.SupportedGroups,
			KeyShares: ch.KeyShareGroups,
			SigAlgs:   ch.SignatureAlgorithms,
			ALPN:      ch.ALPN,
			JA4:       ch.JA4(),
		}
	}, assemble.Options{})

	src, err := capture.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		asm.Packet(data, ci, src.LinkType())
	}
	asm.Close()
	return out, nil
}

// --- comparison -------------------------------------------------------

type report struct {
	checks, mismatches int
}

func (r *report) cmpU16(port uint16, field string, ours, theirs []uint16, ordered bool) {
	r.checks++
	a, b := append([]uint16(nil), ours...), append([]uint16(nil), theirs...)
	if !ordered {
		sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
		sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	}
	if fmt.Sprint(a) == fmt.Sprint(b) {
		return
	}
	r.mismatches++
	fmt.Printf("  MISMATCH port %d %s\n    tlscensus: %s\n    tshark:    %s\n",
		port, field, hexList(ours), hexList(theirs))
}

func (r *report) cmpStr(port uint16, field, ours, theirs string) {
	r.checks++
	if ours == theirs {
		return
	}
	r.mismatches++
	fmt.Printf("  MISMATCH port %d %s\n    tlscensus: %q\n    tshark:    %q\n",
		port, field, ours, theirs)
}

func hexList(vs []uint16) string {
	if len(vs) == 0 {
		return "[]"
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("0x%04x", v)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: diffparse TSHARK_FIELDS_JSON TSHARK_TREE_JSON PCAP")
		os.Exit(2)
	}

	theirs, err := readTsharkFields(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "diffparse:", err)
		os.Exit(1)
	}
	if err := addScopedSigAlgs(os.Args[2], theirs); err != nil {
		fmt.Fprintln(os.Stderr, "diffparse:", err)
		os.Exit(1)
	}
	ours, err := readOurs(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "diffparse:", err)
		os.Exit(1)
	}

	var r report
	var ja4Compared, ja4Agreed int

	ports := make([]uint16, 0, len(theirs))
	for p := range theirs {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })

	// A ClientHello tshark found and tlscensus did not is the most serious
	// possible result: it is a handshake missing from the inventory.
	for _, p := range ports {
		t := theirs[p]
		o, found := ours[p]
		if !found {
			r.checks++
			r.mismatches++
			fmt.Printf("  MISSING port %d (%s) — tshark decoded a ClientHello that tlscensus did not report\n",
				p, t.SNI)
			continue
		}
		r.cmpStr(p, "sni", o.SNI, t.SNI)
		r.cmpU16(p, "cipher_suites", o.Ciphers, t.Ciphers, true)
		r.cmpU16(p, "supported_groups", o.Groups, t.Groups, true)
		r.cmpU16(p, "key_share_groups", o.KeyShares, t.KeyShares, true)
		r.cmpU16(p, "signature_algorithms", o.SigAlgs, t.SigAlgs, true)
		r.cmpStr(p, "alpn", strings.Join(o.ALPN, ","), strings.Join(t.ALPN, ","))

		if t.JA4 != "" {
			ja4Compared++
			if o.JA4 == t.JA4 {
				ja4Agreed++
			} else {
				fmt.Printf("  JA4 DIFFERS port %d\n    tlscensus: %s\n    tshark:    %s\n", p, o.JA4, t.JA4)
			}
		}
	}

	for p, o := range ours {
		if _, found := theirs[p]; !found {
			fmt.Printf("  EXTRA port %d (%s) — tlscensus reported a ClientHello tshark did not\n", p, o.SNI)
			r.checks++
			r.mismatches++
		}
	}

	fmt.Printf("  %d flows, %d field checks, %d mismatches\n",
		len(theirs), r.checks, r.mismatches)
	if ja4Compared > 0 {
		fmt.Printf("  JA4: %d/%d agree with the reference implementation\n", ja4Agreed, ja4Compared)
	} else {
		fmt.Println("  JA4: not compared (this tshark build does not emit tls.handshake.ja4)")
	}
	if r.mismatches > 0 {
		os.Exit(1)
	}
}
