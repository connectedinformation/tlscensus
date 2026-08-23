package tlsparse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 and JA4S fingerprints, per the specification published by FoxIO at
// https://github.com/FoxIO-LLC/ja4 (JA4 itself is BSD-3-Clause licensed;
// note that other members of the JA4+ family are not).
//
// A fingerprint identifies the TLS implementation and its configuration —
// which library, roughly which version, which build flags — without needing
// process attribution. On a host where attribution is unavailable it is the
// closest available answer to "what software made this connection".
//
// !! NOT YET VALIDATED AGAINST THE REFERENCE IMPLEMENTATION.
//
// The encoding below follows the published spec, but the values it produces
// have not been diffed against FoxIO's reference output on a real corpus.
// Fingerprints are only useful if they match everyone else's, so treat
// these as provisional until docs/validation.md records a clean run. Two
// details are known to be incompletely handled and are marked at their
// sites: non-alphanumeric ALPN bytes, and DTLS.

// JA4 returns the JA4 client fingerprint, in the form
// "t13d1516h2_8daaf6152771_b186095e22b6".
func (ch *ClientHello) JA4() string {
	return strings.Join([]string{ch.ja4a(), ch.ja4b(), ch.ja4c()}, "_")
}

func (ch *ClientHello) ja4a() string {
	proto := "t"
	if ch.QUIC {
		proto = "q"
	}
	// TODO: DTLS uses "d" and is distinguished at the record layer, which
	// this parser does not yet decode.

	sni := "i" // connection made to a bare IP address
	if ch.ServerName != "" {
		sni = "d"
	}

	// SNI and ALPN are counted here even though ja4c excludes them from the
	// hashed list.
	return fmt.Sprintf("%s%s%s%02d%02d%s",
		proto,
		ja4Version(ch.NegotiatedVersion()),
		sni,
		cap99(len(ch.CipherSuites)),
		cap99(len(ch.Extensions)),
		ja4ALPN(ch.ALPN),
	)
}

// ja4b hashes the cipher suite list, sorted. Sorting is what makes the
// fingerprint stable against implementations that shuffle their preference
// order between connections.
func (ch *ClientHello) ja4b() string {
	return truncHash(joinHexSorted(ch.CipherSuites))
}

// ja4c hashes the extension list (sorted, with SNI and ALPN removed) joined
// to the signature algorithm list (in original order — the order is itself
// characteristic of the implementation).
func (ch *ClientHello) ja4c() string {
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if e == ExtServerName || e == ExtALPN {
			continue
		}
		exts = append(exts, e)
	}
	s := joinHexSorted(exts)
	if len(ch.SignatureAlgorithms) > 0 {
		s += "_" + joinHex(ch.SignatureAlgorithms)
	}
	return truncHash(s)
}

// JA4S returns the JA4S server fingerprint, in the form
// "t130200_1301_a56c5b993250".
func (sh *ServerHello) JA4S(quic bool) string {
	proto := "t"
	if quic {
		proto = "q"
	}
	a := fmt.Sprintf("%s%s%02d%s",
		proto,
		ja4Version(sh.NegotiatedVersion()),
		cap99(len(sh.Extensions)),
		ja4ALPNOne(sh.SelectedALPN),
	)
	b := fmt.Sprintf("%04x", sh.CipherSuite)
	// Server extensions are hashed in wire order, not sorted.
	c := truncHash(joinHex(sh.Extensions))
	return a + "_" + b + "_" + c
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 {
		return "00"
	}
	return ja4ALPNOne(alpn[0])
}

// ja4ALPNOne encodes the first and last byte of an ALPN value: "h2" stays
// "h2", "http/1.1" becomes "h1".
func ja4ALPNOne(v string) string {
	if v == "" {
		return "00"
	}
	first, last := v[0], v[len(v)-1]
	// TODO: the spec substitutes a hex encoding when either byte is not
	// alphanumeric. Until that is validated, such values are passed through
	// as-is, which is wrong but at least visibly so.
	return string([]byte{first, last})
}

func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func joinHex(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func joinHexSorted(vs []uint16) string {
	sorted := make([]uint16, len(vs))
	copy(sorted, vs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return joinHex(sorted)
}

// truncHash is the JA4 hash: the first 12 hex characters of the SHA-256 of
// the input. An empty input hashes to all zeroes rather than to the hash of
// the empty string, so that "no ciphers offered" is visibly distinct.
func truncHash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
