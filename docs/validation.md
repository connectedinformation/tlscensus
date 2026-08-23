# Validation

What has been checked, and what has not. Kept honest deliberately: a parser
that is confidently wrong is worse than one with a known gap.

## Validated

**Round-trip against an independent encoder.** `internal/tlssynth` builds
handshakes from the RFC wire formats and does not import `internal/tlsparse`
— it defines its own codepoint constants. Tests therefore check the parser
against a separate reading of the specification rather than against itself.

**Fragmentation.** The post-quantum ClientHello in the test suite is over
1400 bytes and is parsed correctly at record chunk sizes of 1024, 512, 64 and
1 byte, and across TCP segments in the sample capture.

**Truncation.** Prefixes of a valid handshake are parsed without panic and
without invented fields.

**Fuzzing.** `FuzzParseStream` covers `FindClientHello`, `FindServerHello`,
the accessors and the registry lookups. Clean at 7.1M executions on the
initial corpus. Not yet running continuously.

## Not yet validated

### JA4 / JA4S — provisional

`internal/tlsparse/ja4.go` implements the published FoxIO specification, but
its output **has not been diffed against the reference implementation**. A
fingerprint that does not match everyone else's is worse than no fingerprint,
since it looks usable and correlates with nothing.

Two known incomplete details, marked at their sites in the source:

- The spec substitutes a hex encoding when the first or last byte of an ALPN
  value is not alphanumeric. Not implemented; such values pass through
  unchanged.
- DTLS should use the `d` protocol character. The record layer does not
  decode DTLS at all yet.

**To close this:** run both implementations over a shared pcap corpus and
record the diff here.

### Differential testing against tshark — not started

The intended M1 gate. `tshark -T ek` extracts nearly the same field set from
the same bytes and is heavily battle-tested; a disagreement is almost always
a bug here. Zeek's `ssl.log` is a useful second opinion.

This wants a corpus of real handshakes — captured locally, never committed —
covering at minimum: a post-quantum handshake, HelloRetryRequest, session
resumption, ECH, a TLS 1.2 chain with multiple intermediates, and a
non-browser client such as curl, OpenSSL `s_client` and a Java runtime.

### Registry completeness — partial

`internal/tlsparse/registry.go` names the cipher suites, groups and signature
algorithms that a modern inventory encounters, plus the obsolete ones worth
flagging by name. It is not the full IANA registry. Unknown codepoints are
reported in hex and counted as unknown rather than silently dropped, so the
failure mode is visible — but a suite that should have been flagged and is
merely unnamed is still a miss.

Post-quantum codepoints in particular are moving. `MLKEM512/768/1024`,
`SecP256r1MLKEM768`, `X25519MLKEM768`, `SecP384r1MLKEM1024` and the two
Kyber draft groups are present; anything newer is not.
