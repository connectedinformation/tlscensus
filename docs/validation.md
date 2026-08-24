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

### Live capture — verified on macOS and Linux

`watch` has been run against a real interface on both platforms and reports
live handshakes correctly: SNI, negotiated version, cipher suite and key
exchange group.

On macOS (Darwin arm64, `/dev/bpf`, en0), three of the four post-quantum
states were observed on real traffic — `post_quantum` (a browser offering
X25519MLKEM768 and having it selected), `offered_not_selected` (a client
offering a PQ key share to a server that chose x25519), and `classical`. The
PQ ClientHello exceeded one TCP segment on the wire and was reassembled
correctly.

On Linux (AF_PACKET via `pcapgo.EthernetHandle`), capture was verified and
four further defects were found and fixed; see below.

`advertised_only` has still not been observed on real traffic. It is covered
by the synthetic capture, but no live client has yet been seen advertising a
post-quantum group without sending a key share for it.

## The gap CI cannot close

Eight defects have now reached a green CI run and been caught only by
running against a real interface. That is the strongest evidence in this
repository for what the automated suite does and does not cover.

### Found on macOS

1. `IoctlSetInt` passes its argument by value (the Linux convention), while
   BSD `_IOW`/`_IOWR` ioctls take a pointer. `BIOCSBLEN` therefore returned
   EFAULT.
2. The minimum `bh_hdrlen` was checked against `sizeof(struct bpf_hdr)` (20)
   rather than the unpadded field size (18) that the kernel actually writes.
   Every packet was rejected as malformed, silently, because the recovery
   path discards the read buffer and keeps reading.
3. `Stream.Accept` returned false once the handshake was understood.
   reassembly consults `Accept` before handling FIN and RST, so the close
   was refused too: the connection never completed, and the flow was
   released only by the idle sweep minutes later while holding a
   `MaxStreams` slot. Offline this is invisible, because `Close` flushes
   everything at end of file.

### Found on Linux

4. The pipeline drove `assemble.Assembler` — documented as not safe for
   concurrent use — from both the capture loop and the idle-sweep ticker.
   The lock covered the sweep and the output writers but not `Packet`.
5. gopacket queues out-of-order segments without limit by default
   (`MaxBufferedPagesPerConnection` and `MaxBufferedPagesTotal` are zero).
   Offline a gap is always filled or the file ends. Live, a kernel buffer
   overrun drops a segment the receiver already acked, so it is never
   retransmitted and the capture-side gap is permanent: every later segment
   of that connection queues until the idle sweep.
6. With connections completing on FIN (fix 3), the final ACK of the
   four-way close arrives for a connection the pool has already removed,
   registering a phantom stream that holds a `MaxStreams` slot.
7. `pcapgo.NewEthernetHandle` formats its errno with `%s` rather than `%w`,
   so `errors.Is(err, os.ErrPermission)` never matched and no unprivileged
   Linux user ever saw the `setcap` hint — dead code from the day it was
   written.
8. Ctrl-C reported the shutdown-induced read error as a capture failure,
   ending every successful run with an error message and a non-zero exit.

### What the pattern says

Three of these — 2, 5 and 6 — could not have been caught by any test in this
repository, because they depend on conditions a capture file cannot express:
a header the kernel writes, a gap that is never filled, a packet that
arrives after the connection is gone.

Two others are worse, because a check existed and agreed with the bug:

- The `bpf_hdr` unit test built its records with `bh_hdrlen` defaulting to
  the same constant the parser validated against, so **the oracle inherited
  the defect**. This is the hazard `CONTRIBUTING.md` describes for keeping
  `tlssynth` independent of `tlsparse`, reproduced one package over. The
  test now asserts 18, 20 and 24 explicitly rather than deriving from the
  constant.
- The CI `testdata` job regenerated the sample captures before running the
  tests, so it passed against a file the repository did not contain
  (`concurrent.pcap`, excluded by a `.gitignore` pattern). It now asserts
  that generated captures are tracked.

The lesson is not "write more tests". Every one of these packages was
tested and every test passed. It is that the pure-function boundary makes
parsing free to verify and leaves everything holding a file descriptor
unverified — and that a test sharing an assumption with the code under test
verifies nothing at all.

### Manual smoke test (required before tagging a release)

CI has no network interface and no privileges, so this cannot be automated
here — and the eight defects above are what that gap costs when the step is
skipped. Run it on **each** platform that claims live capture; six of the
eight were platform-specific, and the two that were not still presented
differently on each.

```sh
sudo ./tlscensus watch -i <iface>
# in another shell: curl https://cloudflare.com/ >/dev/null
# then Ctrl-C
```

Check that:

- handshake lines appear within a second or two of the traffic. Minutes
  later means connection close is not being processed (defects 3 and 6).
- the summary reports a non-zero packet count. Zero means packets are being
  captured and discarded, or never captured at all (defect 2).
- a modern browser produces at least one `post_quantum` flow, which also
  exercises reassembly of a ClientHello larger than one segment.
- Ctrl-C exits cleanly, with a summary and status 0 (defect 8).
- running **without** privileges prints the platform's permission hint
  rather than a bare errno (defect 7).

If nothing appears at all, re-run with `-no-filter` to separate a
kernel-filter fault from a read-path fault. Run under `-race` if anything
about the output looks non-deterministic (defect 4).

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
