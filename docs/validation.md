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

### Live capture — verified on macOS, Linux and Windows

`watch` has been run against a real interface on all three platforms and reports
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

On Windows (Npcap 1.88 via runtime `wpcap.dll` loading, Intel Wireless-AC
9560), capture was verified: 421 packets, four TLS 1.3 flows, all four
negotiating X25519MLKEM768, with JA4 computed and the summary printed after
a real Ctrl-C exited 0. The `pcap_pkthdr` layout is confirmed on hardware
rather than only asserted — capture lengths land within the snaplen and
timestamps match the wall clock, which is what a mis-sized LLP64 `timeval`
would have destroyed.

Twelve defects were found first, eleven by code review before the driver was
ever installed and one by installing it; see below. Npcap also settled two
assumptions that could not be checked without it: `PCAP_IF_UP` **is** set on
`pcap_findalldevs` results, and both `pcap_setbuff` and `pcap_setmintocopy`
resolve, so `BufferBytes` is not inert.

`advertised_only` has still not been observed on real traffic. It is covered
by the synthetic capture, but no live client has yet been seen advertising a
post-quantum group without sending a key share for it.

## The gap CI cannot close

Nine defects have now reached a green CI run and been caught only by
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

### Found on Windows

Windows is the one platform where review preceded the hardware, so the two
are listed apart — the split is the point.

Eleven came out of a code review of the unverified commit, with no driver
installed. The one that mattered most was a use-after-free: `Close` ran
`pcap_close` from the signal goroutine while the capture goroutine sat
inside `pcap_next_ex`, and a `pcap_t` — unlike the POSIX file descriptor the
darwin path closes under a read — is freed along with the buffer the read is
filling. Ctrl-C was an access violation, not a stop. The rest: `errClosed`
returned where every caller keys on `io.EOF`; a missing DLL reported as
`permission denied`, sending a user with no Npcap after an elevated prompt;
first-wins `-i` matching that resolved `Ethernet` to `Ethernet 2`; a default
that fell back to `devs[0]`; no fallback when the NPF service is stopped; a
device-name buffer not kept alive across `pcap_open_live`; an unvalidated
`caplen` feeding `make`; `wpcap.dll` loaded by bare name, so a DLL beside
the executable would win in an elevated process; a required-but-unused
`pcap_lib_version`; and `BufferBytes` silently ignored.

9. Installing the driver found the twelfth, which no amount of reading had
   suggested. `pcap_findalldevs` lists a Bluetooth PAN adapter, two Wi-Fi
   Direct virtual adapters and an unplugged Ethernet port **ahead** of the
   Wi-Fi adapter carrying the traffic. Every one of them reports itself up
   and holds a 169.254 autoconfiguration address and an `fe80::` link-local
   one, so "first that is up, not loopback, and has an address" — the rule
   all three platforms shared — selected Bluetooth. The capture ran, exited
   cleanly, and reported nothing, which is the failure mode that looks most
   like success. The rule is now "has a *routable* address", in the shared
   `DefaultInterface` as well as the Windows path.

The eleven are not evidence that review substitutes for hardware. Nine of
them were reachable by reading because they are contradictions inside the
source — a flag read from two goroutines, an error value the callers do not
match on, a documented option never passed to the driver. Number 9 was not:
nothing in the code says what order a driver enumerates adapters in, or that
a Bluetooth radio would claim to be up. That had to be run.

### Found by using it

9. Observations were reported when a connection closed, not when its
   handshake completed. Under TLS 1.3 nothing after the ServerHello is
   visible, so the wait bought nothing — but a browser holds connections
   open for minutes, so a live capture showed nothing for a site the
   operator had just visited, and a connection outliving the capture never
   appeared at all. Reading a capture file cannot show this: every
   synthetic connection ends, and `Close` flushes the rest at end of file.
   Fixed by reporting once the server's cleartext flight is complete —
   ServerHello under TLS 1.3, ServerHelloDone under TLS 1.2 — and covered
   by `testdata/keepalive.pcap`, which holds completed handshakes on
   connections that are never closed.

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
here — and the nine defects above are what that gap costs when the step is
skipped. Run it on **each** platform that claims live capture; seven of the
nine were platform-specific, and the two that were not still presented
differently on each.

```sh
sudo ./tlscensus watch -i <iface>
# in another shell: curl https://cloudflare.com/ >/dev/null
# then Ctrl-C
```

On Windows, Npcap grants access without elevation unless it was installed
with "Restrict Npcap driver's access to Administrators only", so an ordinary
PowerShell prompt is usually enough:

```powershell
.	lscensus.exe interfaces
.	lscensus.exe watch -i "<adapter description>"
# in another shell: curl.exe https://cloudflare.com/ -o NUL
# then Ctrl-C
```

`go test ./internal/capture/` additionally runs the live-handle tests there
whenever Npcap is present: they open a real `pcap_t`, close it forty times
from another goroutine while a read is in flight, and check that captured
lengths and timestamps are sane. Those cover defects 9 and the use-after-free
without a human watching the output — but only on a machine with the driver,
which is the whole point of this section.

Check that:

- handshake lines appear within a second or two of the traffic. Minutes
  later means connection close is not being processed (defects 3 and 6).
- the summary reports a non-zero packet count. Zero means packets are being
  captured and discarded, or never captured at all (defect 2).
- a modern browser produces at least one `post_quantum` flow, which also
  exercises reassembly of a ClientHello larger than one segment.
- Ctrl-C exits cleanly, with a summary and status 0 (defect 8).
- running **without** privileges prints the platform's permission hint
  rather than a bare errno (defect 7). On Windows, running with **no driver
  installed** must name the missing DLL and how to get it, and must not say
  "permission denied".
- the interface chosen with no `-i` is the one carrying traffic. On Windows
  it will not be first in the list, and several adapters ahead of it will
  claim to be up (defect 9).

If nothing appears at all, re-run with `-no-filter` to separate a
kernel-filter fault from a read-path fault. Run under `-race` if anything
about the output looks non-deterministic (defect 4).

### QUIC — validated against RFC vectors and tshark

Initial key derivation is checked against the published vectors in RFC 9001
appendix A, for both directions, rather than against a round trip of this
package's own code. Header protection, AEAD and packet parsing are checked by
a round trip against a sealer written separately from the RFC, and
`testdata/quic.pcap` is generated by a builder in `internal/tlssynth` that
derives its keys independently of the decoder — so an agreement is not both
halves sharing a mistake about salts or labels.

tshark decrypts the same capture with its own implementation and agrees on
every compared field. Its JA4 is not compared for QUIC: that field is not
emitted for QUIC handshakes by this build.

Not covered: connection migration, Retry, 0-RTT, and QUIC over IPv6 has no
synthetic case yet.

## Not yet validated

### JA4 — validated; JA4S — not

`internal/tlsparse/ja4.go` now agrees with Wireshark's JA4 implementation on
**47 of 47 handshakes**: 21 synthetic and 26 captured from four TLS stacks
(OpenSSL 3.6, LibreSSL, curl/SecureTransport, and three browsers). The
corpus covers TLS 1.2 and 1.3, present and absent SNI — including the `i`
branch that a connection without SNI takes — several ALPN values, narrow
signature-algorithm lists, and post-quantum key shares.

Two details remain unexercised and are marked in the source:

- an ALPN value whose first or last byte is not alphanumeric, where the
  spec substitutes a hex encoding. No client in the corpus sent one.
- DTLS, which the record layer does not decode at all.

**JA4S is not validated.** Wireshark emits `tls.handshake.ja4` for the
client but the harness does not yet compare a server fingerprint, so the
JA4S code has been read against the spec and nothing more.

### Differential testing against tshark — done, with gaps

The M1 gate. Run it with:

```sh
sudo scripts/capture-corpus.sh      # captures into testdata/local/, gitignored
scripts/differential.sh testdata/*.pcap testdata/local/*.pcap
```

Current result — **47 flows, 282 field checks, 0 mismatches**, comparing
SNI, cipher suites, supported groups, key share groups, signature algorithms,
ALPN and JA4 against Wireshark 4.6.8.

Two rules make the comparison mean something:

- **Codepoints, never names.** Mapping tshark's `4865` through this
  project's own registry to `TLS_AES_128_GCM_SHA256` would make the oracle
  agree with the code under test by construction. GREASE is stripped from
  the tshark side by a predicate written out from RFC 8701 in
  `scripts/diffparse`, not imported from `internal/tlsparse`, for the same
  reason.
- **A ClientHello tshark decodes and tlscensus does not is reported as
  MISSING**, not skipped. Silent under-reporting is the failure mode that
  matters most here.

#### What the first run actually found

Two mismatches, and **both were the harness, not the parser**:

1. `signature_algorithms` disagreed on a Chrome ClientHello.
   `tls.handshake.sig_hash_alg` is emitted by `signature_algorithms` (13),
   `signature_algorithms_cert` (50) and `delegated_credentials` (34) alike,
   and `-e` returns their concatenation. Chrome carries 13 and 34, so the
   oracle was comparing a union against one extension. Fixed by reading that
   field from the full dissection tree, scoped to extension 13.
2. `key_share_groups` disagreed on order, non-deterministically. Each
   KeyShareEntry is its own object in tshark's tree, and the walk visited
   siblings in Go's randomised map order. `tshark -V` confirmed the wire
   order is the one tlscensus reports. Fixed by taking order-sensitive
   fields from `-e`, which preserves it, and using the tree only where a
   field name is ambiguous.

Worth recording because the pattern is now familiar: an oracle that is
wrong in a way that accuses correct code is not much better than one that
agrees with broken code.

#### Corpus coverage

| Shape | Covered |
|---|---|
| TLS 1.3 | yes, 23 flows |
| TLS 1.2 | yes, 3 flows |
| Post-quantum key share (X25519MLKEM768) | yes, 16 flows |
| No SNI (JA4 `i` branch) | yes, 1 flow |
| PSK / session resumption offered | yes, 1 flow |
| Distinct client fingerprints | 15 JA4 values |
| **HelloRetryRequest** | **no** |
| **ECH** | **no** (synthetic only) |
| **Non-alphanumeric ALPN** | **no** |
| **DTLS, QUIC** | **no** (not implemented) |

HelloRetryRequest is the significant gap. `openssl s_client -groups
P-521:x25519` was meant to provoke one but OpenSSL sends key shares for
both groups, so no retry was needed. Forcing it needs a server that refuses
every offered group, or a client that key-shares only a group the server
will not take. The HRR path is covered synthetically and by unit tests, but
never against a real server.

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
