# Roadmap

Milestones are gated on the claim each one lets the project honestly make.
Shipping ahead of a gate means publishing a number that is wrong in a
direction that flatters the tool.

| | Deliverable | Status | Gate |
|---|---|---|---|
| **M1** | Parser, TCP reassembly, capture-file reader, JSON/NDJSON/text output | **done** | Differential-clean against `tshark` on a real corpus — see [validation.md](validation.md) |
| **M2** | Live capture on Linux and macOS | **done** | |
| **M3** | Local web report + CycloneDX CBOM export | **done** | |
| **M4** | Windows capture | **done** | **earliest honest public v0.1** |
| **M5** | QUIC / HTTP-3 | **done** | **earliest honest "PQ readiness" headline** |
| **M6** | Process attribution | not started | |

## Why the gates are where they are

**M4 gates the release.** Cross-platform coverage is the differentiator. A
Linux-only passive TLS monitor is a worse Zeek, and Zeek is free, mature and
already deployed. There is no reason for this project to exist until it runs
on the two platforms Zeek does not serve well.

**M5 gates the headline number.** A meaningful share of modern TLS 1.3 rides
on QUIC, and that traffic skews post-quantum — it is largely the same
providers who deployed hybrid key exchange first. Publishing a readiness
percentage while ignoring HTTP/3 biases the figure downward on exactly the
networks doing best. It is also the first thing a competent evaluator will
check.

**M3 — report and CBOM.** Done. `-o html` writes a self-contained page
(inline CSS, no fonts, no network) and `-o cbom` writes CycloneDX 1.6 with
`cryptographic-asset` components, validated against the published schema by
`scripts/validate-cbom.sh`. `tlscensus serve` puts the same report on
loopback with a token.

The CBOM is the interoperability story: it makes this a feed into
procurement and compliance tooling rather than another dashboard. Its serial
number is derived from the asset set rather than from randomness, so the
same inventory produces the same document and two runs can be diffed.

## Notes on the unbuilt parts

**M2 — live capture.** Done, and cgo-free on both platforms, which was not
the original plan. Linux uses `pcapgo.EthernetHandle` (`AF_PACKET`, pure Go);
macOS talks to `/dev/bpf*` directly through `x/sys/unix` rather than linking
libpcap. The consequence is that one build runner still produces every
release target and `go install` needs no C toolchain or libpcap headers.

The kernel BPF filter is hand-assembled and verified by running the real
program in `x/net/bpf`'s userspace VM against the sample capture, so it is
tested without root or an interface. IPv6 is accepted wholesale rather than
tested for `next_header == TCP`, because a filter that checked that byte
would drop every flow carrying an extension header.

Both M1 deferrals are closed: `MaxStreams` caps concurrently tracked
connections and reports the shortfall in `Stats.StreamsDropped`, and a stream
whose prefix fills in both directions without yielding a handshake is
rejected outright instead of being re-parsed.

Still outstanding on this platform pair: **pktap**. Opening Apple's
per-process pseudo-device would give process attribution nearly free, but its
link type is not decoded, so `watch` rejects it with an explicit message
rather than silently capturing nothing. That is M6.

**M4 — Windows.** Done. Verified on Windows 11 with Npcap 1.88: live
capture on an Intel Wireless-AC 9560, four TLS 1.3 flows read correctly, and
Ctrl-C exiting 0 with a summary.

Npcap is driven through runtime DLL loading rather than cgo, so the binary
stays cgo-free like the other two platforms: one runner still produces every
release target, `go install` needs no C toolchain or Npcap SDK, and a machine
without Npcap can still run `tlscensus read`. Npcap is installed by the user;
its licence does not permit redistribution, which for an open-source tool is
normal friction rather than a blocker.

What cannot be checked from a Mac is exactly what broke on the other two
platforms: structure layout. Windows is LLP64, so `long` stays 32 bits and
`struct timeval` inside `struct pcap_pkthdr` is 8 bytes rather than the 16 it
occupies on 64-bit Unix. Getting that wrong does not crash — it shifts
`caplen` and `len` by eight bytes and yields no usable packets. Since there
is no parser to unit-test here, `live_windows_test.go` asserts the sizes and
field offsets directly and CI runs it on a real Windows machine, which is the
closest an automated check can get.

That closed the gap M2 had, and running it closed one more. Twelve defects
were found: eleven by reviewing the unverified commit — a use-after-free on
every Ctrl-C among them, since `pcap_close` frees the buffer an in-flight
`pcap_next_ex` is filling — and a twelfth only by installing the driver.
Npcap enumerates a Bluetooth PAN adapter and two Wi-Fi Direct virtual
adapters ahead of the real one, all reporting themselves up and holding
169.254 addresses, so the default-interface rule every platform shared
picked the Bluetooth radio and captured nothing. See
[validation.md](validation.md).

The driver-free alternatives, `pktmon` (built in since Windows 10 1809) and
WFP, remain optimisations rather than blockers — worth revisiting only if
requiring Npcap proves to be real friction.

**M5 — QUIC.** Done. Initial packets are protected with keys derived from
the Destination Connection ID (RFC 9001), which travels in the clear, so the
handshake is recoverable with no secrets — the protection exists to stop
middleboxes ossifying the wire format, not to hide anything from an observer.

`internal/quic` does header protection removal, AEAD open and CRYPTO-frame
reassembly; the same `internal/tlsparse` then reads the result. The one
structural difference is that QUIC has no TLS record layer — CRYPTO frames
carry handshake messages directly — so the parser grew record-free entry
points. Feeding QUIC bytes to the record-framed ones rejects the flow as
non-TLS, which is a silent total loss rather than a visible error, and is
exactly what happened on the first run.

Key derivation is pinned to the vectors in RFC 9001 appendix A, and the
sample capture is generated by a builder in `internal/tlssynth` that derives
its keys independently rather than reusing the decoder's. tshark decrypts the
same capture and agrees on every field.

Not covered: connection migration, Retry (which re-keys on a new connection
ID and is detected but not followed), and 0-RTT.

**M6 — process attribution.** Linking a handshake to the application that
made it. The README promises this in its opening sentence and does not yet
deliver it: a finding of "this host does classical key exchange" cannot be
acted on, where "this runtime does" is a ticket.

Deliberately **not** starting with eBPF, despite it being the obvious answer.

*Staging.* macOS `pktap` first: packets arrive already carrying pid and
process name, so it is mostly a `DLT_PKTAP` header decoder — capture
currently refuses that link type explicitly rather than capturing nothing.
Then a socket-table lookup **at flow-emit time** on Linux and Windows —
`/proc/net/tcp` plus `/proc/*/fd`, and `GetExtendedTcpTable` — which needs no
privilege beyond what capture already holds and is roughly a day per
platform. eBPF only afterwards, and only if a measured miss rate justifies
it.

*Why not eBPF first.* It raises the privilege requirement from `CAP_NET_RAW`
to `CAP_BPF` + `CAP_PERFMON`, needs BTF, is forbidden outright in some
hardened environments — the same environments a compliance-driven inventory
gets deployed into — and adds an LLVM toolchain to the contributor
requirements of a project whose build is currently `go build` and nothing
else. The platform with the cleanest install story today would take the
biggest hit. A socket-table lookup races short-lived connections and will
miss some; the honest response is to report the attribution rate
(`attributed: 340/412`) so the gap is visible, and to let measurement decide
whether eBPF is worth its cost.

*The rule.* Attribution is **strictly additive**. If it is unavailable the
tool behaves exactly as it does without it, and `watch` never fails because
an attribution backend did not load. A row with no process must be
distinguishable from a row that was never attributed, or the output becomes
quietly incomplete in the way this project keeps having to fix.

*What it costs beyond code.* Attribution is worth less than it sounds on
servers (one process), behind proxies (every flow attributes to the proxy),
in containers (a pid from another namespace means nothing without cgroup
mapping) and for browsers (`Google Chrome Helper`, not the site). Its value
is highest on developer and employee endpoints — which is also where adding
"which application, run by which user" turns a crypto inventory into
something much closer to endpoint monitoring. That is a deployment cost, not
a technical one: it changes who has to approve running it, and the privacy
section needs rewriting rather than footnoting when it lands.

*Sequencing.* M6 was never a release gate and is the only milestone that is
not. v0.1 ships first.

## Deliberately out of scope

- **Active scanning.** Passive observation only. `testssl.sh` and `sslyze`
  do the active job well.
- **Interception, proxying, decryption.** Not a MITM tool, now or later.
  This is the property that makes it deployable in places a proxy is not.
- **Telemetry or a management plane.** No network calls of any kind.
