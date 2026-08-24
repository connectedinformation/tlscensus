# Roadmap

Milestones are gated on the claim each one lets the project honestly make.
Shipping ahead of a gate means publishing a number that is wrong in a
direction that flatters the tool.

| | Deliverable | Status | Gate |
|---|---|---|---|
| **M1** | Parser, TCP reassembly, capture-file reader, JSON/NDJSON/text output | **done** | Differential-clean against `tshark` on a real corpus — see [validation.md](validation.md) |
| **M2** | Live capture on Linux and macOS | **done** | |
| **M3** | Local web report + CycloneDX CBOM export | **done** | |
| **M4** | Windows capture | **code-complete, unverified** | **earliest honest public v0.1** |
| **M5** | QUIC / HTTP-3 | not started | **earliest honest "PQ readiness" headline** |
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

**M4 — Windows.** Written, compiling and vetting clean, and **not yet run on
a Windows machine**. It is not done until it has been.

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

The remaining gap is the same one M2 had: nothing has confirmed that packets
actually arrive. That needs the smoke test in
[validation.md](validation.md) on a machine with Npcap installed.

The driver-free alternatives, `pktmon` (built in since Windows 10 1809) and
WFP, remain optimisations rather than blockers — worth revisiting only if
requiring Npcap proves to be real friction.

**M5 — QUIC.** Initial packets are protected with keys derived from the
Destination Connection ID (RFC 9001), so the ClientHello and ServerHello are
recoverable with no secrets at all. The work is header protection removal,
AEAD open, and CRYPTO-frame reassembly across Initial packets.

**M6 — process attribution.** macOS gets it nearly free via PKTAP. Linux
wants eBPF on `tcp_connect` rather than polling `/proc`, and Windows wants
ETW `Microsoft-Windows-Kernel-Network`, for the same reason in both cases:
polling a socket table races short-lived connections, which are the ones
worth catching.

## Deliberately out of scope

- **Active scanning.** Passive observation only. `testssl.sh` and `sslyze`
  do the active job well.
- **Interception, proxying, decryption.** Not a MITM tool, now or later.
  This is the property that makes it deployable in places a proxy is not.
- **Telemetry or a management plane.** No network calls of any kind.
