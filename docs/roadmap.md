# Roadmap

Milestones are gated on the claim each one lets the project honestly make.
Shipping ahead of a gate means publishing a number that is wrong in a
direction that flatters the tool.

| | Deliverable | Status | Gate |
|---|---|---|---|
| **M1** | Parser, TCP reassembly, capture-file reader, JSON/NDJSON/text output | **done** | Differential-clean against `tshark` on a real corpus — see [validation.md](validation.md) |
| **M2** | Live capture on Linux and macOS | **done** | |
| **M3** | Local web report + CycloneDX CBOM export | not started | |
| **M4** | Windows capture | not started | **earliest honest public v0.1** |
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

**M4 — Windows.** Npcap is libpcap-API-compatible, so the capture layer is
close to a drop-in. **Its licence does not permit redistribution inside a
commercial product**; for an open-source tool, telling users to install
Npcap themselves is normal and Wireshark has trained the market on it. The
driver-free alternatives are `pktmon` (built in since Windows 10 1809) and
WFP; both are more awkward for real-time work and are optimisations, not
blockers.

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
