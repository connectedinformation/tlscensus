# Roadmap

Milestones are gated on the claim each one lets the project honestly make.
Shipping ahead of a gate means publishing a number that is wrong in a
direction that flatters the tool.

| | Deliverable | Status | Gate |
|---|---|---|---|
| **M1** | Parser, TCP reassembly, capture-file reader, JSON/NDJSON/text output | **done** | Differential-clean against `tshark` on a real corpus — see [validation.md](validation.md) |
| **M2** | Live capture on Linux and macOS | not started | |
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

**M2 — live capture.** libpcap on macOS and Linux, behind a build tag, with
the pure-Go file reader remaining the default path so CI never needs
privileges. Prefer `AF_PACKET` on Linux where it avoids cgo. On macOS,
opening `pktap` instead of a plain BPF device yields per-process attribution
for free, which is most of M6 on that platform. Do not run the whole agent
as root: follow Wireshark's ChmodBPF pattern.

Two things M1 defers that M2 must handle. The stream table is bounded only
by an idle timeout, with no cap on concurrent flows — fine for a file, not
for a busy host. And the reject heuristic needs a byte cap so a long-lived
non-TLS flow cannot be re-examined indefinitely.

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
