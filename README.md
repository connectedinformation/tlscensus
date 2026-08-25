# tlscensus

**Passive TLS cryptography inventory for Linux, macOS and Windows.**

Answers one question that is getting harder to avoid: *which of my machines
are still negotiating classical-only key exchange, and what software is doing
it?*

tlscensus watches TLS handshakes go by, decodes the ClientHello and
ServerHello, and reports what cryptography is actually in use — protocol
versions, cipher suites, key exchange groups, signature algorithms, ALPN,
SNI, and JA4 fingerprints — with a post-quantum readiness verdict for every
handshake. It never terminates, proxies, decrypts or modifies a connection.
There is no CA to install and no traffic interception.

```
$ tlscensus read capture.pcap

TLS handshakes:   9 (8 with a captured server response)
PQ readiness:     37.5% of observed negotiations used a post-quantum group

POST-QUANTUM STATUS
  classical                  3   33.3%
  post_quantum               3   33.3%
  advertised_only            1   11.1%
  offered_not_selected       1   11.1%

FINDINGS
  CRITICAL  1  broken_cipher       TLS_RSA_WITH_RC4_128_SHA uses broken primitive RC4_128
  CRITICAL  1  obsolete_protocol   TLS 1.0 is deprecated and prohibited by RFC 8996
  HIGH      2  no_forward_secrecy  TLS_RSA_WITH_AES_128_CBC_SHA has no forward secrecy
```

## Status

**Early. Reads capture files and captures live on Linux and macOS.**
See [docs/roadmap.md](docs/roadmap.md) for what lands when, and
[docs/validation.md](docs/validation.md) for what has not yet been checked
against a reference implementation.

## Install

Reading capture files needs no privileges on any platform. Live capture
needs one extra step everywhere — see
[docs/permissions.md](docs/permissions.md).

**macOS and Linux — Homebrew**

```sh
brew install tlscensus/tap/tlscensus
```

**Linux — package**

```sh
sudo dpkg -i tlscensus_*_linux_amd64.deb     # or: sudo rpm -i tlscensus-*.rpm
sudo setcap cap_net_raw=eip $(command -v tlscensus)
```

The package prints that `setcap` line on install. It does not run it:
granting a binary raw-socket capability is the administrator's decision, and
it has to be reapplied after every upgrade because replacing the binary
clears it.

**Windows**

```powershell
# 1. Install Npcap from https://npcap.com  (not bundled — its licence
#    forbids redistribution. If Wireshark is installed, so is Npcap.)
# 2. Extract tlscensus.exe from the release .zip onto your PATH.
```

**Any platform — verified download**

```sh
curl -fsSLO https://github.com/connectedinformation/tlscensus/releases/latest/download/checksums.txt
curl -fsSLO https://github.com/connectedinformation/tlscensus/releases/latest/download/tlscensus_Linux_x86_64.tar.gz
sha256sum --ignore-missing -c checksums.txt
tar xzf tlscensus_*.tar.gz && sudo install tlscensus /usr/local/bin/
```

Every release ships checksums and an SBOM. There is deliberately no
`curl | sh` installer: this tool runs as root and its readers are security
engineers, so piping a URL into a root shell would route around exactly the
verification the release provides.

**The binaries are not code-signed or notarised.** Verify the checksum
instead — that is what `checksums.txt` is for. On macOS this means Gatekeeper
would otherwise refuse a Homebrew-installed binary, so the cask clears the
quarantine attribute on install; if you download the archive by hand and
macOS blocks it, `xattr -dr com.apple.quarantine ./tlscensus` is the same
step done yourself.

**From source**

```sh
go install github.com/connectedinformation/tlscensus/cmd/tlscensus@latest
```

## Use

```sh
# Offline
tlscensus read capture.pcap
tlscensus read -o ndjson capture.pcapng | jq 'select(.pq_status == "classical")'
tlscensus read -o json -records *.pcap > inventory.json

# Live (Linux, macOS)
tlscensus interfaces
sudo tlscensus watch -i en0
sudo tlscensus watch -o ndjson | tee handshakes.ndjson

# Report
tlscensus read -o html capture.pcap > report.html   # self-contained page
tlscensus read -o cbom capture.pcap > crypto.cdx.json
tlscensus serve capture.pcap                         # loopback + token
sudo tlscensus serve -i en0                          # live, auto-refreshing
```

**No cgo, anywhere.** Linux capture is `AF_PACKET`; macOS reads `/dev/bpf*`
directly. There is no libpcap dependency, so `go install` works with no C
toolchain and one build runner produces every release target.

Reading a capture file needs no privileges at all, which is also why the
entire pipeline is exercised in CI. Live capture needs `CAP_NET_RAW` on Linux
or BPF device access on macOS — see [docs/permissions.md](docs/permissions.md)
for how to grant the narrow capability instead of running as root.

## What it gets right

Most of these are ways a TLS inventory quietly produces a wrong number
rather than an obvious error.

**Key shares are reported separately from supported groups.** A client can
advertise `X25519MLKEM768` in `supported_groups` and still send a key share
only for `x25519`. It will then complete a fully classical handshake against
any server that takes the offer. Collapsing the two is the most common way a
migration dashboard flatters itself, so readiness is reported as a ladder —
`post_quantum`, `offered_not_selected`, `advertised_only`, `classical` —
rather than as a boolean.

**Handshakes are reassembled across TCP segments.** A post-quantum key share
is over a kilobyte, so a ClientHello offering one routinely exceeds a single
segment. A parser that reads one packet drops precisely the handshakes a
post-quantum inventory exists to count, and reports a more classical world
than the one on the wire.

**Every TCP port is examined, not just 443.** Detection is by content. STARTTLS
on 587, a database on 5432, an appliance on 8443 — restricting to the
well-known port is how "we found no weak ciphers" comes to mean "we did not
look".

**GREASE is stripped** (RFC 8701), so the report does not fill with phantom
`0x8a8a` cipher suites from every Chrome connection.

**ECH is flagged, not silently mis-recorded.** When `encrypted_client_hello`
is present the visible SNI is the provider's public outer name. Recording it
as the destination is not a degraded reading, it is a wrong one, so those
flows are counted separately and kept out of hostname distributions.

**TLS 1.2 groups are read from ServerKeyExchange**, the only place a 1.2
handshake names its key exchange group.

**QUIC is decoded, not skipped.** Initial packets are protected with keys
derived from the connection ID in the clear, so HTTP/3 handshakes are read
the same as TCP ones. This matters more than it sounds: the providers who
deployed hybrid post-quantum key exchange early are the same ones who
deployed HTTP/3 early, so a TCP-only inventory reports a more classical
world than the one on the wire — and a site you just loaded can be missing
from it entirely.

## What it cannot see

Stated plainly, because an inventory that overstates its coverage is worse
than no inventory.

- **TLS 1.3 encrypts the certificate.** Certificate inventory — key sizes,
  issuers, expiry — is only available for TLS 1.2 and below. This is the
  protocol, not a gap in the parser.
- **QUIC connection migration, Retry and 0-RTT** are not followed. A Retry
  re-keys the connection on a new connection ID; it is detected, and the
  flow is then abandoned rather than guessed at.
- **No process attribution yet** (M6). Flows are identified by address and
  port, not by the application that opened them. On macOS the `pktap`
  pseudo-device would provide this nearly free; its link type is not decoded
  yet, so `watch` refuses it explicitly rather than capturing nothing.
- **Windows live capture is written but unverified** (M4) — it has never
  been run on a Windows machine, so treat it as untested. `read` works there
  today. Live capture needs [Npcap](https://npcap.com), installed
  separately; tlscensus loads it at runtime and does not bundle it.
- **STARTTLS is not tracked.** A session that begins as cleartext SMTP or
  IMAP and upgrades in place is not currently detected.
- **Resumed sessions** carry no full handshake, so they report what the
  client offered and little else.

## Output

| Format | Use |
|---|---|
| `text` | terminal summary (default) |
| `ndjson` | one record per line, for `jq` or a log shipper |
| `json` | the whole report, with `-records` for per-flow detail |
| `html` | self-contained page — no network access, no fonts, no CDN |
| `cbom` | CycloneDX 1.6 with `cryptographic-asset` components |

The CBOM is what makes this a feed into other tooling rather than one more
dashboard: post-quantum readiness is a property of your estate, not of this
program. Its serial number is derived from the asset set rather than from
randomness, so two runs over the same inventory produce the same document
and can be diffed. Validate with `scripts/validate-cbom.sh`.

`tlscensus serve` puts the report on **127.0.0.1 only**, behind a token
minted at startup. There is no flag to bind a routable address. Loopback by
itself is not an authorisation boundary — every local user can reach it —
which is why the token exists too.

## Privacy

A list of the hostnames a machine contacted is browsing-history-grade data.
tlscensus has no telemetry, makes no network connections of its own, and
sends nothing anywhere. Output goes to the file or pipe you point it at.
Nothing in this repository phones home; `grep -r 'http'` over the source is
a short read.

## Who makes this

tlscensus is built and maintained by **Connected Information**, which also
makes commercial TLS tooling. It is open source because a tool that runs as
root and reads every hostname a machine contacts should be one you can audit
before you trust it — and because the reports that make it correct come from
people running it on networks we do not have.

It has no telemetry, makes no network connections of its own, and is
Apache-2.0 licensed. Those are checkable claims, not assurances.

## Contributing

**A bug report from your own network is worth more to this project than a
pull request.** Nearly every real defect it has had was found by someone
running it against real hardware, after a green CI run — see
[docs/validation.md](docs/validation.md). Details in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
