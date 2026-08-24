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

```sh
go install github.com/tlscensus/tlscensus/cmd/tlscensus@latest
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

## What it cannot see

Stated plainly, because an inventory that overstates its coverage is worse
than no inventory.

- **TLS 1.3 encrypts the certificate.** Certificate inventory — key sizes,
  issuers, expiry — is only available for TLS 1.2 and below. This is the
  protocol, not a gap in the parser.
- **QUIC / HTTP-3 is not decoded yet** (M5). A meaningful share of modern
  TLS 1.3 traffic rides on QUIC, and it skews post-quantum. Until M5 lands,
  the readiness figure is biased *downward* on any network carrying HTTP/3.
- **No process attribution yet** (M6). Flows are identified by address and
  port, not by the application that opened them. On macOS the `pktap`
  pseudo-device would provide this nearly free; its link type is not decoded
  yet, so `watch` refuses it explicitly rather than capturing nothing.
- **Windows live capture** is not implemented (M4). `read` works there today.
- **STARTTLS is not tracked.** A session that begins as cleartext SMTP or
  IMAP and upgrades in place is not currently detected.
- **Resumed sessions** carry no full handshake, so they report what the
  client offered and little else.

## Privacy

A list of the hostnames a machine contacted is browsing-history-grade data.
tlscensus has no telemetry, makes no network connections of its own, and
sends nothing anywhere. Output goes to the file or pipe you point it at.
Nothing in this repository phones home; `grep -r 'http'` over the source is
a short read.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the
[DCO](https://developercertificate.org/) — sign commits with `git commit -s`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
