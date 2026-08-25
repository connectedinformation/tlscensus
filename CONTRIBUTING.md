# Contributing

**The most useful thing you can send is a bug report from your own network.**

That is not politeness. Almost every real defect this project has had was
found by someone running it against real hardware or real traffic, after a
green CI run and a passing test suite — a header field the kernel writes
differently, a default that picked a Bluetooth adapter, a site that was
missing because it had quietly moved to HTTP/3. Tests can be written; the
diversity of real networks cannot. `docs/validation.md` lists them, and the
pattern is consistent enough to be worth stating as policy.

## Reporting something wrong

The best reports say what the tool claimed and what was actually true:

- **It reported nothing.** Include `tlscensus watch -i <iface>` output, the
  packet count from the summary, your platform, and whether `-no-filter`
  changes it. A capture that runs cleanly and reports nothing is the failure
  mode we most want to hear about, because it looks like success.
- **It reported the wrong thing.** If you can, run
  `scripts/differential.sh <capture>` — it compares this parser against
  tshark's on the same bytes and prints every disagreement. A disagreement is
  a bug here until shown otherwise.
- **A handshake was missing.** The server name, and whether the host offers
  HTTP/3 (`curl -sI https://host/ | grep alt-svc`).

**Do not attach a capture of real traffic.** It is a record of who talked to
whom. Describe it, or reproduce it against a host you control.

## Code

Pull requests are welcome but are not what the project needs most. If you
send one:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/) — sign
commits with `git commit -s`. There is no CLA.

## House rules

**`internal/tlsparse` takes no dependencies.** It is the fuzz target and the
code that reads hostile input in a privileged process. Standard library plus
`golang.org/x/crypto/cryptobyte`, nothing else.

**The parser describes; it does not judge.** `tlsparse` reports what was on
the wire. Deciding that 3DES is worth flagging is policy and belongs in
`internal/inventory`, where it can change without touching the code that
reads bytes.

**A test must not share its assumptions with the code under test.**
`internal/tlssynth` deliberately does not import `internal/tlsparse`, and
builds its QUIC packets from its own key derivation rather than the
decoder's. This is not fastidiousness: the one time that rule was broken, a
unit test derived a header length from the same constant the parser
validated against, agreed with the bug, and passed for days.

**New protocol coverage needs a test that would fail without it.** Ideally a
synthetic handshake in `internal/tlssynth` plus a case in a sample capture.
Regenerate captures with `go run ./testdata/gen`.

**Never commit a real capture.** Everything in `testdata/` is synthesised.
`testdata/local/` is git-ignored for local captures.

## Accuracy is the product

An inventory that silently undercounts is worse than one that errors. If a
change narrows coverage — a port range, a size cap, a sampling rule — say so
in the output or in the README's "What it cannot see", not only in the commit
message.
