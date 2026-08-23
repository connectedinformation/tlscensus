# Contributing

## Sign-off

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/). Add a
sign-off to every commit:

```sh
git commit -s
```

There is no CLA.

## Before you open a pull request

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

## House rules

**`internal/tlsparse` takes no dependencies.** It is the fuzz target and the
code that reads hostile input in a privileged process. Standard library plus
`golang.org/x/crypto/cryptobyte`, nothing else.

**The parser describes; it does not judge.** `tlsparse` reports what was on
the wire. Deciding that 3DES is worth flagging is policy and belongs in
`internal/inventory`, where it can change without touching the code that
reads bytes.

**`internal/tlssynth` does not import `internal/tlsparse`.** The builders
define their own codepoint constants on purpose. A test oracle that shares
definitions with the code under test cannot catch a wrong constant.

**New protocol coverage needs a test that would fail without it.** Ideally a
synthetic handshake in `internal/tlssynth` plus a case in the sample capture.
Regenerate the capture with `go run ./testdata/gen`.

**Never commit a real capture.** A recording of live traffic is a record of
who talked to whom. Everything in `testdata/` is synthesised.

## Accuracy is the product

An inventory that silently undercounts is worse than one that errors. If a
change narrows coverage — a port range, a size cap, a sampling rule — say so
in the output or in the README's "What it cannot see", not only in the commit
message.
