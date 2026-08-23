# Security Policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the
Security tab of this repository. Please do not open a public issue for a
security report.

Expect an acknowledgement within three working days.

## Why this matters more than usual here

The parser in `internal/tlsparse` reads bytes chosen by whoever is on the
other end of the network, and in live-capture mode it does so inside a
process holding elevated privileges. That is the highest-value target in the
codebase, and it is why the package is structured the way it is:

- Pure functions over `[]byte`. No I/O, no global state, no dependency
  beyond `golang.org/x/crypto/cryptobyte`.
- Every length prefix is read through `cryptobyte`, which bounds-checks
  rather than trusting a declared length.
- Buffers are bounded before parsing, not by it: `internal/assemble` caps
  each stream direction, so a declared length can never drive an allocation.
- A continuously running fuzz target, `FuzzParseStream`.

## In scope

- Memory-safety or panic conditions in `internal/tlsparse` or
  `internal/assemble` reachable from captured bytes.
- Unbounded memory or CPU growth driven by crafted traffic.
- Any path where captured data escapes the process.

## Out of scope

- Missing or incorrect protocol coverage that produces a wrong report but no
  safety issue. Open a normal issue for those; accuracy bugs are taken
  seriously but handled in public.
- Privilege requirements of packet capture itself.

## Fuzzing

```sh
go test ./internal/tlsparse -run=Fuzz -fuzz=FuzzParseStream -fuzztime=5m
```

Crashers are written to `internal/tlsparse/testdata/fuzz/`. Commit any
reproducer you find along with the fix.
