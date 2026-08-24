#!/usr/bin/env bash
#
# Validate emitted CBOMs against the published CycloneDX schema.
#
#   scripts/validate-cbom.sh CAPTURE...
#
# Not a Go test: it needs cyclonedx-cli, which CI does not have. Schema
# conformance is the whole value of emitting CycloneDX rather than a bespoke
# JSON shape, so it is checked against the real validator rather than against
# this project's reading of the spec.
#
#   macOS:  brew install cyclonedx-cli
#   other:  https://github.com/CycloneDX/cyclonedx-cli/releases

set -uo pipefail

CDX=${CDX:-cyclonedx}
TLSCENSUS=${TLSCENSUS:-./tlscensus}

if ! command -v "$CDX" >/dev/null 2>&1; then
    echo "validate-cbom: $CDX not found; brew install cyclonedx-cli" >&2
    exit 127
fi
if [ ! -x "$TLSCENSUS" ]; then
    echo "validate-cbom: build first — go build -o tlscensus ./cmd/tlscensus" >&2
    exit 127
fi
[ $# -gt 0 ] || { echo "usage: $0 CAPTURE..." >&2; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
status=0
for pcap in "$@"; do
    [ -e "$pcap" ] || continue
    out="$work/$(basename "$pcap").cdx.json"
    if ! "$TLSCENSUS" read -o cbom "$pcap" > "$out"; then
        echo "=== $pcap: tlscensus failed"; status=1; continue
    fi
    printf '=== %s: ' "$pcap"
    if "$CDX" validate --input-file "$out" --input-format json --fail-on-errors 2>&1 | tail -1; then :; else status=1; fi
done
exit $status
