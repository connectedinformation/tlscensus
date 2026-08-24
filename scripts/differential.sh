#!/usr/bin/env bash
#
# Differential test: compare tlscensus's handshake decoding against tshark's
# on the same bytes.
#
# tshark is the oracle for a reason. It decodes the same fields from the same
# packets, it has had two decades of exposure to real traffic, and it was
# written by different people from a different reading of the RFCs. Where the
# two disagree, tlscensus is wrong until shown otherwise.
#
# Comparison is on raw codepoints, never names — see scripts/diffparse.
#
# Usage:
#   scripts/differential.sh CAPTURE...
#   scripts/differential.sh testdata/*.pcap testdata/local/*.pcap
#
# Exit status is non-zero if any field disagrees.

set -uo pipefail

TSHARK=${TSHARK:-tshark}

if ! command -v "$TSHARK" >/dev/null 2>&1; then
    echo "differential: $TSHARK not found." >&2
    echo "  macOS:  brew install wireshark" >&2
    echo "  Debian: apt install tshark" >&2
    exit 127
fi
if [ $# -eq 0 ]; then
    echo "usage: $0 CAPTURE..." >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

status=0
for pcap in "$@"; do
    [ -e "$pcap" ] || continue
    echo "=== $pcap"

    # One JSON object per ClientHello, joined to tlscensus on source port.
    # Two passes, for two different reasons.
    #
    # -e preserves wire order within each field, which matters for cipher
    # and key-share lists. The full tree does not: sibling objects come back
    # in map order.
    #
    # The tree is needed anyway, because tls.handshake.sig_hash_alg is
    # emitted by signature_algorithms, signature_algorithms_cert and
    # delegated_credentials alike, and only the nesting distinguishes them.
    if ! "$TSHARK" -r "$pcap" -Y 'tls.handshake.type == 1' -T json \
        -e tcp.srcport \
        -e udp.srcport \
        -e tls.handshake.extensions_server_name \
        -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions_supported_group \
        -e tls.handshake.extensions_key_share_group \
        -e tls.handshake.extensions_alpn_str \
        -e tls.handshake.ja4 \
        > "$work/fields.json" 2>"$work/tshark.err"
    then
        echo "  tshark failed:"; sed 's/^/    /' "$work/tshark.err"; status=1; continue
    fi

    if ! "$TSHARK" -r "$pcap" -Y 'tls.handshake.type == 1' -T json --no-duplicate-keys \
        > "$work/tree.json" 2>"$work/tshark.err"
    then
        echo "  tshark failed:"; sed 's/^/    /' "$work/tshark.err"; status=1; continue
    fi

    if ! go run ./scripts/diffparse "$work/fields.json" "$work/tree.json" "$pcap"; then
        status=1
    fi
done

if [ $status -eq 0 ]; then
    echo "all captures agree"
else
    echo "DISAGREEMENTS FOUND — tlscensus is wrong until shown otherwise" >&2
fi
exit $status
