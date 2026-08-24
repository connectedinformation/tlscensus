#!/usr/bin/env bash
#
# Capture a corpus of real TLS handshakes and run the differential test
# against it.
#
#   sudo scripts/capture-corpus.sh [interface]
#
# Needs root for tcpdump. The capture lands in testdata/local/, which is
# ignored by git — and must stay that way. A recording of real traffic is a
# record of who talked to whom, which is exactly the data this tool exists to
# treat carefully. The recipe is committed; the capture never is.
#
# Diversity is the point. A corpus of one client validates one client's
# quirks. This drives four TLS stacks and a range of deliberately awkward
# options: no SNI, a group the server will refuse, session resumption,
# post-quantum key shares, and TLS 1.2 as well as 1.3.

set -uo pipefail

IFACE=${1:-}
OUT_DIR=testdata/local
OUT=$OUT_DIR/corpus.pcap
BROWSE_SECONDS=${BROWSE_SECONDS:-20}
OPENSSL3=${OPENSSL3:-/opt/homebrew/opt/openssl@3/bin/openssl}
SYS_OPENSSL=${SYS_OPENSSL:-/usr/bin/openssl}

if [ "$(id -u)" -ne 0 ]; then
    echo "capture-corpus: must run as root (tcpdump); try: sudo $0" >&2
    exit 1
fi

# Everything created here belongs to the invoking user, not root.
OWNER=${SUDO_USER:-$(id -un)}
mkdir -p "$OUT_DIR"

if [ -z "$IFACE" ]; then
    IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    IFACE=${IFACE:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}
fi
if [ -z "$IFACE" ]; then
    echo "capture-corpus: could not determine the default interface; pass one" >&2
    exit 1
fi

echo "capturing on $IFACE -> $OUT"
tcpdump -i "$IFACE" -s 0 -w "$OUT" 'tcp' >/dev/null 2>&1 &
TCPDUMP=$!
trap 'kill $TCPDUMP 2>/dev/null' EXIT
sleep 2

HOSTS="cloudflare.com www.google.com github.com example.com wikipedia.org"

say()  { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; }

# macOS ships no coreutils timeout, and the first version of this script
# discarded stderr — so every scripted variant failed with "command not
# found" and the corpus silently contained nothing but curl. Prefer a real
# timeout, fall back to a watchdog, and always report failures.
if command -v timeout >/dev/null 2>&1; then
    limit() { timeout "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
    limit() { gtimeout "$@"; }
else
    limit() {
        local secs=$1; shift
        "$@" & local pid=$!
        ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) & local watchdog=$!
        wait "$pid" 2>/dev/null; local rc=$?
        kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
        return $rc
    }
fi

# 1. curl: SecureTransport / LibreSSL, the system stack.
for h in $HOSTS; do
    curl -s -o /dev/null --max-time 8 "https://$h/" && say "curl $h"
done

# 2. OpenSSL 3: full control over what gets offered.
if [ -x "$OPENSSL3" ]; then
    # $1 is the label, $2 the host, the rest s_client options.
    s() {
        local label=$1 host=$2; shift 2
        if limit 12 "$OPENSSL3" s_client -connect "$host:443" -servername "$host" \
             "$@" </dev/null >/dev/null 2>&1
        then say "$label"; else fail "$label"; fi
    }

    s "openssl3 default"        cloudflare.com
    s "openssl3 google"         www.google.com
    s "openssl3 TLS 1.2"        cloudflare.com -tls1_2
    s "openssl3 PQ only"        cloudflare.com -groups X25519MLKEM768
    s "openssl3 PQ + classical" cloudflare.com -groups x25519:X25519MLKEM768
    # A group most servers will not select: expect a HelloRetryRequest, and
    # with it a second ClientHello and a cookie extension on the same flow.
    s "openssl3 HRR bait"       cloudflare.com -groups P-521:x25519
    s "openssl3 ALPN h2"        cloudflare.com -alpn h2
    s "openssl3 ALPN http/1.1"  cloudflare.com -alpn http/1.1
    s "openssl3 narrow sigalgs" cloudflare.com -sigalgs ECDSA+SHA256:RSA-PSS+SHA256
    s "openssl3 no TLS 1.3"     cloudflare.com -no_tls1_3
    s "openssl3 TLS 1.2 + ECDSA" www.google.com -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256

    # No SNI at all: JA4 must report 'i' rather than 'd'.
    if limit 12 "$OPENSSL3" s_client -connect cloudflare.com:443 -noservername \
        </dev/null >/dev/null 2>&1
    then say "openssl3 no SNI"; else fail "openssl3 no SNI"; fi

    # Session resumption: the second connection offers a PSK instead of a
    # full handshake, and its ClientHello looks materially different.
    TICKET=$(mktemp)
    if limit 12 "$OPENSSL3" s_client -connect cloudflare.com:443 -servername cloudflare.com \
        -sess_out "$TICKET" </dev/null >/dev/null 2>&1
    then say "openssl3 session saved"; else fail "openssl3 session saved"; fi
    if limit 12 "$OPENSSL3" s_client -connect cloudflare.com:443 -servername cloudflare.com \
        -sess_in "$TICKET" </dev/null >/dev/null 2>&1
    then say "openssl3 session resumed"; else fail "openssl3 session resumed"; fi
    rm -f "$TICKET"
else
    echo "  (OpenSSL 3 not found at $OPENSSL3; skipping scripted variants)"
fi

# 3. LibreSSL, a different stack again.
if [ -x "$SYS_OPENSSL" ]; then
    if limit 12 "$SYS_OPENSSL" s_client -connect github.com:443 -servername github.com \
        </dev/null >/dev/null 2>&1
    then say "libressl github"; else fail "libressl github"; fi
fi

# 4. Whatever the operator drives by hand. Browsers are the most valuable
#    entries in the corpus: they carry GREASE, extension orders and
#    post-quantum key shares that no scripted client reproduces.
echo
echo "  >>> Browse now — ${BROWSE_SECONDS}s <<<"
echo "      Use a PRIVATE / INCOGNITO window and visit several DIFFERENT sites."
echo "      A warm browser resumes sessions and reuses connections, so an"
echo "      ordinary tab may produce no new handshake at all."
sleep "$BROWSE_SECONDS"

kill $TCPDUMP 2>/dev/null
wait $TCPDUMP 2>/dev/null
trap - EXIT
sleep 1

chown "$OWNER" "$OUT" 2>/dev/null
PACKETS=$(tcpdump -r "$OUT" 2>/dev/null | wc -l | tr -d ' ')
HELLOS=$(tshark -r "$OUT" -Y 'tls.handshake.type == 1' 2>/dev/null | wc -l | tr -d ' ')

echo
echo "captured $PACKETS packets, $HELLOS ClientHellos into $OUT"
if [ "${HELLOS:-0}" -lt 12 ]; then
    echo
    echo "WARNING: a thin corpus. A differential pass over a handful of"
    echo "handshakes from one client proves very little — check the FAIL"
    echo "lines above and browse more next time."
fi
echo
echo "Now run:  scripts/differential.sh $OUT"
