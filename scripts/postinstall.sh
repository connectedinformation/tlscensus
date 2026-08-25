#!/bin/sh
#
# Run by dpkg/rpm after installing the package.
#
# It prints the capability step rather than performing it. Granting a binary
# CAP_NET_RAW is a policy decision that belongs to whoever administers the
# machine, and a security tool that silently gives itself raw socket access
# at install time is exactly the sort of thing that gets a package barred
# from a hardened environment. Wireshark's Debian package asks rather than
# assumes, for the same reason.

set -e

BIN=/usr/bin/tlscensus
[ -x "$BIN" ] || BIN=$(command -v tlscensus 2>/dev/null || echo /usr/bin/tlscensus)

cat <<EOF

tlscensus is installed.

Reading capture files needs no privileges:

    tlscensus read capture.pcap

Live capture needs CAP_NET_RAW. Grant it to the binary rather than running
the whole tool as root:

    sudo setcap cap_net_raw=eip $BIN

Add cap_net_admin as well if you intend to use promiscuous mode (-promisc),
which is off by default. Note that setcap is lost whenever the binary is
replaced, so it must be reapplied after every upgrade.

See /usr/share/doc/tlscensus/permissions.md, or:
https://github.com/connectedinformation/tlscensus/blob/main/docs/permissions.md

EOF
