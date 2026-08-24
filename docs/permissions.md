# Capture permissions

Reading a capture file needs no privileges at all. Live capture does, on
every operating system, because reading raw frames off an interface is a
privileged operation by design.

The recommendation throughout is the same: **grant the narrow capability,
don't run the whole tool as root.** tlscensus parses bytes chosen by whoever
is on the other end of the network. That parser is fuzzed and bounded, but
the correct assumption is still that it will one day have a bug, and the
blast radius of that bug is whatever privilege the process holds.

## Linux

Capture uses an `AF_PACKET` socket, which needs `CAP_NET_RAW`.

```sh
sudo setcap cap_net_raw,cap_net_admin=eip $(which tlscensus)
tlscensus watch
```

`CAP_NET_ADMIN` is only needed for promiscuous mode (`-promisc`), which is
off by default. If you never use it:

```sh
sudo setcap cap_net_raw=eip $(which tlscensus)
```

Verify with `getcap $(which tlscensus)`. Note that `setcap` is lost when the
binary is replaced, so it must be reapplied after every upgrade.

Under systemd, prefer ambient capabilities over `User=root`:

```ini
[Service]
User=tlscensus
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
```

Failing all that, `sudo tlscensus watch` works.

## macOS

Capture opens a `/dev/bpf*` device, which is `root:wheel` and mode `0600` by
default.

```sh
sudo tlscensus watch
```

The better arrangement is the one Wireshark installs, for exactly this
reason — give a group read access to the BPF devices and put yourself in it:

```sh
sudo dseditgroup -o create -q access_bpf
sudo dseditgroup -o edit -a "$USER" -t user access_bpf
sudo chgrp access_bpf /dev/bpf*
sudo chmod g+r /dev/bpf*
```

Log out and back in for the group membership to take effect.

**The device permissions reset on reboot.** Wireshark ships a launch daemon
(`ChmodBPF`) that reapplies them at boot; if you have Wireshark installed,
that daemon already exists and adding yourself to `access_bpf` is all that is
needed. tlscensus does not install a daemon of its own — it would be an
odd thing for an inventory tool to leave behind.

No kernel extension, no system extension, and no approval dialog is involved.
Capture is a plain read of a character device.

## Windows

Not yet implemented. See [roadmap.md](roadmap.md) — M4.

## What promiscuous mode does, and why it is off

By default tlscensus captures only frames the interface would have accepted
anyway: this host's traffic, plus broadcast and multicast. That answers the
question the tool is for — *what cryptography does this machine negotiate?*

`-promisc` captures everything the interface can see, which on some networks
means other people's connections. Since the output includes the hostnames
each connection asked for, turning it on changes the tool from an inventory
of this host into a record of the neighbours' browsing. That is a legitimate
thing to want on a mirror port you own, and a bad default everywhere, so it
is opt-in.

## What tlscensus does with what it captures

Nothing leaves the process except what you asked for, where you asked for it.
There is no telemetry, no auto-update, and no network connection of any kind
in the binary. Captured packet data is bounded to the first 32 KiB of each
connection direction, held only long enough to parse the handshake, and then
discarded — full packet payloads are never written anywhere.
