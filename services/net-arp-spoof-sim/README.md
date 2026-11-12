# Challenge 9: net-arp-spoof-sim (Simulated On-Path Attacker)

A toy, plain-text simulation of a LAN's ARP table — not real ARP
packets, no raw sockets — that reproduces the exact design mistake
that makes real ARP spoofing possible: the table accepts **any**
announcement about which MAC address owns which IP, completely
unsolicited, with no check that a request was outstanding, and no
check against what it already knew.

## Running it

Standalone:

```bash
cd services/net-arp-spoof-sim
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-arp-spoof-sim
```

The service listens on port `6006` (mapped to `8008` externally):

```bash
nc localhost 8008
```

## The setup (not hidden from you — read it, that's the point)

Look at `src/lan_sim.py`. Each connection gets its own fresh simulated
LAN with two known hosts:

- `10.0.0.10` — "admin", starting MAC `AA:AA:AA:AA:AA:AA`
- `10.0.0.53` — "fileserver", starting MAC `FF:FF:FF:FF:FF:FF`

Three commands:

- `ARP_REPLY <ip> <mac>` — announce, completely unsolicited, that
  `<ip>` is now at `<mac>`. The table just believes it — no check
  that this corresponds to a request anyone actually made.
- `REQUEST_FLAG` — simulates admin (`10.0.0.10`) asking fileserver
  for the flag. Fileserver's reply is delivered to **whichever MAC
  the table currently says owns `10.0.0.10`** — not necessarily the
  real admin host.
- `READ_MAILBOX <mac>` — read (and clear) whatever's been delivered
  to a given MAC so far.

This is exactly the real-world ARP spoofing pattern: a switch/host
that accepts a gratuitous (unsolicited) ARP reply and updates its
table based on it, with nothing to confirm the announcement is
genuine, lets an attacker claim to *be* some other host's IP address
and have traffic meant for that host redirected to them instead.

## What you need to work out

1. **Confirm the normal flow first.** Connect, send `REQUEST_FLAG`,
   then `READ_MAILBOX AA:AA:AA:AA:AA:AA` (admin's starting MAC). You
   should see the flag land there — because nobody's announced
   anything about `10.0.0.10` yet, so the table still has its
   original, correct mapping.

2. **Think about what controls where the reply actually goes.** The
   `REQUEST_FLAG` handler doesn't care who's "really" at
   `10.0.0.10` — it just trusts whatever the ARP table currently
   says. What happens if you change that before asking?

3. **Claim to be admin.** Pick any MAC address string you like for
   yourself, announce it for `10.0.0.10`, and see where the next
   `REQUEST_FLAG`'s reply lands.

## Tools you'll need

| Tool | Why |
|---|---|
| Python `socket` (or `nc`) | Send `ARP_REPLY`/`REQUEST_FLAG`/`READ_MAILBOX` and read the responses |

**Don't ask what MAC address to claim.** Any string you like works —
the table doesn't validate MAC format or check it against a real
network interface, because there isn't one; this is a simulation. If
you're stuck for more than 15 minutes, come back with exactly what
you tried.

## Defender role

Once you have the flag, think about how to fix `src/lan_sim.py`
without losing the ability for admin to legitimately receive
fileserver's replies:

- A real fix usually isn't "reject all ARP replies" (unsolicited
  gratuitous ARP has legitimate uses, like announcing a MAC change
  after a NIC swap) — it's validating that a reply corresponds to an
  actual outstanding request, or using a static/pinned mapping for
  sensitive hosts that refuses to be overwritten at all once set.
- Real-world mitigations for this exact class of bug include **Dynamic
  ARP Inspection** (switches that only trust ARP replies consistent
  with a DHCP-observed binding) and static ARP entries for critical
  infrastructure (gateways, file servers) that software refuses to
  update from the network at all.

After patching, redeploy and confirm that an `ARP_REPLY` for
`10.0.0.10` claiming a different MAC no longer redirects
`REQUEST_FLAG`'s reply away from the real admin host.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique stays exactly the same; only
the flag text rotates. Submit whatever you currently extract; stale
ones expire.

## Where this sits in the Network Protocols ladder

`net-protocol-fuzzing` (rung 8) → **`net-arp-spoof-sim` (rung 9)** →
`net-c2-beacon-analysis` (rung 10). See `main.md` for the full ladder.
