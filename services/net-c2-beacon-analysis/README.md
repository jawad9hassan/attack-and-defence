# Challenge 10: net-c2-beacon-analysis (Spotting a Beacon in a Capture)

A blue-team-flavored challenge. A workstation was reported "acting
weird," and before it got reimaged, IT pulled a short network capture.
Nothing in it is encrypted or hidden — the whole exercise is **finding
the one conversation that doesn't belong** among several that look
perfectly normal.

## Running it

Standalone:

```bash
cd services/net-c2-beacon-analysis
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-c2-beacon-analysis
```

Then open `http://localhost:8009/` and download `capture.pcap`.

## The scenario

The capture holds several HTTP-looking conversations from
`10.40.0.23` (the workstation) to a handful of different destinations.
Open it in Wireshark (or `tshark`) and you'll see ordinary-looking
requests to a few different IPs, each at different, irregular times —
exactly like someone clicking around a few websites: load a page, read
it for a while, click something else, get distracted, come back.

One destination doesn't fit that pattern.

## What you need to work out

Real command-and-control malware "checks in" with its controller on a
fixed schedule — every N seconds, like clockwork — because it's a
program, not a person idly browsing. A human's browsing habits are
bursty and irregular; a beacon's timing is suspiciously, mechanically
regular.

### Suggested analysis steps

1. **Open the capture and look at `Statistics → Conversations`** (or
   `Statistics → Endpoints`) in Wireshark. You'll see several distinct
   IP:port destinations the workstation talked to.

2. **For each destination, look at the time between connections.**
   Wireshark's packet list shows timestamps directly; you can also
   right-click a conversation and "Follow" it, or just eyeball the
   `Time` column for packets grouped by destination IP. Most
   destinations should show messy, random-looking gaps. One shouldn't.

3. **Once you've found the suspiciously regular destination**, follow
   that TCP stream (right-click → **Follow → TCP Stream** in
   Wireshark, or `tshark -r capture.pcap -q -z follow,tcp,ascii,<stream
   number>` on the command line). The server's response is in plain
   text.

## Tools you'll need

| Tool | Why |
|---|---|
| Wireshark (or `tshark`) | Open the capture, inspect conversations and timing, follow the suspicious stream |
| A packet-timing eye | The whole exercise is noticing "this one is too regular to be a person" |

**Don't ask which IP address is the beacon.** Compare the timing
patterns across destinations yourself — that comparison *is* the
skill this challenge is teaching. If you're stuck for more than 20-30
minutes, come back with what you've tried (e.g. "I found 4
destinations, here's the gap pattern for each one").

## Defender role

This is a blue-team exercise — there's no server-side code to patch
here, since the "vulnerability" is that the malware exists on the
workstation at all, not a bug in this web page. The relevant defensive
skill is detection, not patching:

- A real SOC would build this same kind of analysis into automated
  tooling: flag any destination whose inter-connection timing has
  unusually low variance (a real human's browsing timing is "noisy";
  a beacon's isn't), especially to an external IP the organization
  has no business relationship with.
- Other real-world tells worth knowing, even though this toy capture
  doesn't model all of them: identical payload sizes on every check-in,
  connections that happen even when the user isn't active on the
  machine, and destinations with no corresponding DNS lookup (if
  malware connects straight to an IP, skipping DNS, that's often
  another red flag).

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd`, and a fresh capture (with a newly timestamped
beacon, carrying the current flag) is generated on every download —
the analysis technique stays exactly the same; only the flag text
rotates. Submit whatever you currently extract; stale ones expire.

## Where this sits in the Network Protocols ladder

`net-arp-spoof-sim` (rung 9) → **`net-c2-beacon-analysis` (rung 10)**.
This is the last challenge in this category — see `main.md` for the
full ladder.
