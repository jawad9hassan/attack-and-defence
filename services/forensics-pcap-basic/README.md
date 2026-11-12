# Challenge: Legacy Monitor Capture (Digital Forensics, ladder rung 1 of 3)

The easiest challenge in the Digital Forensics category, and arguably
the easiest challenge on the whole platform. A tiny web page offers one
download: a network capture (`.pcap`) someone forgot to turn off on an
old internal monitoring box.

There is nothing to decode here. The flag is sitting in a request body,
in plain text, because the tool that made this capture talks plain HTTP
instead of HTTPS — a genuinely common finding on internal/legacy
networks in real security assessments.

## Running it

Standalone:

```bash
cd services/forensics-pcap-basic
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build forensics-pcap-basic   # from the repo root
```

Then open `http://localhost:9000`.

## Attacker role

1. Download the capture:
   ```bash
   curl -o capture.pcap http://localhost:9000/capture.pcap
   ```
2. Open it in Wireshark, find the `POST` packet, and either look at its
   payload directly in the packet details pane, or right-click it →
   **Follow → TCP Stream** to see the whole plaintext exchange at once.
3. No Wireshark handy? This capture is plaintext, so even
   `strings capture.pcap | grep FLAG` finds it. That's the point: this
   is what "no encryption at all" looks like on the wire.

## Defender role

The fix isn't really about this specific tool — it's the general
lesson: **never send anything sensitive over plain HTTP.** In a real
environment, the fix is forcing the legacy tool onto HTTPS (or, more
realistically, decommissioning it, since "it's internal-only so it's
fine" is exactly the assumption that gets broken the moment an attacker
is already on the internal network).

## Flag rotation

Every round, the capture is rebuilt from scratch with the current flag,
so re-downloading `capture.pcap` each round gets you the current value.

## What's next in this ladder

- `forensics-stego` (rung 2) — the flag is still just raw bytes, but
  now hidden inside an image's pixels instead of sitting in a plaintext
  request.
- `forensics-pcap-ftp` (rung 3) — a capture with more than one
  conversation in it; you have to find the right one.
