# Challenge 4: forensics-memory-dump (Basic Memory Forensics)

A small, simplified "memory capture" from a workstation flagged by
endpoint monitoring. It's not a real Windows/Linux memory image (no
Volatility plugin will understand it) — it's a tiny custom format with
one chunk per running process, each carrying a slice of that
process's own memory.

## Running it

Standalone:

```bash
cd services/forensics-memory-dump
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-memory-dump
```

Then open `http://localhost:9003/` and download `memory.dmp`.

## What's in the file

The format, documented here since no real tool knows it:

```
for each process:
    b"PROC:" + pid (4 bytes) + name (32 bytes, null-padded) +
    size (4 bytes) + <size> bytes of that process's memory
```

Several processes are in the dump. Most of them have perfectly normal
Windows process names.

## What you need to work out

1. **Pull a process list out of the dump.** Even without parsing the
   binary structure properly, a plain text-extraction tool will show
   you every process name in the file (they're stored as plain ASCII).

2. **Look closely at each name.** Real incident response starts here:
   comparing what's running against what *should* be running. Does
   anything look almost-but-not-quite like a legitimate Windows
   process name?

3. **Once you've spotted the impostor**, the flag is sitting
   somewhere in the raw bytes of the file — the same basic text-
   extraction approach that found the process names will find it too.

## Tools you'll need

| Tool | Why |
|---|---|
| `strings` (or Python, reading the file as bytes) | Pull every printable chunk of text out of the dump, process names and flag included |

**Don't ask which process name is the fake one.** Look at the list
yourself and compare it, letter by letter if you have to, against
what you'd expect a real Windows process to be called. This is
exactly the "wait, that's not quite right" moment real malware
analysts rely on. If you're stuck for more than 15 minutes, come back
with the process names you found.

## Defender role

This is a forensics/analysis exercise — there's no server-side bug to
patch (the "vulnerability" is that a process impersonating a system
process exists on the machine, not a bug in how this page serves the
dump). The relevant defensive skill is detection and response:

- A real EDR tool would flag `svch0st.exe` (zero instead of the
  letter O) automatically by comparing running process names and
  paths against a known-good baseline — typosquatted process names
  are a well-documented, very real malware persistence trick.
- The appropriate response to finding this in a real incident is
  isolating the host, capturing a proper forensic image (not just a
  quick triage dump like this one), and checking whether the
  impostor process has persistence mechanisms (scheduled tasks,
  registry run keys, services) elsewhere on the system.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a fresh dump (with the flag embedded in
the impostor process's memory region) is generated on every download —
the analysis technique stays exactly the same; only the flag text
rotates. Submit whatever you currently extract; stale ones expire.

## Where this sits in the Digital Forensics ladder

`forensics-pcap-ftp` (rung 3) → **`forensics-memory-dump` (rung 4)** →
`forensics-disk-image` (rung 5). See `main.md` for the full ladder.
