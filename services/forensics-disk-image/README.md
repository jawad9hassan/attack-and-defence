# Challenge 5: forensics-disk-image (Deleted File Recovery)

A small, fabricated "disk image" — not a real FAT/NTFS/ext4
filesystem, since no real disk-forensics tool (Autopsy, `TestDisk`,
etc.) would know how to parse this custom format — built to practice
the single most important idea in deleted-file recovery: **deleting a
file almost never erases its data.** It just marks the directory
entry as free. The bytes themselves stay exactly where they were
until something else happens to overwrite that space.

## Running it

Standalone:

```bash
cd services/forensics-disk-image
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-disk-image
```

Then open `http://localhost:9004/` and download `disk.img`.

## The format (not hidden from you — read it, that's the point)

Documented in full in `app/app.py`, but the short version:

```
magic: b"DISKIMG1"
entry_count: 4 bytes
entry_count directory entries, each 64 bytes:
    status: 1 byte     (0x00 = active, 0xE5 = deleted)
    name: 32 bytes, null-padded
    data_offset: 4 bytes
    data_length: 4 bytes
    (padding)
data region: every file's raw bytes, back to back, at the recorded offsets
```

This `0x00` / `0xE5` convention is exactly what real FAT filesystems
use for "this entry is free" — it's a genuine, widely-documented
forensic detail, not something invented for this challenge.

## What you need to work out

1. **Parse the directory table.** Read the magic, the entry count,
   then walk `entry_count` fixed-size 64-byte records. For each one,
   pull out the status byte, the name, and the `(offset, length)`
   pair describing where its data lives.

2. **Find the one entry marked deleted** (`status == 0xE5`). Its
   name still tells you what the file was called.

3. **Its data never went anywhere.** The directory entry being marked
   "deleted" says nothing about whether the bytes at its recorded
   offset and length are still intact — read them from the data
   region exactly the way you would for any active file.

## Tools you'll need

| Tool | Why |
|---|---|
| Python, reading the file in binary mode (`struct` for the fixed-width fields) | Parse the directory table and pull out each entry's offset/length |

**Don't ask which entry is deleted or where its data sits.** Walking
the directory table yourself and checking each entry's status byte
is the actual skill — it's a handful of lines of Python. If you're
stuck for more than 20 minutes, come back with exactly what you
tried.

## Defender role

This is a forensics/analysis exercise — there's no server-side bug to
patch (the "vulnerability" is a property of how most real filesystems
work, not a flaw introduced by this challenge). The relevant takeaway
for a defender:

- If sensitive data genuinely needs to be gone, deleting the file
  (even "emptying the recycle bin") is not enough — the data is
  still recoverable with basic tools until it's overwritten, which
  can take a long time on a lightly-used drive or SSD.
- Secure deletion requires either overwriting the freed space
  (multiple-pass wipe tools, `shred`, full-disk encryption with key
  destruction) or using an encrypted filesystem from the start, where
  "deleting the key" makes the data unrecoverable without needing to
  touch every block that ever held it.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a fresh image (with the flag embedded in
the deleted file's data region) is generated on every download — the
analysis technique stays exactly the same; only the flag text rotates.
Submit whatever you currently extract; stale ones expire.

## Where this sits in the Digital Forensics ladder

`forensics-memory-dump` (rung 4) → **`forensics-disk-image` (rung 5)**
→ `forensics-log-analysis` (rung 6). See `main.md` for the full
ladder.
