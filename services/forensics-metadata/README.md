# Challenge 7: forensics-metadata (Flag Hidden in File Metadata)

A tiny "marketing asset portal" serving a product photo for a catalog
listing. Open `photo.png` in any image viewer and you'll see a plain,
boring gray graphic — nothing is hidden in the pixels. This is **not**
a steganography challenge (see `forensics-stego` for that). The flag
lives somewhere else entirely: the file's own metadata.

## Running it

Standalone:

```bash
cd services/forensics-metadata
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-metadata
```

Then open `http://localhost:9006/` and download `photo.png`.

## Background

Every image format can carry metadata alongside the actual pixel
data — EXIF fields in JPEGs, text chunks in PNGs, document properties
in Office files and PDFs. Cameras, phones and editing software write
dozens of these fields automatically: software version, author,
timestamps, descriptions, sometimes even internal notes nobody meant
to publish. This has caused real leaks before: internal file paths,
usernames, GPS coordinates and review comments have all gone out the
door inside "harmless" image files because nobody thought to check
what metadata was riding along with them.

## What you need to work out

1. **The flag is not in the image.** Don't bother with stego tools,
   bit-plane viewers, or anything pixel-related — you'll find nothing.
2. **Inspect the file's metadata.** PNG files can carry arbitrary
   text metadata chunks. Several tools can show you every chunk a PNG
   file carries, including fields a normal image viewer never
   displays.
3. **There are several metadata fields.** Most of them are decoys
   that look like ordinary camera/editor boilerplate. Read through
   all of them — one holds something that isn't boilerplate at all.

## Tools you'll need

| Tool | Why |
|---|---|
| `exiftool photo.png` | Dumps every metadata field a file carries, including PNG text chunks |
| `python3` + Pillow (`Image.open(...).text`) | Reads PNG text chunks programmatically if you don't have exiftool |
| `strings photo.png` | Works in a pinch — PNG text chunks are stored as plain ASCII/Latin-1 |

**Don't ask which field has the flag.** Any of the three tools above
lists every field in the file in one shot — read through all of them.
If you're stuck for more than 15 minutes, come back with what the
metadata dump showed you.

## Defender role

This is a forensics/analysis exercise rather than a traditional
server-side bug — there's no injection or overflow here, just a data
leak through metadata. The relevant defensive takeaway:

- **Strip metadata before publishing files.** Tools like `exiftool
  -all=` or re-encoding an image before release remove exactly this
  kind of accidental leak.
- **Never put sensitive information in "soft" fields** like
  descriptions, comments or author tags, on the assumption nobody
  looks there — metadata is exactly as readable as the file itself to
  anyone who downloads it.
- **Review what automated tooling writes.** Editing software, cameras
  and CI pipelines often embed far more metadata than anyone intended
  (build paths, internal usernames, ticket references); an automated
  metadata-stripping step in the publishing pipeline closes this for
  good.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a freshly generated `photo.png` (with the
current flag embedded in its `ReviewerNote` metadata field) is
produced on every download — the extraction technique stays exactly
the same; only the flag text rotates. Submit whatever you currently
extract; stale ones expire.

## Where this sits in the Digital Forensics ladder

`forensics-log-analysis` (rung 6) → **`forensics-metadata` (rung 7)**
→ `forensics-timeline` (rung 8). See `main.md` for the full ladder.
