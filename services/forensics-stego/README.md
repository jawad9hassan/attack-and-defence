# Challenge 11: Totally Normal Image Gallery (Digital Forensics / Steganography)

A new category on this platform: **digital forensics** — specifically,
**steganography** (hiding data inside other data). A tiny "image
gallery" page serves one PNG image. Nothing about the page says so, but
today's flag is hidden inside the image's pixel data.

This is the first challenge of this category on the platform; there's
no ladder yet (see the main index for how new rungs get added over
time).

## Running it

Standalone:

```bash
cd services/forensics-stego
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build forensics-stego   # from the repo root
```

Then open `http://localhost:5004`.

## Background: what LSB steganography is

An image file stores a number (0-255) for each of the red, green and
blue channels of every pixel. Changing the **least significant bit**
(the "ones place" in binary) of a color value changes that color by at
most 1 out of 256 — completely invisible to the human eye, but
perfectly readable by a program that knows to look at just that one bit
per pixel.

That's the entire trick here: data is hidden one bit at a time, across
the least-significant bit of the red channel of consecutive pixels, in
plain row-major order (left to right, top to bottom, same order
`Image.getdata()` gives you in Python's Pillow library).

## What you need to work out

### Suggested analysis steps

1. Download the image:
   ```bash
   curl -o image.png http://localhost:5004/download
   ```
2. Open it with Pillow (`pip install Pillow` if you don't have it) and
   look at its pixel data:
   ```python
   from PIL import Image
   img = Image.open("image.png")
   pixels = list(img.getdata())
   print(pixels[:10])  # first 10 (r, g, b) tuples
   ```
3. For each pixel, extract just the least-significant bit of the **red**
   value (`r & 1`). You now have a long sequence of 0s and 1s.
4. Group those bits into bytes, 8 at a time, most-significant-bit first.
5. **The first 16 bits (2 bytes) are special** — they're a length
   header telling you how many bytes of real payload follow. Read those
   first 2 bytes as a big-endian integer; that's your payload length in
   bytes.
6. Take exactly that many bytes right after the length header, and
   decode them as text.

**Don't ask for a ready extraction script.** You have the exact bit
order, the channel used, and the length-prefix format above — writing a
short Python script (under 20 lines) to turn that into working code is
the exercise. If you're stuck for more than 20-30 minutes, tell me
exactly what your script's intermediate output looks like (the raw bit
list, or the decoded length header) and you'll get a sharper hint.

## Defender role

There's no single "vulnerable line" to patch here the way there is in
the injection challenges — the whole service exists to demonstrate the
technique. As a team discussion:

- What would make this harder to detect? (Spreading bits across a
  pseudo-random subset of pixels instead of the first N in order, using
  a keyed selection the defender controls, is one real technique —
  though note it raises the bar, it still doesn't make the data
  genuinely *secret* without actual encryption on top.)
- Why is "nobody will think to look" (security through obscurity) never
  a real substitute for encryption, if the goal is to keep the flag
  secret rather than just mildly hidden?

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd`. The cover image's visible pattern looks identical
every round (it's generated from a fixed seed) — only the hidden payload
changes, so your extraction script works unmodified across rounds; just
re-download and re-run it each round.
