"""
forensics-stego: a tiny HTTP service that serves a PNG image with
today's flag hidden inside it via LSB (least-significant-bit)
steganography -- a real digital-forensics / stego skill, distinct from
every other category on this platform (web, binary, crypto, network).

The image itself is regenerated on every request from a fixed-seed
pattern (so re-downloading gives the same cover image each round, only
the hidden payload changes), with the CURRENT flag's bytes hidden across
the least-significant bit of each red-channel pixel value, in simple
row-major order:

    [2-byte big-endian length][flag bytes], one bit per pixel's red
    channel, most-significant-bit of each byte first.

There's no password, no key, no encryption -- the "secret" is entirely
in knowing HOW the data is hidden and being able to write a short
script to extract it. This is intentionally a different skill from
crypto-encoding (which is about recognizing stacked text encodings):
here, the hidden data lives inside the pixel values of an image file,
not in the text you can see.
"""
import io
import os
import random

from flask import Flask, Response, render_template_string
from PIL import Image

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

WIDTH, HEIGHT = 200, 200
COVER_SEED = 1337  # fixed, so the cover pattern looks the same every round


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def make_cover_pixels():
    """A deterministic pseudo-random cover image, same every round."""
    rng = random.Random(COVER_SEED)
    pixels = []
    for _ in range(WIDTH * HEIGHT):
        pixels.append((rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)))
    return pixels


def embed_flag(pixels, flag: bytes):
    payload = len(flag).to_bytes(2, "big") + flag
    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    if len(bits) > len(pixels):
        raise ValueError("flag too long to embed in this cover image")

    new_pixels = list(pixels)
    for i, bit in enumerate(bits):
        r, g, b = new_pixels[i]
        r = (r & 0xFE) | bit  # clear the LSB, set it to our bit
        new_pixels[i] = (r, g, b)
    return new_pixels


def build_png_bytes() -> bytes:
    pixels = make_cover_pixels()
    pixels = embed_flag(pixels, read_current_flag())

    img = Image.new("RGB", (WIDTH, HEIGHT))
    img.putdata(pixels)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


INDEX_PAGE = """
<!doctype html>
<title>Totally Normal Image Gallery</title>
<h2>Totally Normal Image Gallery</h2>
<p>Here's today's featured image. Nothing unusual about it at all.</p>
<p><img src="/download" alt="featured"></p>
<p><a href="/download">Download the raw PNG</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/download")
def download():
    data = build_png_bytes()
    return Response(data, mimetype="image/png")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
