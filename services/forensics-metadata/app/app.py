"""
forensics-metadata: the flag isn't in the picture -- it's in the
metadata that rides along *with* the picture.

The service serves a perfectly ordinary-looking PNG product photo.
Opening it in any image viewer shows nothing but a plain colored
graphic. The flag is stored as a PNG text metadata chunk (the same
mechanism real cameras, phones and editing tools use to embed EXIF-
style fields like camera model, GPS coordinates, author, or editing
software) under an innocuous-sounding key, sitting right alongside a
handful of decoy metadata fields that look far more "interesting" at
a glance.

This is a direct analogue of real incidents where sensitive data
(internal usernames, file paths, GPS location, author identity) leaked
to the public purely through metadata nobody stripped before
publishing a file.
"""
import io
import os
import random

from flask import Flask, Response, render_template_string
from PIL import Image
from PIL.PngImagePlugin import PngInfo

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_image() -> bytes:
    flag = read_current_flag()
    rng = random.Random(42)

    # A plain, boring product-photo-style graphic. Nothing is hidden in
    # the pixels themselves -- this is NOT a steganography challenge.
    img = Image.new("RGB", (480, 320), (235, 235, 230))
    pixels = img.load()
    for _ in range(600):
        x = rng.randint(0, 479)
        y = rng.randint(0, 319)
        shade = rng.randint(180, 220)
        pixels[x, y] = (shade, shade, shade)

    meta = PngInfo()
    # Decoy fields, the kind a real camera/editor actually writes.
    meta.add_text("Software", "PhotoSuite Pro 14.2")
    meta.add_text("Author", "marketing-team")
    meta.add_text("Description", "Q3 product catalog - item 4417")
    meta.add_text("Copyright", "Internal use only")
    meta.add_text("DateCreated", "2026-06-14T09:12:03")
    # The field nobody remembered to scrub before this went out the
    # door: an internal review comment that still has the flag in it.
    meta.add_text("ReviewerNote", f"approved for release -- ticket ref {flag}")

    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=meta)
    return buf.getvalue()


INDEX_PAGE = """
<!doctype html>
<title>Catalog Asset Download</title>
<h2>Marketing Asset Portal</h2>
<p>Product photo for catalog item 4417.</p>
<p><a href="/photo.png">Download photo.png</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/photo.png")
def photo():
    data = build_image()
    return Response(data, mimetype="image/png",
                     headers={"Content-Disposition": "attachment; filename=photo.png"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
