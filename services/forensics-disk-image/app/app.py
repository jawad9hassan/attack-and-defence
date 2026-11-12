"""
forensics-disk-image: a tiny, fabricated "disk image" (not a real
FAT/NTFS/ext4 filesystem -- a simple custom format, documented here
since no real disk-forensics tool understands it) built to practice
the most basic deleted-file-recovery idea: deleting a file in most
real filesystems does NOT erase its actual data, it just marks the
directory entry as free/deleted. The bytes stay on disk until
something else happens to overwrite them.

File format:

    magic: b"DISKIMG1"
    entry_count: 4 bytes, little-endian
    entry_count directory entries, each exactly 64 bytes:
        status: 1 byte (0x00 = active file, 0xE5 = deleted --
                the same convention real FAT filesystems use)
        name: 32 bytes, null-padded ASCII
        data_offset: 4 bytes, little-endian (offset into the data
                region below)
        data_length: 4 bytes, little-endian
        padding: remaining bytes, zero
    data region: every file's raw bytes, back to back, at the
        offsets recorded above -- including the deleted file's. Its
        directory entry says it's gone; its actual data never moved.
"""
import os
import struct

from flask import Flask, Response, render_template_string

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

MAGIC = b"DISKIMG1"
ENTRY_SIZE = 64
STATUS_ACTIVE = 0x00
STATUS_DELETED = 0xE5


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_image() -> bytes:
    flag = read_current_flag()

    files = [
        (STATUS_ACTIVE, "report.docx", b"Quarterly report draft, nothing sensitive here.\n" * 3),
        (STATUS_ACTIVE, "notes.txt", b"Remember to renew the office plants' water schedule.\n"),
        (STATUS_DELETED, "secret.txt", f"Internal use only -- do not share.\n{flag}\n".encode()),
        (STATUS_ACTIVE, "budget.csv", b"item,cost\ncoffee,42\ndesks,1200\n"),
    ]

    data_region = bytearray()
    directory = bytearray()
    for status, name, content in files:
        offset = len(data_region)
        data_region += content
        entry = bytes([status]) + name.encode().ljust(32, b"\x00") + \
            struct.pack("<II", offset, len(content))
        entry = entry.ljust(ENTRY_SIZE, b"\x00")
        directory += entry

    header = MAGIC + struct.pack("<I", len(files))
    return bytes(header + directory + data_region)


INDEX_PAGE = """
<!doctype html>
<title>Evidence Locker - Disk Image</title>
<h2>Evidence Locker: USB Drive Image</h2>
<p>A USB drive seized during an investigation was imaged bit-for-bit.
It's a small, simplified image -- not a real filesystem, but it
behaves the same way a real one does when it comes to "deleted"
files.</p>
<p><a href="/disk.img">Download disk.img</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/disk.img")
def disk_image():
    data = build_image()
    return Response(data, mimetype="application/octet-stream",
                     headers={"Content-Disposition": "attachment; filename=disk.img"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
