"""
forensics-memory-dump: a tiny, fabricated "memory dump" (not a real
Windows/Linux memory image, no Volatility-compatible structures --
just a simple custom binary format with process-sized chunks) built
to practice the most basic memory-forensics workflow: pull a process
list out of a dump, notice ONE process whose name doesn't look right,
and find the flag sitting in that process's own memory region.

File format (entirely custom, documented here since there's no real
memory-forensics tool that understands it):

    for each process:
        b"PROC:" + pid (4 bytes, little-endian) +
        name (32 bytes, null-padded ASCII) +
        size (4 bytes, little-endian) +
        <size> bytes of that process's "memory"

The flag sits inside ONE process's memory region -- the one with a
typosquatted name (svch0st.exe, a zero instead of the letter O; a
very real malware-naming trick used to blend in with legitimate
system processes like svchost.exe in a quick glance).
"""
import os
import random
import struct
import sys

from flask import Flask, Response, render_template_string

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

PROCESSES = [
    (1004, "svchost.exe"),
    (2048, "explorer.exe"),
    (3112, "chrome.exe"),
    (4096, "svch0st.exe"),   # the typosquatted impostor -- zero, not the letter O
    (5201, "spoolsv.exe"),
]


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_dump() -> bytes:
    flag = read_current_flag()
    rng = random.Random(4242)
    out = bytearray()
    for pid, name in PROCESSES:
        name_field = name.encode().ljust(32, b"\x00")
        if name == "svch0st.exe":
            # pad the flag with harmless noise on both sides, like any
            # other scrap of leftover process memory would be
            region = rng.randbytes(96) + flag.encode() + rng.randbytes(160)
        else:
            region = rng.randbytes(256)
        out += b"PROC:" + struct.pack("<I", pid) + name_field + struct.pack("<I", len(region)) + region
    return bytes(out)


INDEX_PAGE = """
<!doctype html>
<title>Incident Response - Memory Capture</title>
<h2>Incident Response: Workstation Memory Capture</h2>
<p>A quick RAM capture was taken from a workstation flagged by
endpoint monitoring. It's a small, simplified dump -- a handful of
running processes, each with a chunk of their own memory attached.</p>
<p><a href="/memory.dmp">Download memory.dmp</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/memory.dmp")
def dump():
    data = build_dump()
    return Response(data, mimetype="application/octet-stream",
                     headers={"Content-Disposition": "attachment; filename=memory.dmp"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
