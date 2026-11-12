#!/usr/bin/env python3
"""
crypto-encoding: today's flag, run through a few layers of plain
ENCODING (not encryption -- no key, no secret, nothing to break). Every
layer is a standard, well-known, reversible transformation. The whole
point of this challenge is recognizing which encodings are stacked and
in what order, and peeling them back one at a time.

Protocol (plain text over TCP):

    Connect, and the service immediately sends the puzzle blob, then
    closes the connection. There's nothing to send it -- just connect
    and read.

This is intentionally the EASIEST crypto challenge on the platform
(crypto-xor, which actually involves breaking a cryptographic weakness,
is the next step up). This one is about encoding literacy: recognizing
hex, Base64, and a reversed string by sight, and knowing which Python/
CLI tool undoes each one.
"""
import base64
import os
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def encode_layers(flag: bytes) -> str:
    # Layer 1 (innermost): hex-encode the raw flag bytes.
    hex_layer = flag.hex()
    # Layer 2: base64-encode that hex string.
    b64_layer = base64.b64encode(hex_layer.encode()).decode()
    # Layer 3 (outermost): reverse the whole string.
    reversed_layer = b64_layer[::-1]
    return reversed_layer


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        blob = encode_layers(read_current_flag())
        self.wfile.write(
            b"=== Today's Encoding Puzzle ===\n"
            b"Someone ran the flag through a few layers of encoding before\n"
            b"posting it here. Peel them back, one at a time.\n\n"
            + blob.encode()
            + b"\n"
        )


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("PUZZLE_PORT", "9100"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"encoding puzzle listening on 0.0.0.0:{port}")
        server.serve_forever()
