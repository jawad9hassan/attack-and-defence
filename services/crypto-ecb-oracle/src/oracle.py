#!/usr/bin/env python3
"""
crypto-ecb-oracle: an "encrypt anything you want, as long as the flag
gets appended to it" oracle, built on a block cipher operating in ECB
mode -- the mode where every 16-byte block is scrambled completely
independently of every other block.

This service does not use AES (no heavy crypto dependency on this
dependency-free platform -- see main.md's design notes). Instead it
uses a small toy "block scrambler": each 16-byte block is run through
SHA-256 keyed with a secret, deterministically producing a different-
looking 16-byte output for different input -- i.e. a one-way,
non-invertible stand-in for "encrypt this block with a secret key".
This is intentional and does not weaken the lesson: the bug being
taught is a property of ECB MODE itself (same plaintext block always
maps to the same ciphertext block), not of any particular cipher's
internals -- real AES-ECB has exactly the same flaw, and the classic
"byte-at-a-time ECB decryption" attack never needs to invert or crack
the underlying cipher at all, only to notice when two ciphertext blocks
are byte-for-byte identical.

Protocol (plain text over TCP, one request per line, many lines per
connection):

    Connect, then send a line of HEX-encoded bytes. The service
    appends the current flag to whatever you sent, pads it to a
    multiple of 16 bytes (PKCS#7), encrypts it block-by-block in ECB
    mode, and replies with one line of HEX-encoded ciphertext. Repeat
    as many times as you like on the same connection.

The flag is always appended AFTER your input, never before -- exactly
the "secret suffix" setup of the classic exercise.
"""
import hashlib
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
BLOCK_SIZE = 16

KEY = secrets.token_bytes(32)  # fixed for the life of this process


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def encrypt_block(block: bytes) -> bytes:
    """Toy one-way block scrambler. Deterministic in `block` (and the
    fixed secret KEY) -- exactly the property real ECB-mode AES has
    that this challenge is about: identical input blocks ALWAYS
    produce identical output blocks."""
    return hashlib.sha256(KEY + block).digest()[:BLOCK_SIZE]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def ecb_encrypt(data: bytes) -> bytes:
    padded = pkcs7_pad(data)
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out += encrypt_block(padded[i:i + BLOCK_SIZE])
    return bytes(out)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            b"ECB encryption oracle. Send hex bytes; your input is "
            b"prepended to a secret suffix, padded, and encrypted in "
            b"ECB mode. Reply is hex ciphertext. One line in, one line "
            b"out, reuse the connection.\n"
        )
        while True:
            line = self.rfile.readline()
            if not line:
                return
            line = line.strip()
            try:
                user_bytes = bytes.fromhex(line.decode())
            except ValueError:
                self.wfile.write(b"ERROR: not valid hex\n")
                continue
            if len(user_bytes) > 4096:
                self.wfile.write(b"ERROR: input too long\n")
                continue
            plaintext = user_bytes + read_current_flag()
            ciphertext = ecb_encrypt(plaintext)
            self.wfile.write(ciphertext.hex().encode() + b"\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9700"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"ecb-oracle listening on 0.0.0.0:{port}")
        server.serve_forever()
