#!/usr/bin/env python3
"""
crypto-nonce-reuse: a stream-cipher "secure messaging" oracle with a
classic Nonce Reuse vulnerability -- the same bug class that breaks
real AES-GCM/ChaCha20-Poly1305 the moment a nonce is ever reused with
the same key.

No AES/ChaCha library is used (dependency-free, see main.md's design
notes). Instead this is a small counter-mode stream cipher built from
HMAC-SHA256 as a keyed PRF:

    keystream_block(nonce, counter) = HMAC-SHA256(key, nonce || counter)[:16]
    ciphertext = plaintext XOR (keystream_block(nonce, 0) ||
                                 keystream_block(nonce, 1) || ...)

This is structurally identical, for the purposes of this bug, to real
counter-mode AES/ChaCha: the security of EVERY stream cipher used this
way depends entirely on never reusing the same (key, nonce) pair for
two different messages. This service reuses the exact same fixed nonce
for every single message it ever encrypts -- the flag included.

Protocol (plain text over TCP):

    On connect, the service sends:
        FLAG_CIPHERTEXT: <hex>
    (the current flag, encrypted under THIS process's one fixed,
    reused nonce). Then it loops: send a line of hex plaintext, get
    back a line of hex ciphertext -- encrypted under that SAME nonce.
"""
import hashlib
import hmac
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
BLOCK_SIZE = 16

KEY = secrets.token_bytes(32)

# --- THE BUG: one nonce, generated once, reused for EVERY message
# this process ever encrypts -- including the flag. A correct
# implementation generates a brand-new random nonce per message. ------
NONCE = secrets.token_bytes(16)
# -------------------------------------------------------------------------


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def keystream(nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(KEY, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()[:BLOCK_SIZE]
        out += block
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext: bytes, nonce: bytes = NONCE) -> bytes:
    ks = keystream(nonce, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        flag_ct = encrypt(read_current_flag())
        self.wfile.write(b"FLAG_CIPHERTEXT: " + flag_ct.hex().encode() + b"\n")
        self.wfile.write(
            b"Send hex plaintext to encrypt (same session nonce every "
            b"time). Reply is hex ciphertext.\n"
        )
        while True:
            line = self.rfile.readline()
            if not line:
                return
            line = line.strip()
            try:
                pt = bytes.fromhex(line.decode())
            except ValueError:
                self.wfile.write(b"ERROR: not valid hex\n")
                continue
            if len(pt) > 4096:
                self.wfile.write(b"ERROR: too long\n")
                continue
            ct = encrypt(pt)
            self.wfile.write(ct.hex().encode() + b"\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9900"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"nonce-reuse oracle listening on 0.0.0.0:{port}")
        server.serve_forever()
