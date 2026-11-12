#!/usr/bin/env python3
"""
crypto-padding-oracle: a CBC-mode "decrypt and check the padding"
service with a classic Padding Oracle vulnerability.

No AES library is used (kept dependency-free, see main.md's design
notes). The underlying "block cipher" is a random, secret, invertible
byte substitution table (an S-box) generated once at startup -- the
attack below works against ANY invertible block cipher wrapped in CBC
mode this way, including real AES, because the padding-oracle attack
never has to learn or invert the block cipher itself. It only needs to
know, for a ciphertext block it can freely tamper with, whether the
decrypted PKCS#7 padding came out valid or not.

Protocol (plain text over TCP):

    On connect, the service sends one line:
        COOKIE: <hex of IV || ciphertext>
    which decrypts (under the server's secret key) to the current
    flag, PKCS#7 padded. That's the target.

    Then it loops, reading lines of HEX (IV || ciphertext) from you and
    replying with exactly one of:
        GOOD PADDING
        BAD PADDING
    depending on whether CBC-decrypting what you sent ends in valid
    PKCS#7 padding. It never shows you any decrypted bytes directly --
    only that single bit per request. That one bit, repeated across a
    few thousand requests, is enough to decrypt the whole cookie
    without ever learning the key.
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
BLOCK_SIZE = 16


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


# --- A secret, invertible, keyed byte substitution -- our dependency-
# free stand-in for "a block cipher". The padding-oracle attack below
# never needs to know this table; it only needs valid/invalid padding
# feedback after CBC decryption. ------------------------------------------
_rng_seed = secrets.token_bytes(32)
_sbox = list(range(256))
_r = secrets.SystemRandom()
_r.seed(_rng_seed)
_r.shuffle(_sbox)
SBOX = bytes(_sbox)
INV_SBOX = bytearray(256)
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
INV_SBOX = bytes(INV_SBOX)


def block_encrypt(block: bytes) -> bytes:
    return bytes(SBOX[b] for b in block)


def block_decrypt(block: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in block)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad_check(data: bytes) -> bool:
    """Returns True iff `data` ends in valid PKCS#7 padding."""
    if not data:
        return False
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE or pad_len > len(data):
        return False
    return data[-pad_len:] == bytes([pad_len]) * pad_len


def cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        ct = block_encrypt(xor_bytes(block, prev))
        out += ct
        prev = ct
    return bytes(out)


def cbc_decrypt_check_padding(iv_and_ct: bytes) -> bool:
    """CBC-decrypts iv_and_ct = IV || ciphertext and returns whether the
    result has valid PKCS#7 padding. Never returns the plaintext."""
    if len(iv_and_ct) < 2 * BLOCK_SIZE or len(iv_and_ct) % BLOCK_SIZE != 0:
        return False
    iv, ct = iv_and_ct[:BLOCK_SIZE], iv_and_ct[BLOCK_SIZE:]
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), BLOCK_SIZE):
        block = ct[i:i + BLOCK_SIZE]
        pt = xor_bytes(block_decrypt(block), prev)
        out += pt
        prev = block
    return pkcs7_unpad_check(bytes(out))


def make_cookie() -> bytes:
    iv = secrets.token_bytes(BLOCK_SIZE)
    ct = cbc_encrypt(read_current_flag(), iv)
    return iv + ct


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        cookie = make_cookie()
        self.wfile.write(b"COOKIE: " + cookie.hex().encode() + b"\n")
        self.wfile.write(
            b"Send hex (IV||ciphertext); I reply GOOD PADDING or BAD "
            b"PADDING. No plaintext is ever shown.\n"
        )
        while True:
            line = self.rfile.readline()
            if not line:
                return
            line = line.strip()
            try:
                blob = bytes.fromhex(line.decode())
            except ValueError:
                self.wfile.write(b"ERROR: not valid hex\n")
                continue
            if len(blob) > 4096:
                self.wfile.write(b"ERROR: too long\n")
                continue
            ok = cbc_decrypt_check_padding(blob)
            self.wfile.write((b"GOOD PADDING\n" if ok else b"BAD PADDING\n"))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9800"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"padding-oracle listening on 0.0.0.0:{port}")
        server.serve_forever()
