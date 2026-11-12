#!/usr/bin/env python3
"""
crypto-xor: a tiny "encryption oracle" demonstrating why a repeating XOR
key (a two-time pad) is broken the moment it's reused.

Protocol (plain text over TCP, one command per line):

    GETFLAG           -> "CIPHERTEXT: <hex>" (the flag, XORed with the key)
    ENC <hex bytes>    -> "CIPHERTEXT: <hex>" (your own bytes, XORed with
                           the SAME key, at the SAME starting position)

The key is a fixed-length random byte string, generated once at startup
and reused for every connection and every command until the service is
restarted. That reuse is the entire vulnerability: XOR is only secure as
a one-time pad — reusing the same key (keystream) for two different
messages always leaks information, and if you can get the oracle to XOR
a message of your choosing, you can recover the key outright.
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
KEY_LEN = 64

# Generated once per process start. Deliberately NOT tied to flagd / the
# checker: only the flag rotates each round, to keep this challenge
# focused on the crypto bug rather than operational plumbing.
KEY = secrets.token_bytes(KEY_LEN)


def read_current_flag():
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def xor_with_key(data: bytes) -> bytes:
    return bytes(b ^ KEY[i % KEY_LEN] for i, b in enumerate(data))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            b"=== XOR Encryption Oracle ===\n"
            b"Commands:\n"
            b"  GETFLAG            - get the encrypted flag\n"
            b"  ENC <hex bytes>    - encrypt your own data with the same key\n"
            b"> "
        )
        self.wfile.flush()

        line = self.rfile.readline(4096).strip()
        if line == b"GETFLAG":
            ct = xor_with_key(read_current_flag())
            self.wfile.write(b"CIPHERTEXT: " + ct.hex().encode() + b"\n")
        elif line.startswith(b"ENC "):
            hex_arg = line[4:].strip()
            try:
                plaintext = bytes.fromhex(hex_arg.decode())
            except ValueError:
                self.wfile.write(b"ERROR: not valid hex\n")
                return
            if len(plaintext) > 4096:
                self.wfile.write(b"ERROR: too long\n")
                return
            ct = xor_with_key(plaintext)
            self.wfile.write(b"CIPHERTEXT: " + ct.hex().encode() + b"\n")
        else:
            self.wfile.write(b"ERROR: unknown command\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9000"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"xor oracle listening on 0.0.0.0:{port}")
        server.serve_forever()
