#!/usr/bin/env python3
"""
crypto-timing: a token-check service with a classic Timing Side-
Channel in how it compares your guess to the real secret token.

The comparison is a naive, character-by-character loop that returns
(and therefore stops taking time) the INSTANT it finds a mismatching
character -- instead of always comparing every byte in constant time.
That means: the longer your guess's correct PREFIX is, the longer the
comparison takes to run, before it bails out on the first wrong byte.
Measuring response time, one character at a time, lets you recover the
whole secret without ever seeing it.

To keep this reliably exploitable over a real (if local) TCP
connection -- where network jitter would otherwise drown out a
nanosecond-scale timing difference on a single memcmp -- each matched
character adds a deliberately large, measurable delay
(`PER_CHAR_DELAY`, see below). This is a well-established technique for
making a timing side-channel exercise reproducible and fair in a
training environment (the real-world attack this teaches is exactly
the same shape, just measured in microseconds against a non-exaggerated
comparison -- the exaggerated delay here is a teaching aid, not a
different vulnerability).

Protocol (plain text over TCP, one request per line, many lines per
connection):

    Connect, then send a line containing your guess at the secret
    token (plain text, same charset/length as the real one -- see the
    README for the charset/length). The service replies "MATCH" (and
    the current flag) or "NO MATCH" after comparing it the vulnerable
    way. Timing each request's response is up to you.
"""
import os
import secrets
import socketserver
import string
import time

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
TOKEN_ALPHABET = string.ascii_lowercase + string.digits
TOKEN_LENGTH = 8
PER_CHAR_DELAY = float(os.environ.get("PER_CHAR_DELAY", "0.03"))

SECRET_TOKEN = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


# --- VULNERABLE: stops comparing (and therefore stops taking time) the
# instant it finds a mismatch, instead of always touching every byte in
# constant time regardless of where (or whether) a mismatch occurs. ----
def leaky_compare(guess: str, secret: str) -> bool:
    for i in range(len(secret)):
        if i >= len(guess) or guess[i] != secret[i]:
            return False
        time.sleep(PER_CHAR_DELAY)  # <-- the exploitable timing leak
    return len(guess) == len(secret)
# -------------------------------------------------------------------------


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            f"Guess the {TOKEN_LENGTH}-character token "
            f"(charset: a-z, 0-9). One guess per line.\n".encode()
        )
        while True:
            line = self.rfile.readline()
            if not line:
                return
            guess = line.strip().decode(errors="replace")[:64]
            if leaky_compare(guess, SECRET_TOKEN):
                self.wfile.write(f"MATCH. Flag: {read_current_flag()}\n".encode())
            else:
                self.wfile.write(b"NO MATCH\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9995"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"timing-oracle listening on 0.0.0.0:{port}")
        server.serve_forever()
