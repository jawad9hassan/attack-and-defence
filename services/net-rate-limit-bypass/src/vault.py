#!/usr/bin/env python3
"""
net-rate-limit-bypass: a tiny "PIN vault" over plain TCP. Enter the
correct 4-digit PIN and get the flag. Only 3 wrong guesses allowed
per... "session" -- which is exactly the bug. The lockout counter lives
in the connection handler's own state, so it resets to zero the instant
you disconnect and reconnect. A real rate limiter has to track attempts
by something that survives across connections (an IP, an account, a
device fingerprint) -- this one doesn't track anything at all once you
hang up.

With only 10,000 possible 4-digit PINs and 3 free guesses every time
you reconnect, the "protection" adds essentially zero real-world cost
to a brute-force attack -- just reconnect ~3,334 times.

Protocol (plain text over TCP):

    PIN: <you type a 4-digit PIN>
    -> "Correct! <flag>" or "Incorrect." (up to 3 tries, then disconnect)
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
REAL_PIN = f"{secrets.randbelow(10000):04d}"
MAX_ATTEMPTS = 3


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"=== SecureVault PIN Terminal ===\r\n")
        for attempt in range(MAX_ATTEMPTS):
            self.wfile.write(b"PIN: ")
            self.wfile.flush()
            try:
                line = self.rfile.readline(16).decode("utf-8", errors="replace").strip()
            except Exception:
                return
            if line == REAL_PIN:
                self.wfile.write(f"Correct! {read_current_flag()}\r\n".encode())
                return
            self.wfile.write(b"Incorrect.\r\n")
        self.wfile.write(b"Too many attempts. Disconnecting.\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("VAULT_PORT", "9600"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"net-rate-limit-bypass vault listening on 0.0.0.0:{port}")
        server.serve_forever()
