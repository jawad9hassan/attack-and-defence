#!/usr/bin/env python3
"""
net-auth: a tiny "device admin console" over plain TCP, protected by a
username/password login. The REAL admin account has a long random
password nobody could guess. But the device also ships with a
vendor-default maintenance account still enabled -- a textbook case of
leaving default/weak credentials active in production.

This is the easiest challenge in the Network category: no injection,
no scripting, no forged tokens. Just try the kind of credentials that
show up on "most common default device logins" lists, same as a real
network security assessment would start with.

Protocol (plain text over TCP):

    Username: <you type this>
    Password: <you type this>

    -> "Access granted.\\n" + the flag, if the credentials match
    -> "Access denied.\\n" otherwise
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

# The "real" admin account: a strong, unguessable password generated
# once at startup. Nobody is meant to ever log in with this one.
REAL_ADMIN_USER = "admin"
REAL_ADMIN_PASS = secrets.token_hex(16)

# --- THE BUG: a vendor-default maintenance account, left enabled. ---
DEFAULT_CREDS = {
    "admin": "admin",
}
# ----------------------------------------------------------------------


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"=== NetGuard Device Admin Console ===\r\nUsername: ")
        self.wfile.flush()
        try:
            username = self.rfile.readline(256).decode("utf-8", errors="replace").strip()
        except Exception:
            return

        self.wfile.write(b"Password: ")
        self.wfile.flush()
        try:
            password = self.rfile.readline(256).decode("utf-8", errors="replace").strip()
        except Exception:
            return

        authenticated = (
            (username == REAL_ADMIN_USER and password == REAL_ADMIN_PASS)
            or DEFAULT_CREDS.get(username) == password
        )

        if authenticated:
            self.wfile.write(
                b"Access granted.\r\n" + read_current_flag().encode() + b"\r\n"
            )
        else:
            self.wfile.write(b"Access denied.\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("CONSOLE_PORT", "9400"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"net-auth console listening on 0.0.0.0:{port}")
        server.serve_forever()
