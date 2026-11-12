#!/usr/bin/env python3
"""
net-replay: the hardest challenge in the Network category. A tiny
"bank terminal" over plain TCP. Ordinary customers can check their
balance and withdraw small amounts. Only an authenticated admin session
can approve a large ("privileged") withdrawal -- which is what reveals
the flag.

The bug: the server left verbose debug logging on in production, and
that debug output -- printed right in the connection banner, as if it
were a harmless status line -- leaks a real admin session token. Worse,
that token is STATIC: it's generated once when the process starts and
never expires, never rotates per-session, and isn't bound to any
specific request. In a real environment, an attacker who ever captures
this token on the wire (via a packet sniffer, a proxy log, a leaked
debug line -- doesn't matter how) can replay it to authenticate as
admin, at any time, forever, since the server has no way to tell "the
real admin's current session" apart from "someone presenting a token
that was valid at some point in the past."

That is the essence of a replay attack: a captured, valid piece of an
authentication exchange that can be reused later, because the protocol
never binds it to a single use, a specific time window, or a specific
request.

Protocol (plain text over TCP, one command per line):

    BALANCE              -> shows the current balance
    WITHDRAW <amount>    -> withdraws <amount> if authenticated as admin
                            and amount is large ("privileged"); denied
                            for ordinary (unauthenticated) sessions
    AUTH <token>         -> authenticate this connection as admin, if
                            <token> matches the (leaked) admin token
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

# --- THE BUG: generated once per process, never rotated, never tied
# to a single session or request. "Debug logging left on in prod"
# leaks it to every single connection's banner. -----------------------
ADMIN_TOKEN = secrets.token_hex(8)
# ----------------------------------------------------------------------

PRIVILEGED_AMOUNT = 1_000_000
STARTING_BALANCE = 500


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.balance = STARTING_BALANCE
        self.is_admin = False

        self.wfile.write(
            b"=== MiniBank Terminal v3 ===\r\n"
            b"[debug] last admin session token=" + ADMIN_TOKEN.encode() +
            b" (cached, reused across connections)\r\n"
            b"Commands: BALANCE | WITHDRAW <amount> | AUTH <token>\r\n> "
        )
        self.wfile.flush()

        while True:
            try:
                line = self.rfile.readline(256).decode("utf-8", errors="replace").strip()
            except Exception:
                return
            if not line:
                return

            parts = line.split(" ", 1)
            cmd = parts[0].upper()

            if cmd == "BALANCE":
                self.wfile.write(f"Balance: ${self.balance}\r\n> ".encode())

            elif cmd == "AUTH" and len(parts) == 2:
                if parts[1].strip() == ADMIN_TOKEN:
                    self.is_admin = True
                    self.wfile.write(b"Authenticated as admin.\r\n> ")
                else:
                    self.wfile.write(b"Invalid token.\r\n> ")

            elif cmd == "WITHDRAW" and len(parts) == 2:
                try:
                    amount = int(parts[1].strip())
                except ValueError:
                    self.wfile.write(b"Invalid amount.\r\n> ")
                    continue

                if amount >= PRIVILEGED_AMOUNT:
                    if self.is_admin:
                        flag = read_current_flag()
                        self.wfile.write(
                            f"Privileged withdrawal approved.\r\n"
                            f"Audit receipt: {flag}\r\n> ".encode()
                        )
                    else:
                        self.wfile.write(
                            b"DENIED: privileged withdrawal requires admin.\r\n> "
                        )
                else:
                    self.wfile.write(f"Withdrew ${amount}.\r\n> ".encode())

            else:
                self.wfile.write(b"Unknown command.\r\n> ")
            self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("BANK_PORT", "9500"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"net-replay bank terminal listening on 0.0.0.0:{port}")
        server.serve_forever()
