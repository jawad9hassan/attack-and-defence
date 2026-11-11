#!/usr/bin/env python3
"""
flagd — a tiny internal-only admin daemon that lets the checker rotate a
service's flag at runtime, without rebuilding or restarting the service.

This is the same idea real attack-defense gameservers use: the checker
has a privileged channel into each team's vulnbox that normal players
(and attackers) cannot reach, because it is never published outside the
Docker network the service runs on.

Protocol (plain text, one line per request, newline-terminated):

    <secret> SET <flag>\n   -> overwrites the flag file, replies "OK\n"
    <secret> GET\n           -> replies "<flag>\n" (lets the checker
                                 confirm the write actually stuck)
    anything else            -> replies "ERR\n"

Environment variables:
    FLAGD_PORT    port to listen on (default: 10000)
    FLAGD_SECRET  shared secret the checker must present (required)
    FLAG_PATH     file the live flag is stored in (default: /flag.txt)
"""
import os
import socket
import socketserver
import sys

PORT = int(os.environ.get("FLAGD_PORT", "10000"))
SECRET = os.environ.get("FLAGD_SECRET")
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

if not SECRET:
    print("flagd: FLAGD_SECRET is required, refusing to start", file=sys.stderr)
    sys.exit(1)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(4096).decode("utf-8", errors="replace").strip()
        except Exception:
            return

        parts = data.split(" ", 2)
        reply = b"ERR\n"

        if len(parts) >= 2 and parts[0] == SECRET:
            cmd = parts[1]
            if cmd == "SET" and len(parts) == 3:
                flag = parts[2]
                try:
                    with open(FLAG_PATH, "w") as f:
                        f.write(flag + "\n")
                    reply = b"OK\n"
                except OSError as e:
                    reply = f"ERR write_failed: {e}\n".encode()
            elif cmd == "GET" and len(parts) == 2:
                try:
                    with open(FLAG_PATH, "r") as f:
                        reply = (f.read().strip() + "\n").encode()
                except OSError:
                    reply = b"ERR no_flag\n"

        try:
            self.request.sendall(reply)
        except Exception:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as server:
        print(f"flagd listening on 0.0.0.0:{PORT}, flag file {FLAG_PATH}")
        server.serve_forever()
