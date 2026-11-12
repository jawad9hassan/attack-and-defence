"""
net-tls-downgrade: a toy, text-protocol handshake (not real TLS) that
demonstrates two mistakes real downgrade attacks exploit:

  1. The server negotiates a protocol version by honoring the
     CLIENT's preference order, instead of always preferring the
     strongest version both sides support regardless of what the
     client listed first. A real TLS server that does this lets an
     on-path attacker rewrite the ClientHello's offered cipher
     list/version to only include weak options, and the server will
     happily "agree" to them -- it never insists on its own strongest
     available option.

  2. Once ANY version is negotiated, a `session_established` flag is
     set -- and the command that hands out the flag only checks THAT
     flag, not which specific version was actually negotiated. This
     mirrors a very real class of bug: a check meant to gate access on
     "did we negotiate strong encryption" accidentally only checks
     "did we negotiate *some* session", so a successful downgrade
     doesn't just weaken confidentiality -- it slips straight past an
     access check that was supposed to require the strong mode.

Commands (one per line, plain text over TCP):
  HELLO <comma-separated versions, client's preference order>
      Negotiates a version: the server supports SECURE-V2 and
      PLAIN-V1, and picks the FIRST version in the CLIENT's list that
      it also supports -- it never overrides that order with its own
      preference.
  STATUS
      Shows the currently negotiated version for this connection.
  GET_FLAG
      Hands out the flag if a session has been established at all
      (the bug) -- the intent was "only over SECURE-V2".
"""
import os
import socketserver

SUPPORTED_VERSIONS = ["SECURE-V2", "PLAIN-V1"]  # server's own preference order
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing}"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.version = None
        self.established = False
        self.wfile.write(
            f"toy handshake sim. Server supports: {','.join(SUPPORTED_VERSIONS)}\n".encode()
        )
        self.wfile.write(b"Commands: HELLO <versions>, STATUS, GET_FLAG\n")

        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(None, 1)
            cmd = parts[0].upper() if parts else ""

            if cmd == "HELLO" and len(parts) == 2:
                client_versions = [v.strip() for v in parts[1].split(",") if v.strip()]
                negotiated = None
                # THE BUG: iterate in the CLIENT's order, not the
                # server's own preference order -- the first mutually
                # supported version WINS, whatever the client listed
                # first, instead of the server always insisting on
                # its own strongest mutually supported option.
                for v in client_versions:
                    if v in SUPPORTED_VERSIONS:
                        negotiated = v
                        break
                if negotiated is None:
                    self.wfile.write(b"ERROR: no mutually supported version\n")
                    continue
                self.version = negotiated
                self.established = True
                self.wfile.write(f"NEGOTIATED version={negotiated}\n".encode())

            elif cmd == "STATUS":
                self.wfile.write(
                    f"established={self.established} version={self.version}\n".encode()
                )

            elif cmd == "GET_FLAG":
                # THE BUG: checks "is a session established at all",
                # not "is the negotiated version specifically
                # SECURE-V2". Any successfully negotiated version,
                # including the weak one, satisfies this check.
                if self.established:
                    self.wfile.write(f"FLAG: {read_flag()}\n".encode())
                else:
                    self.wfile.write(b"ERROR: no session established yet\n")

            else:
                self.wfile.write(b"ERROR: unknown command or bad arguments\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("HANDSHAKE_PORT", "6004"))
    with ThreadingTCPServer(("0.0.0.0", port), Handler) as server:
        print(f"handshake sim listening on 0.0.0.0:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
