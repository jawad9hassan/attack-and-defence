"""
net-protocol-fuzzing: a tiny length-prefixed echo protocol with a
Heartbleed-shaped bug -- the server trusts a CLAIMED length that can
be larger than the payload actually sent, and pads the shortfall out
of an internal buffer that happens to sit right next to the flag in
memory. A malformed request (claimed length far bigger than the real
payload) leaks whatever is sitting in that adjacent buffer instead of
erroring out.

Protocol (one command per line, plain text over TCP):
  ECHO <claimed_len> <hex payload>
      Decodes <hex payload> to raw bytes (call this `actual`), then
      responds with the first <claimed_len> bytes of
      `actual + INTERNAL_BUFFER[len(actual):]`
      -- i.e. your own bytes, padded out with whatever comes next in
      a buffer you were never supposed to be able to read, if you ask
      for more bytes back than you actually sent.
"""
import os
import secrets
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
MAX_CLAIMED_LEN = 256


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing}"


def build_internal_buffer():
    # Fresh every call, so a flag rotation is picked up immediately --
    # models "adjacent heap memory" that happens to currently hold the
    # flag, flanked by unrelated random bytes on both sides.
    return secrets.token_bytes(32) + read_flag().encode() + secrets.token_bytes(128)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"toy length-prefixed echo. Commands: ECHO <claimed_len> <hex_payload>\n")
        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(None, 2)
            cmd = parts[0].upper() if parts else ""

            if cmd == "ECHO" and len(parts) in (2, 3):
                try:
                    claimed_len = int(parts[1])
                except ValueError:
                    self.wfile.write(b"ERROR: bad claimed_len\n")
                    continue
                if claimed_len < 0 or claimed_len > MAX_CLAIMED_LEN:
                    self.wfile.write(
                        f"ERROR: claimed_len out of range (0-{MAX_CLAIMED_LEN})\n".encode()
                    )
                    continue
                hex_payload = parts[2] if len(parts) == 3 else ""
                try:
                    actual = bytes.fromhex(hex_payload)
                except ValueError:
                    self.wfile.write(b"ERROR: bad hex payload\n")
                    continue

                # THE BUG: claimed_len is never checked against
                # len(actual). If it's bigger, the shortfall is padded
                # out of an internal buffer the client was never given
                # any of -- a classic over-read.
                internal_buffer = build_internal_buffer()
                combined = actual + internal_buffer[len(actual):]
                response = combined[:claimed_len]
                self.wfile.write(response.hex().encode() + b"\n")

            else:
                self.wfile.write(b"ERROR: unknown command or bad arguments\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("ECHO_PROTO_PORT", "6005"))
    with ThreadingTCPServer(("0.0.0.0", port), Handler) as server:
        print(f"echo-proto sim listening on 0.0.0.0:{port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
