#!/usr/bin/env python3
"""
net-proto: a tiny "network diagnostics" service with a classic
incomplete-blacklist command injection bug.

Protocol (plain text over TCP):

    The service prompts for a hostname, runs `ping -c 1 <hostname>`, and
    returns the output. It tries to be "safe" by stripping out
    semicolons — but that's the ONLY character it blocks. Every other
    shell metacharacter (&&, |, backticks, $(...), newlines) still works.

This mirrors a very common real-world bug class: someone adds input
"sanitization" by blacklisting the one dangerous character they thought
of, instead of using an allowlist (or, correctly, never building a shell
command from user input at all).
"""
import os
import socketserver
import subprocess

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def naive_sanitize(host: str) -> str:
    # VULNERABLE: blocks only ';'. && | ` $() and newlines all still work.
    return host.replace(";", "")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            b"=== Network Diagnostics ===\n"
            b"Enter a hostname to ping: "
        )
        self.wfile.flush()

        try:
            line = self.rfile.readline(256).decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not line:
            self.wfile.write(b"ERROR: empty input\n")
            return

        host = naive_sanitize(line)

        try:
            # VULNERABLE: shell=True with a string built from user input.
            # The semicolon-stripping above gives a false sense of safety;
            # && | ` and $() are not blocked at all.
            result = subprocess.run(
                f"ping -c 1 -W 2 {host}",
                shell=True,
                capture_output=True,
                timeout=5,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = b"[diag] command timed out\n"
        except Exception as e:
            output = f"[diag] error: {e}".encode()

        if len(output) > 8192:
            output = output[:8192] + b"\n...[truncated]"

        self.wfile.write(output)
        if not output.endswith(b"\n"):
            self.wfile.write(b"\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("DIAG_PORT", "9200"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"diag service listening on 0.0.0.0:{port}")
        server.serve_forever()
