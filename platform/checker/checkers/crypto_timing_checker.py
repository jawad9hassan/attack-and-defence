"""
Checker module for crypto-timing.

sla_check sends one obviously-wrong, fixed-length guess and confirms
the service responds "NO MATCH" promptly (within a generous timeout).
It never measures or compares response timings itself and never
attempts to recover the secret, so switching the comparison to
`hmac.compare_digest` (the actual fix, which removes the timing signal
but still correctly rejects a wrong guess) keeps this check passing.
"""
import socket
import time


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            f.readline()  # banner

            start = time.perf_counter()
            s.sendall(b"xxxxxxxx\n")
            reply = f.readline().strip()
            elapsed = time.perf_counter() - start
    except OSError as e:
        return False, f"connection failed: {e}"

    if not reply.startswith(b"NO MATCH"):
        return False, f"unexpected response to a wrong guess: {reply!r}"
    if elapsed > 3.0:
        return False, f"response took unexpectedly long ({elapsed:.2f}s)"
    return True, "service correctly rejects a wrong guess promptly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
