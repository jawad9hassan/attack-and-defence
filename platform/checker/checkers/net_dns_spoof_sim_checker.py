"""
Checker module for the net-dns-spoof-sim service.

sla_check only ever QUERYs an ordinary (non-"flag.internal") domain
and confirms it resolves normally -- it never touches flag.internal,
never races a SPOOF against a pending query, and never depends on the
predictable-transaction-ID bug. A team that fixes the bug (e.g. makes
transaction IDs random instead of a shared sequential counter) would
still pass this check, since ordinary resolution is untouched by that
fix.
"""
import socket


def _read_line(f, timeout=3):
    import socket as _s
    try:
        return f.readline()
    except _s.timeout:
        return None


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            s.settimeout(3)
            f.readline()  # banner
            s.sendall(b"QUERY checker-probe.example.com\n")
            resp = f.readline()
    except OSError as e:
        return False, f"connection failed: {e}"

    if not resp.startswith(b"RESOLVED domain=checker-probe.example.com"):
        return False, f"unexpected response to ordinary QUERY: {resp!r}"
    return True, "ordinary domain resolved normally"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
