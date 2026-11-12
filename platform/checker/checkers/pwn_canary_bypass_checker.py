"""
Checker module for the pwn-canary-bypass service.

sla_check sends a SHORT, harmless hex payload -- well under the 64-byte
buffer, nowhere near the canary at offset 72 -- so it only confirms the
server is up and speaking its protocol normally. It must never depend
on the overflow/canary-bypass itself, or a team that patches the bug
correctly (e.g. bounds-checks the copy) would start failing their own
SLA check.
"""
import socket


def _connect(host, port, timeout=5):
    s = socket.create_connection((host, port), timeout=timeout)
    f = s.makefile("rb")
    f.readline()  # banner line
    return s, f


def _query(s, f, payload_bytes, timeout=3):
    s.sendall(payload_bytes.hex().encode() + b"\n")
    s.settimeout(timeout)
    try:
        return f.readline()
    except socket.timeout:
        return None


def sla_check(host, port):
    try:
        s, f = _connect(host, port)
        resp = _query(s, f, b"benign-check")
        s.close()
    except OSError as e:
        return False, f"connection failed: {e}"

    if resp != b"OK\n":
        return False, f"unexpected response from service: {resp!r}"
    return True, "benign short payload accepted normally"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
