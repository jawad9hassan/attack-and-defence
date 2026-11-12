"""
Checker module for the net-ssrf-pivot service.

sla_check uses the gateway EXACTLY the way it's intended to be used:
CONNECT to the public echo service (127.0.0.1:6000, the gateway's
documented, intended target) and confirm the echo round-trips. It
never asks the gateway to CONNECT anywhere else, so it never depends
on the missing-allowlist bug -- a team that fixes the bug by adding an
allowlist containing only the echo service would still pass.
"""
import socket


def _connect(host, port, timeout=5):
    s = socket.create_connection((host, port), timeout=timeout)
    f = s.makefile("rb")
    return s, f


def sla_check(host, port):
    try:
        s, f = _connect(host, port)
        f.readline()  # gateway banner
        s.sendall(b"CONNECT 127.0.0.1:6000\n")
        s.settimeout(3)
        connected_line = f.readline()
        if connected_line != b"CONNECTED\n":
            s.close()
            return False, f"gateway did not confirm CONNECT: {connected_line!r}"
        f.readline()  # echo service's own banner
        s.sendall(b"benign-check\n")
        resp = f.readline()
        s.close()
    except OSError as e:
        return False, f"connection failed: {e}"

    if resp != b"ECHO: benign-check\n":
        return False, f"unexpected echo response: {resp!r}"
    return True, "gateway correctly relayed to its intended echo target"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
