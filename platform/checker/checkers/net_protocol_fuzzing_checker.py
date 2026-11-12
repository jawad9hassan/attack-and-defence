"""
Checker module for the net-protocol-fuzzing service.

sla_check only ever sends a claimed_len that exactly matches the real
payload length, and confirms the echo round-trips byte-for-byte with
no extra data appended. It never asks for more bytes back than it
sent, so it never depends on the over-read bug -- a team that fixes
it (clamping claimed_len to the actual payload length, or rejecting a
mismatch outright) would still pass this check.
"""
import socket


def sla_check(host, port):
    probe = b"checker-probe"
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            s.settimeout(3)
            f.readline()  # banner
            s.sendall(f"ECHO {len(probe)} {probe.hex()}\n".encode())
            resp = f.readline()
    except OSError as e:
        return False, f"connection failed: {e}"

    try:
        echoed = bytes.fromhex(resp.decode().strip())
    except ValueError:
        return False, f"response was not valid hex: {resp!r}"

    if echoed != probe:
        return False, f"echo did not match the exact payload sent: {echoed!r}"
    return True, "exact-length echo round-tripped correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
