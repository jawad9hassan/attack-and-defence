"""
Checker module for crypto-ecb-oracle.

sla_check connects, sends one benign request (empty input), and
confirms the service replies with a well-formed, block-aligned hex
ciphertext. It never performs the byte-at-a-time ECB attack itself, so
a fix that switches the encryption mode (e.g. to CBC with a random IV
per request) keeps passing this check -- it only needs *some*
hex-encoded, block-sized ciphertext back for a benign query.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            f.readline()  # banner
            s.sendall(b"\n")
            reply = f.readline().strip()
    except OSError as e:
        return False, f"connection failed: {e}"

    if not reply:
        return False, "no reply to benign query"
    try:
        raw = bytes.fromhex(reply.decode())
    except ValueError:
        return False, f"reply is not valid hex: {reply!r}"
    if len(raw) == 0 or len(raw) % 16 != 0:
        return False, f"reply is not block-aligned ({len(raw)} bytes)"
    return True, "benign query returned well-formed block-aligned ciphertext"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
