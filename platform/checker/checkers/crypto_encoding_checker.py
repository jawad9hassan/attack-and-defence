"""
Checker module for crypto-encoding.

sla_check just connects and confirms the service sends back a non-empty
puzzle blob in the expected shape (base64-alphabet characters, reversed
or not -- the checker doesn't need to decode it, only confirm the
service is alive and producing output). It never decodes the flag
itself, so this stays valid regardless of how a team might modify the
encoding scheme during a defense exercise, as long as SOME blob comes
back.
"""
import re
import socket
import time


def _read_for(sock, duration=1.5):
    sock.settimeout(0.3)
    deadline = time.time() + duration
    chunks = []
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            data = _read_for(s, duration=1.5)
    except OSError as e:
        return False, f"connection failed: {e}"

    lines = [l for l in data.decode(errors="replace").splitlines() if l.strip()]
    if not lines:
        return False, "no output from service"

    blob = lines[-1]
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", blob):
        return False, f"last line doesn't look like an encoded blob: {blob!r}"
    return True, "puzzle blob received"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
