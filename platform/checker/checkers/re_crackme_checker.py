"""
Checker module for re-crackme.

sla_check deliberately sends a WRONG license key -- it only confirms the
service is up and responds with "Access denied", never the real key, so
it never depends on (or leaks) the solution.
"""
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
            _read_for(s, duration=0.5)
            s.sendall(b"definitely-the-wrong-key\n")
            data = _read_for(s, duration=1.5)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"Access denied" not in data:
        return False, f"unexpected response from service: {data!r}"
    return True, "license check rejects wrong key as expected"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
