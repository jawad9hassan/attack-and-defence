"""
Checker module for the pwn-baby service.

sla_check deliberately sends a SHORT, harmless name — nowhere near the
72-byte offset that triggers the overflow — so it only verifies the
service still behaves normally. It must never itself depend on the
vulnerability, or a team that patches the bug correctly would start
failing their own SLA check.
"""
import socket
import time


def _read_for(sock, duration=1.5):
    """Accumulate everything the socket sends for up to `duration` seconds.

    A single recv() call is NOT guaranteed to return a whole message: TCP
    is a byte stream, and the service's two printf() calls can arrive as
    separate packets. Looping until the deadline (or the peer closes)
    avoids false "service is down" reports caused by reading mid-message.
    """
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
            _read_for(s, duration=0.5)  # banner + prompt
            s.sendall(b"checker\n")
            data = _read_for(s, duration=1.5)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"Nice to meet you" not in data:
        return False, f"unexpected response from service: {data!r}"
    return True, "benign echo ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
