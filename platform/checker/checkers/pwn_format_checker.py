"""
Checker module for the pwn-format service.

sla_check sends a completely benign name and feedback string (no '%'
characters at all), so it only verifies the service still behaves
normally. It must never itself depend on the format-string vulnerability,
or a team that patches the bug correctly (e.g. printf("%s", feedback))
would start failing their own SLA check.
"""
import socket
import time


def _read_for(sock, duration=1.5):
    """Accumulate everything the socket sends for up to `duration` seconds.

    Same rationale as pwn-baby's checker: a single recv() isn't guaranteed
    to capture a full multi-printf() response over TCP.
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
            _read_for(s, duration=0.5)  # banner + "What's your name?" prompt
            s.sendall(b"checker\n")
            _read_for(s, duration=0.5)  # "Hello, checker! ..." + feedback prompt
            s.sendall(b"everything looks fine today\n")
            data = _read_for(s, duration=1.5)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"Thanks for your feedback" not in data:
        return False, f"unexpected response from service: {data!r}"
    return True, "benign feedback round-trip ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
