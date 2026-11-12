"""
Checker module for the pwn-ret2libc service.

sla_check sends a SHORT, harmless line of input -- nowhere near the
72-byte offset that reaches the saved return address -- so it only
confirms the service still prompts, accepts input, echoes nothing
unexpected, and exits/continues normally. It must never depend on the
overflow itself, or a team that patches the bug correctly (bounds-
checks the read, e.g. replacing gets() with a safe fgets()) would
start failing their own SLA check.
"""
import socket


def _read_for(sock, duration=1.5):
    import time
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
            banner = _read_for(s, duration=1.0)
            s.sendall(b"hello\n")
            after = _read_for(s, duration=1.5)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"Give me input:" not in banner:
        return False, f"missing expected prompt: {banner!r}"
    if b"Thanks, bye." not in after:
        return False, f"service did not respond normally after benign input: {after!r}"
    return True, "prompt and benign round-trip ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
