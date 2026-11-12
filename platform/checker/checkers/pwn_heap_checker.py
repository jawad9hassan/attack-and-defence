"""
Checker module for the pwn-heap service.

sla_check sends a SHORT, harmless NEW payload -- well under the
56-byte data field, nowhere near the function pointer that follows it
-- then SHOWs it back and confirms the text round-trips unchanged.
It must never depend on the overflow itself, or a team that patches
the bug correctly (bounds-checks NEW's length against DATA_SIZE)
would start failing their own SLA check.
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
    probe_text = b"checker-probe"
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            _read_for(s, duration=0.5)  # banner
            s.sendall(b"NEW " + probe_text.hex().encode() + b"\n")
            new_resp = _read_for(s, duration=1.0)
            s.sendall(b"SHOW\n")
            show_resp = _read_for(s, duration=1.0)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"OK" not in new_resp:
        return False, f"NEW did not succeed: {new_resp!r}"
    expected = b"Note: " + probe_text + b"\n"
    if expected not in show_resp:
        return False, f"SHOW did not echo the note back correctly: {show_resp!r}"
    return True, "note created and shown back correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
