"""
Checker module for crypto-xor.

sla_check exercises the ENC command with a short benign payload (NOT the
all-zero chosen-plaintext attack an attacker would use) and confirms the
XOR round-trips correctly. This never touches GETFLAG or the key-recovery
technique, so it stays true to "normal functionality only."
"""
import socket


def _recv_until(sock, marker=b"> ", timeout=5):
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            _recv_until(s, b"> ")
            probe = b"hello"
            s.sendall(b"ENC " + probe.hex().encode() + b"\n")
            resp = _recv_until(s, b"\n")
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"CIPHERTEXT: " not in resp:
        return False, f"unexpected response: {resp!r}"
    return True, "ENC round-trip ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
