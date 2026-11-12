"""
Checker module for crypto-weak-rsa.

sla_check connects once and confirms a well-formed N/E/C triple comes
back -- it never connects twice or runs the gcd attack itself, so this
stays valid regardless of how a team reworks key generation during a
defense exercise, as long as the service keeps answering with a valid
RSA triple.
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
            data = _read_for(s, duration=2.0)
    except OSError as e:
        return False, f"connection failed: {e}"

    text = data.decode(errors="replace")
    n_match = re.search(r"N:\s*([0-9a-fA-F]+)", text)
    e_match = re.search(r"E:\s*([0-9a-fA-F]+)", text)
    c_match = re.search(r"C:\s*([0-9a-fA-F]+)", text)
    if not (n_match and e_match and c_match):
        return False, f"missing N/E/C in response: {text!r}"

    try:
        n = int(n_match.group(1), 16)
        e = int(e_match.group(1), 16)
    except ValueError:
        return False, "N or E is not valid hex"

    if n.bit_length() < 64 or e == 0:
        return False, "returned key looks malformed"

    return True, "RSA triple received"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
