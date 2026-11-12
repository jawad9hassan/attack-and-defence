"""
Checker module for net-auth.

sla_check sends an obviously-wrong username/password and confirms the
service denies it -- it never tries the default credentials, so this
stays valid regardless of how a team patches the default-account bug.
"""
import socket
import time


def _recv_until(sock, marker: bytes, timeout=3):
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
            _recv_until(s, b"Username: ", timeout=2)
            s.sendall(b"definitely_not_a_real_user\n")
            _recv_until(s, b"Password: ", timeout=2)
            s.sendall(b"definitely_not_the_real_password\n")
            time.sleep(0.2)
            resp = _recv_until(s, b"\n", timeout=2)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"Access denied" not in resp:
        return False, f"expected denial for bogus credentials, got: {resp!r}"
    return True, "console reachable, bogus credentials correctly denied"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
