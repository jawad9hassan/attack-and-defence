"""
Checker module for net-proto.

sla_check sends a plain hostname (no shell metacharacters at all) and
confirms the service responds — it never injects a command, so a correct
fix (removing shell=True, using subprocess with an argument list, or
allowlisting characters) keeps passing this check.
"""
import socket


def _recv_until_timeout(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
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
            _recv_until_timeout(s, timeout=1)  # banner + prompt
            s.sendall(b"127.0.0.1\n")
            resp = _recv_until_timeout(s, timeout=4)
    except OSError as e:
        return False, f"connection failed: {e}"

    if not resp:
        return False, "no response from service"
    return True, "diagnostics request handled"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
