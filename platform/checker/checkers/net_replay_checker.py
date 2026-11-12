"""
Checker module for net-replay.

sla_check connects, checks the balance, and attempts an unauthenticated
privileged withdrawal, confirming it's denied -- it never authenticates
or uses any captured token, so this stays valid regardless of how a
team patches the leaked/static-token bug.
"""
import socket
import time


def _recv_until(sock, marker: bytes, timeout=2):
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
            _recv_until(s, b"> ", timeout=2)
            s.sendall(b"BALANCE\n")
            time.sleep(0.2)
            balance_resp = _recv_until(s, b"> ", timeout=2)
            if b"Balance: $" not in balance_resp:
                return False, f"BALANCE did not return a balance: {balance_resp!r}"

            s.sendall(b"WITHDRAW 1000000\n")
            time.sleep(0.2)
            withdraw_resp = _recv_until(s, b"> ", timeout=2)
    except OSError as e:
        return False, f"connection failed: {e}"

    if b"DENIED" not in withdraw_resp:
        return False, f"expected unauthenticated privileged withdrawal to be denied: {withdraw_resp!r}"

    return True, "balance check + unauthenticated privileged-withdrawal denial both working"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
