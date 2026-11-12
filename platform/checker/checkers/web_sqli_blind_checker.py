"""
Checker module for web-sqli-blind.

sla_check sends a plain, benign username (no SQL metacharacters at all)
that is guaranteed not to be taken, and confirms the service responds
with "available". It never uses the blind boolean injection itself, so
a correct fix (parameterized queries) keeps passing this check.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.get(
            f"http://{host}:{port}/check",
            params={"username": "checker_probe_user_not_taken"},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if "available" not in resp.text:
        return False, "expected 'available' for an unused username"
    return True, "benign availability check ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
