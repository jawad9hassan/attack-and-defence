"""
Checker module for web-path-traversal.

sla_check only requests one of the seeded, intended notes
(welcome.txt) and confirms its known content comes back. It never
sends a `..` or absolute-path payload, so a fix that resolves the
requested path and rejects anything outside NOTES_DIR (the actual
remediation) keeps passing this check as long as the intended notes
still load normally.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.get(
            f"http://{host}:{port}/view", params={"file": "welcome.txt"}, timeout=5
        )
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if "Browse available notes" not in resp.text:
        return False, "welcome.txt note did not load as expected"
    return True, "intended note loaded normally"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
