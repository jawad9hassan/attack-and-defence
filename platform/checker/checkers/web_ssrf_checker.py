"""
Checker module for web-ssrf.

sla_check only hits /health directly on the published port -- it never
uses the /fetch proxy feature and never touches the internal-only
admin API, so a fix that blocks loopback/private-range targets inside
/fetch (the actual remediation) keeps passing this check regardless of
how strict the new allowlist is.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/health", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if resp.text.strip() != "ok":
        return False, f"unexpected /health body: {resp.text!r}"
    return True, "service healthy"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
