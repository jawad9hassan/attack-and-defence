"""
Checker module for web-xss-stored.

sla_check posts a plain, benign guestbook comment (no HTML/JS at all)
and confirms it comes back in the page's text. It never posts the
onerror/fetch exfiltration payload and never touches /admin, so a fix
that escapes output (removing the |safe filter / autoescaping properly)
keeps passing this check as long as plain-text comments still render.
"""
import uuid

import requests


def sla_check(host, port):
    marker = f"sla-check-{uuid.uuid4().hex[:8]}"
    try:
        resp = requests.post(
            f"http://{host}:{port}/board",
            data={"name": "checker", "message": marker},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if marker not in resp.text:
        return False, "benign comment did not appear on the guestboard"
    return True, "benign comment posted and rendered"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
