"""
Checker module for web-idor.

sla_check logs in as the seeded 'bob' account and reads bob's OWN note
(never the admin note at id=1) — this must keep working no matter how
the IDOR is patched, since that's completely legitimate, intended
behavior.
"""
import socket

import requests


def sla_check(host, port):
    base = f"http://{host}:{port}"
    try:
        resp = requests.post(
            f"{base}/login",
            data={"username": "bob", "password": "bobsecurepw"},
            timeout=5,
            allow_redirects=False,
        )
        if resp.status_code != 302:
            return False, f"login did not redirect (status {resp.status_code})"

        cookies = resp.cookies
        resp2 = requests.get(f"{base}/note/3", cookies=cookies, timeout=5)
    except requests.RequestException as e:
        return False, f"request failed: {e}"

    if resp2.status_code != 200:
        return False, f"own note fetch failed (status {resp2.status_code})"
    if "Shopping list" not in resp2.text:
        return False, "bob's own note content missing or changed unexpectedly"
    return True, "bob can view his own note"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
