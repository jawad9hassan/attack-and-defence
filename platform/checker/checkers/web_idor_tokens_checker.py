"""
Checker module for web-idor-tokens.

sla_check fetches alice's own share link (the one the homepage itself
hands out) and confirms her note content is returned. It never computes
the admin's token or relies on the hash-of-username weakness, so a
correctly patched service (e.g. tokens switched to per-account random
secrets, looked up server-side) keeps passing as long as alice's own
link still works for alice.
"""
import re

import requests


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code on / : {resp.status_code}"

    m = re.search(r'action="(/n/[0-9a-f]{16})"', resp.text)
    if not m:
        return False, "homepage did not contain alice's share link"

    try:
        note_resp = requests.get(f"http://{host}:{port}{m.group(1)}", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed on share link: {e}"

    if note_resp.status_code != 200:
        return False, f"unexpected status code on share link: {note_resp.status_code}"
    if "oat milk" not in note_resp.text:
        return False, "alice's own share link did not return her note"
    return True, "alice's own share link works"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
