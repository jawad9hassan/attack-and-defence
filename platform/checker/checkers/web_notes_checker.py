"""
Checker module for the web-notes service.

Every checker module must expose:
  sla_check(host, port) -> (ok: bool, detail: str)
  put_flag(host, flagd_port, flagd_secret, flag) -> bool

sla_check must exercise the service's NORMAL, non-exploit functionality
(the same thing a legitimate player would do), so a broken defense patch
is caught immediately: if the team "fixes" the SQLi by breaking login
entirely, this check fails and they lose defense points, same as in a
real attack-defense game.
"""
import socket

import requests


def sla_check(host, port):
    url = f"http://{host}:{port}/login"
    try:
        resp = requests.post(
            url,
            data={"username": "guest", "password": "guestpass"},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"request failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status {resp.status_code}"
    if "Welcome, guest" not in resp.text:
        return False, "guest login did not succeed (service broken or patched incorrectly)"
    return True, "guest login ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
