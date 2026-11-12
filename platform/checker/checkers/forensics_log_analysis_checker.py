"""
Checker module for forensics-log-analysis.

sla_check only confirms /auth.log returns a plausible, non-empty text
log containing at least one recognizable syslog-style "Accepted
password" line -- it never looks for the brute-force burst or the
flag itself, so this stays valid regardless of how a team might
rework the log's contents during a defense exercise, as long as a
well-formed log keeps coming back.
"""
import socket

import requests


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/auth.log", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    text = resp.text
    if len(text.splitlines()) < 5:
        return False, "log file has implausibly few lines"
    if "Accepted password" not in text:
        return False, "log does not contain any recognizable login lines"

    return True, "auth log served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
