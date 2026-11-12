"""
Checker module for web-authbypass-jwt.

sla_check logs in normally (gets a real, correctly-signed guest token)
and confirms /admin denies it with 403 -- it never forges a token, so a
service that correctly rejects "alg: none" tokens still passes this
check.
"""
import socket

import requests


def sla_check(host, port):
    base = f"http://{host}:{port}"
    try:
        r = requests.post(f"{base}/login", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if r.status_code != 200 or "token" not in r.cookies:
        return False, f"login did not return a token cookie (status {r.status_code})"

    token = r.cookies["token"]
    try:
        r2 = requests.get(f"{base}/admin", cookies={"token": token}, timeout=5)
    except requests.RequestException as e:
        return False, f"admin request failed: {e}"

    if r2.status_code != 403:
        return False, f"expected 403 for a non-admin token, got {r2.status_code}"

    return True, "login + guest-token admin-denial both working"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
