"""
Checker module for web-api-mass-assignment.

sla_check registers a brand-new user with ONLY username/password (no
extra fields), logs in, and confirms /api/profile reports the normal
default role "user". It never sends an extra "role" field itself, so a
fix that switches registration to an explicit field allowlist (the
actual remediation) keeps passing this check -- a normal signup with
just username/password should always end up as a normal "user".
"""
import uuid

import requests


def sla_check(host, port):
    base = f"http://{host}:{port}"
    username = f"sla-{uuid.uuid4().hex[:10]}"
    password = "sla-check-password"

    try:
        r1 = requests.post(
            f"{base}/api/register",
            json={"username": username, "password": password},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed on register: {e}"
    if r1.status_code != 201:
        return False, f"registration failed with status {r1.status_code}: {r1.text}"

    try:
        r2 = requests.post(
            f"{base}/api/login",
            json={"username": username, "password": password},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed on login: {e}"
    if r2.status_code != 200 or "token" not in r2.json():
        return False, f"login failed with status {r2.status_code}: {r2.text}"
    token = r2.json()["token"]

    try:
        r3 = requests.get(
            f"{base}/api/profile", headers={"Authorization": f"Bearer {token}"}, timeout=5
        )
    except requests.RequestException as e:
        return False, f"connection failed on profile: {e}"
    if r3.status_code != 200:
        return False, f"profile fetch failed with status {r3.status_code}: {r3.text}"

    role = r3.json().get("role")
    if role != "user":
        return False, f"freshly registered account did not default to role 'user' (got {role!r})"
    return True, "signup/login/profile flow ok, default role is 'user'"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
