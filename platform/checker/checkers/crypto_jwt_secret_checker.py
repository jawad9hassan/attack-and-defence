"""
Checker module for crypto-jwt-secret.

sla_check logs in as a normal guest, gets a token, and confirms that
token is accepted as a valid session by checking /admin correctly
reports "not admin" (role 'user', 403) rather than erroring out or
rejecting the token outright. It never brute-forces the signing secret
and never forges an admin token, so swapping in a long random secret
(the actual fix) keeps this check passing as long as guest tokens still
verify correctly.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.post(f"http://{host}:{port}/login", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed on login: {e}"
    if resp.status_code != 200 or "token" not in resp.cookies:
        return False, f"login did not return a token cookie (status {resp.status_code})"

    token = resp.cookies["token"]
    try:
        admin_resp = requests.get(
            f"http://{host}:{port}/admin", cookies={"token": token}, timeout=5
        )
    except requests.RequestException as e:
        return False, f"connection failed on admin check: {e}"

    if admin_resp.status_code != 403:
        return False, f"expected 403 (valid token, non-admin role) but got {admin_resp.status_code}: {admin_resp.text}"
    if "is not admin" not in admin_resp.text:
        return False, f"unexpected /admin response body: {admin_resp.text!r}"
    return True, "guest token issued and correctly verified as non-admin"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
