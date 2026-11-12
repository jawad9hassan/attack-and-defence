"""
Checker module for crypto-weak-hash.

sla_check logs in as the seeded non-admin account (alice) with her
known password and confirms login succeeds (and does NOT return a
flag, since she isn't admin). It never touches /debug/hash and never
cracks the admin's password, so switching the hashing scheme to a
salted, slow KDF (the actual fix) keeps this check passing as long as
alice's own known password still logs her in.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.post(
            f"http://{host}:{port}/login",
            data={"username": "alice", "password": "correct-horse-battery-staple-99"},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if "Invalid credentials" in resp.text:
        return False, "alice's known-good login was rejected"
    if "The flag is" in resp.text:
        return False, "non-admin login unexpectedly returned a flag"
    return True, "alice's known-good login works and returns no flag"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
