"""
Checker module for web-sqli-union.

sla_check sends a plain, benign search term (no SQL metacharacters at
all) and confirms the known seeded product ("Laptop") still shows up in
the results. It never uses the UNION injection itself, so a correct fix
(parameterized queries) keeps passing this check.
"""
import requests


def sla_check(host, port):
    try:
        resp = requests.get(
            f"http://{host}:{port}/search",
            params={"q": "lap"},
            timeout=5,
        )
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if "Laptop" not in resp.text:
        return False, "seeded product 'Laptop' missing from search results"
    return True, "benign search ok"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
