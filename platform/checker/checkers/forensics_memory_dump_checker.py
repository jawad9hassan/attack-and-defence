"""
Checker module for forensics-memory-dump.

sla_check only confirms /memory.dmp returns bytes that start with the
expected "PROC:" record marker and are a plausible size -- it never
parses out the process list or reads the flag itself, so this stays
valid regardless of how a team might rework the dump's contents
during a defense exercise, as long as a well-formed dump keeps coming
back.
"""
import socket

import requests


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/memory.dmp", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if len(resp.content) < 64 or resp.content[:5] != b"PROC:":
        return False, "response is not a well-formed memory dump"

    return True, "memory dump served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
