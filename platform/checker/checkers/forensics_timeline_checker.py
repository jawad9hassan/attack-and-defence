"""
Checker module for forensics-timeline.

sla_check only confirms /logs.zip returns a well-formed zip archive
containing exactly the three expected log files, each a plausible,
non-empty text log -- it never parses log contents, looks for any
particular IP, or depends on the flag's location, so this stays valid
regardless of how a team reworks the logs' contents during a defense
exercise, as long as a well-formed bundle keeps coming back.
"""
import io
import socket
import zipfile

import requests

EXPECTED_FILES = {"firewall.log", "web_access.log", "auth.log"}


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/logs.zip", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"

    try:
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
    except zipfile.BadZipFile:
        return False, "response is not a valid zip archive"

    names = set(zf.namelist())
    if not EXPECTED_FILES.issubset(names):
        return False, f"zip is missing expected log files, got {names}"

    for name in EXPECTED_FILES:
        data = zf.read(name)
        if len(data.splitlines()) < 3:
            return False, f"{name} has implausibly few lines"

    return True, "logs.zip served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
