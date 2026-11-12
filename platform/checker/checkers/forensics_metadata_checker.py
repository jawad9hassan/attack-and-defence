"""
Checker module for forensics-metadata.

sla_check only confirms /photo.png returns a well-formed PNG file of a
plausible size (checks the 8-byte PNG magic header and that the body
isn't suspiciously tiny) -- it never parses or depends on any
particular metadata chunk or the flag itself, so this stays valid
regardless of how a team reworks the image or its metadata fields
during a defense exercise, as long as a well-formed PNG keeps coming
back.
"""
import socket

import requests

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/photo.png", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    body = resp.content
    if not body.startswith(PNG_MAGIC):
        return False, "response is not a valid PNG file"
    if len(body) < 200:
        return False, "PNG file is implausibly small"

    return True, "photo.png served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
