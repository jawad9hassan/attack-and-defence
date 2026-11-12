"""
Checker module for forensics-disk-image.

sla_check only confirms /disk.img returns bytes starting with the
expected "DISKIMG1" magic and a plausible entry count -- it never
parses out individual files or reads the flag itself, so this stays
valid regardless of how a team might rework the image's contents
during a defense exercise, as long as a well-formed image keeps
coming back.
"""
import socket
import struct

import requests


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/disk.img", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if len(resp.content) < 12 or resp.content[:8] != b"DISKIMG1":
        return False, "response is not a well-formed disk image"

    entry_count = struct.unpack_from("<I", resp.content, 8)[0]
    if entry_count == 0 or entry_count > 1000:
        return False, f"implausible entry count: {entry_count}"

    return True, "disk image served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
