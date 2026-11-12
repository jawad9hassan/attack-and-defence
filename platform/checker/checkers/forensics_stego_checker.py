"""
Checker module for forensics-stego.

sla_check only confirms the /download endpoint returns a valid PNG of
the expected size -- it never decodes the hidden payload, so this stays
valid regardless of how a team might rework the stego scheme during a
defense exercise, as long as a correctly-sized PNG keeps coming back.
"""
import io

import requests

try:
    from PIL import Image
    _HAVE_PIL = True
except ImportError:
    _HAVE_PIL = False


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/download", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if not resp.content.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "response is not a valid PNG"

    if _HAVE_PIL:
        try:
            img = Image.open(io.BytesIO(resp.content))
            if img.size != (200, 200):
                return False, f"unexpected image size {img.size}"
        except Exception as e:
            return False, f"failed to open image: {e}"

    return True, "stego image served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    import socket

    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
