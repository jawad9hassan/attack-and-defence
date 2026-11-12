"""
Checker module for net-rate-limit-bypass.

sla_check sends 3 deliberately-wrong PINs and confirms the lockout
message appears -- it never brute-forces the real PIN or relies on the
per-connection-reset bug, so a fix that rate-limits by IP instead of
per-connection still passes.
"""
import socket
import time


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.settimeout(2)
            for pin in ("0000", "1111", "2222"):
                s.sendall((pin + "\n").encode())
            time.sleep(0.3)
            data = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
    except OSError as e:
        return False, f"connection failed: {e}"

    text = data.decode(errors="replace")
    if "Too many attempts" not in text:
        return False, f"expected lockout after 3 wrong guesses, got: {text!r}"

    return True, "lockout after 3 wrong guesses confirmed"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
