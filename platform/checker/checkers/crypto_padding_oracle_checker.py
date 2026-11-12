"""
Checker module for crypto-padding-oracle.

sla_check connects, reads the COOKIE line the service hands out
unprompted, and replays that EXACT cookie back to the oracle -- which
must always report GOOD PADDING, since it's a real ciphertext the
service itself just produced. It never performs the bit-flipping
padding-oracle attack, so a fix that makes decryption failures
indistinguishable (constant-time, generic error, no GOOD/BAD
distinction at all) only needs to be adjusted to still accept the
service's own freshly-issued cookie as valid -- which any correct
implementation naturally does.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            banner1 = f.readline().strip()
            f.readline()  # second banner line

            if not banner1.startswith(b"COOKIE: "):
                return False, f"unexpected banner: {banner1!r}"
            cookie_hex = banner1.split(b": ", 1)[1]

            s.sendall(cookie_hex + b"\n")
            reply = f.readline().strip()
    except OSError as e:
        return False, f"connection failed: {e}"

    if reply != b"GOOD PADDING":
        return False, f"service's own fresh cookie was reported as {reply!r}, expected GOOD PADDING"
    return True, "service's own cookie round-trips as GOOD PADDING"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
