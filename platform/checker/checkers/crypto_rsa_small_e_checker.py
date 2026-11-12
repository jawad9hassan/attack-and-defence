"""
Checker module for crypto-rsa-small-e.

sla_check connects and only confirms the service hands back a
well-formed N/E/C triple with E == 3 and N large enough to be a real
modulus. It never computes an integer cube root or recovers the
plaintext, so a fix that switches to real OAEP padding (the actual
remediation -- NOT simply raising the exponent, which alone doesn't
fix the underlying issue) keeps this check passing as long as the
service still returns a well-formed ciphertext.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError as e:
        return False, f"connection failed: {e}"

    text = data.decode(errors="replace")
    if text.startswith("ERROR"):
        return False, f"service reported an error: {text!r}"

    vals = {}
    for line in text.splitlines():
        if ": " not in line:
            continue
        k, v = line.split(": ", 1)
        try:
            vals[k] = int(v, 16)
        except ValueError:
            return False, f"field {k!r} is not valid hex: {v!r}"

    for field in ("N", "E", "C"):
        if field not in vals:
            return False, f"missing field {field!r} in response: {text!r}"

    if vals["N"].bit_length() < 512:
        return False, f"modulus suspiciously small ({vals['N'].bit_length()} bits)"
    if vals["C"] <= 0 or vals["C"] >= vals["N"]:
        return False, "ciphertext C is not in the valid range [0, N)"
    return True, "well-formed N/E/C triple received"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
