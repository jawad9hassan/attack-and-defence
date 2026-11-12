"""
Checker module for the net-tls-downgrade service.

sla_check always offers SECURE-V2 first (the server's own strongest
option) and confirms it negotiates SECURE-V2 and that GET_FLAG works
over that legitimate, strong session. It never sends a HELLO that
omits or deprioritizes SECURE-V2, so it never depends on the
version-negotiation bug -- a team that fixes the bug (server always
prefers its own strongest mutually supported version, and GET_FLAG
checks the version specifically rather than "any session") would
still pass, since the legitimate SECURE-V2 flow is untouched by that
fix.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            s.settimeout(3)
            f.readline()  # banner line 1
            f.readline()  # banner line 2
            s.sendall(b"HELLO SECURE-V2,PLAIN-V1\n")
            negotiated = f.readline()
            s.sendall(b"GET_FLAG\n")
            flag_resp = f.readline()
    except OSError as e:
        return False, f"connection failed: {e}"

    if negotiated != b"NEGOTIATED version=SECURE-V2\n":
        return False, f"did not negotiate SECURE-V2: {negotiated!r}"
    if not flag_resp.startswith(b"FLAG: "):
        return False, f"GET_FLAG failed over a legitimate SECURE-V2 session: {flag_resp!r}"
    return True, "SECURE-V2 negotiated and flag retrieved over the legitimate session"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
