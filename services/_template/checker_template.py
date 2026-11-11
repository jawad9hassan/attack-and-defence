"""
Checker module template.

Copy this to platform/checker/checkers/<your-service>_checker.py and:
  1. Fill in sla_check() with your service's REAL, non-exploit behavior.
  2. put_flag() below is the same for almost every service — the flagd
     protocol doesn't change — so you can usually leave it as-is.
"""
import socket


def sla_check(host, port):
    """
    Exercise the service's normal functionality ONLY — never the
    vulnerability itself. Return (True, "some detail") if everything
    looks healthy, or (False, "what went wrong") otherwise.

    A broken-but-"patched" service must fail this check, the same way a
    real attack-defense checker would mark a team's service down.
    """
    raise NotImplementedError("fill this in for your service")


def put_flag(host, flagd_port, flagd_secret, flag):
    """Push `flag` into the service via its flagd sidecar."""
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
