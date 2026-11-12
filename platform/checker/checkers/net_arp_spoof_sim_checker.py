"""
Checker module for the net-arp-spoof-sim service.

sla_check never sends ARP_REPLY, so it never poisons anything. It
confirms REQUEST_FLAG completes normally and that an uninvolved MAC
(never mentioned anywhere else) receives nothing -- a benign, secure-
by-default outcome that holds whether or not the ARP_REPLY validation
bug has been fixed, since the checker never triggers that bug itself.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            s.settimeout(3)
            f.readline()  # banner line 1
            f.readline()  # banner line 2
            s.sendall(b"REQUEST_FLAG\n")
            request_resp = f.readline()
            s.sendall(b"READ_MAILBOX MAC-UNINVOLVED-CHECKER\n")
            mailbox_resp = f.readline()
    except OSError as e:
        return False, f"connection failed: {e}"

    if not request_resp.startswith(b"fileserver replied"):
        return False, f"REQUEST_FLAG did not behave normally: {request_resp!r}"
    if mailbox_resp != b"EMPTY\n":
        return False, f"an uninvolved mailbox was not empty: {mailbox_resp!r}"
    return True, "normal request/reply flow works and leaks nothing to an uninvolved party"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
