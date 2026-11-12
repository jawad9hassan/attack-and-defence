"""
Checker module for forensics-pcap-ftp.

sla_check only confirms /capture.pcap returns a well-formed pcap with
more than one packet record -- it never parses out streams or reads the
flag, so this stays valid regardless of how a team reworks the
capture's contents during a defense exercise.
"""
import socket
import struct

import requests

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/capture.pcap", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    content = resp.content
    if len(content) < 24 or content[:4] != PCAP_MAGIC:
        return False, "response is not a valid pcap file"

    off = 24
    packet_count = 0
    while off + 16 <= len(content):
        _, _, caplen, _ = struct.unpack_from("<IIII", content, off)
        off += 16 + caplen
        packet_count += 1
    if packet_count < 2:
        return False, f"expected multiple packets, found {packet_count}"

    return True, "pcap capture served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
