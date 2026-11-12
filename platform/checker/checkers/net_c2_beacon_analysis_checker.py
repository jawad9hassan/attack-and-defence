"""
Checker module for net-c2-beacon-analysis.

sla_check only confirms /capture.pcap returns bytes that start with a
valid libpcap magic number and contain at least one packet record --
it never parses out the beacon or reads the flag itself, so this
stays valid regardless of how a team might rework the capture's
contents during a defense exercise, as long as a well-formed pcap
keeps coming back.
"""
import socket
import struct

import requests

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"  # little-endian 0xA1B2C3D4


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/capture.pcap", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"
    if len(resp.content) < 24 or resp.content[:4] != PCAP_MAGIC:
        return False, "response is not a valid pcap file"

    try:
        _, _, caplen, _ = struct.unpack_from("<IIII", resp.content, 24)
    except struct.error:
        return False, "pcap has no packet records"
    if caplen == 0 or 24 + 16 + caplen > len(resp.content):
        return False, "pcap packet record looks malformed"

    return True, "pcap capture served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
