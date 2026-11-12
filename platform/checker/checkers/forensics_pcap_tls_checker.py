"""
Checker module for forensics-pcap-tls.

sla_check only confirms /capture.pcap returns a well-formed classic
libpcap file (magic number + at least one packet record) -- the same
shallow check used by every other pcap-serving checker on this
platform (forensics-pcap-basic, forensics-pcap-ftp,
net-c2-beacon-analysis). It never parses the TCP stream, derives any
key, or depends on the flag's location, so it stays valid regardless
of how a team reworks the capture's contents during a defense
exercise.
"""
import socket
import struct

import requests

PCAP_MAGIC = 0xA1B2C3D4


def sla_check(host, port):
    try:
        resp = requests.get(f"http://{host}:{port}/capture.pcap", timeout=5)
    except requests.RequestException as e:
        return False, f"connection failed: {e}"

    if resp.status_code != 200:
        return False, f"unexpected status code {resp.status_code}"

    body = resp.content
    if len(body) < 24:
        return False, "response is too short to be a pcap file"

    (magic,) = struct.unpack("<I", body[:4])
    if magic != PCAP_MAGIC:
        return False, "response does not have a valid pcap global header"

    if len(body) < 24 + 16:
        return False, "pcap file has no packet records"

    return True, "capture.pcap served correctly"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
