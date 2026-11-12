"""
platform/common/pcap_writer.py

A tiny, dependency-free helper for building a classic libpcap (.pcap,
NOT pcapng) file containing fabricated Ethernet/IPv4/TCP packets.

Why this exists instead of scapy/dpkt: the forensics "capture analysis"
challenges on this platform need to hand the attacker a realistic,
Wireshark-openable .pcap file, but pulling in scapy as a dependency adds
a heavy, slow-to-build package to services that otherwise have none at
all (this project has deliberately stayed minimal-dependency since the
start -- see crypto-xor, net-proto, re-crackme, all pure stdlib). This
module is NOT a general-purpose packet crafting library: it's just
enough to build simple one-directional "who sent what" TCP frames, with
correctly incrementing sequence numbers so Wireshark's "Follow TCP
Stream" reassembles them in order, and real (if not always
flag-perfect) IPv4/TCP checksums.

Usage:

    from pcap_writer import PcapWriter, TcpStream

    w = PcapWriter()
    stream = TcpStream(
        client_mac=b"\\x02\\x00\\x00\\x00\\x00\\x01", server_mac=b"\\x02\\x00\\x00\\x00\\x00\\x02",
        client_ip="10.0.0.5", server_ip="10.0.0.9",
        client_port=54321, server_port=80,
    )
    stream.client_to_server(w, b"GET / HTTP/1.1\\r\\n\\r\\n")
    stream.server_to_client(w, b"HTTP/1.1 200 OK\\r\\n\\r\\n")
    data = w.to_bytes()   # write this to a .pcap file
"""
import socket
import struct
import time


def _checksum16(data: bytes) -> int:
    """Internet checksum (RFC 1071) over `data`, padded to even length."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def build_eth_ip_tcp_packet(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
                             src_port: int, dst_port: int, seq: int, ack: int,
                             flags: int, payload: bytes) -> bytes:
    """Build one Ethernet+IPv4+TCP frame carrying `payload`."""
    eth = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)

    src_ip_b, dst_ip_b = _ip4(src_ip), _ip4(dst_ip)

    tcp_no_csum = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        5 << 4, flags, 65535, 0, 0,
    )
    tcp_segment_no_csum = tcp_no_csum + payload
    pseudo = struct.pack("!4s4sBBH", src_ip_b, dst_ip_b, 0, 6, len(tcp_segment_no_csum))
    tcp_csum = _checksum16(pseudo + tcp_segment_no_csum)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        5 << 4, flags, 65535, tcp_csum, 0,
    )
    tcp_segment = tcp_header + payload

    total_len = 20 + len(tcp_segment)
    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0, 64, 6, 0, src_ip_b, dst_ip_b,
    )
    ip_csum = _checksum16(ip_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0, 64, 6, ip_csum, src_ip_b, dst_ip_b,
    )

    return eth + ip_header + tcp_segment


# TCP flag bits
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_ACK = 0x10
FLAG_PSH = 0x08


class TcpStream:
    """
    Tracks sequence/ack numbers for one simulated TCP connection, so a
    sequence of client_to_server()/server_to_client() calls produces
    frames that reassemble correctly in Wireshark.
    """

    def __init__(self, client_mac, server_mac, client_ip, server_ip, client_port, server_port):
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = 1000
        self.server_seq = 5000

    def client_to_server(self, writer: "PcapWriter", payload: bytes, dt: float = 0.02):
        pkt = build_eth_ip_tcp_packet(
            self.client_mac, self.server_mac, self.client_ip, self.server_ip,
            self.client_port, self.server_port,
            self.client_seq, self.server_seq, FLAG_ACK | FLAG_PSH, payload,
        )
        writer.add_packet(pkt, dt=dt)
        self.client_seq += len(payload)

    def server_to_client(self, writer: "PcapWriter", payload: bytes, dt: float = 0.02):
        pkt = build_eth_ip_tcp_packet(
            self.server_mac, self.client_mac, self.server_ip, self.client_ip,
            self.server_port, self.client_port,
            self.server_seq, self.client_seq, FLAG_ACK | FLAG_PSH, payload,
        )
        writer.add_packet(pkt, dt=dt)
        self.server_seq += len(payload)


class PcapWriter:
    """Accumulates packets and serializes them as a classic libpcap file."""

    LINKTYPE_ETHERNET = 1

    def __init__(self):
        self._packets = []  # list of (sec, usec, data)
        self._t = time.time()

    def add_packet(self, data: bytes, dt: float = 0.02):
        self._t += dt
        sec = int(self._t)
        usec = int((self._t - sec) * 1_000_000)
        self._packets.append((sec, usec, data))

    def to_bytes(self) -> bytes:
        global_header = struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,              # magic number (native byte order)
            2, 4,                     # version major, minor
            0,                         # GMT to local correction
            0,                         # accuracy of timestamps
            65535,                     # snaplen
            self.LINKTYPE_ETHERNET,    # data link type
        )
        parts = [global_header]
        for sec, usec, data in self._packets:
            rec_header = struct.pack("<IIII", sec, usec, len(data), len(data))
            parts.append(rec_header + data)
        return b"".join(parts)
