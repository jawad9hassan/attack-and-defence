"""
net-c2-beacon-analysis: a blue-team-flavored challenge. A tiny web
page offers a "network capture" pulled from a workstation suspected of
being compromised. Nothing in the capture is encrypted or obfuscated
-- the exercise is entirely about SPOTTING malicious traffic among
normal-looking noise, the way a real SOC analyst would in Wireshark:
one connection, among many, that reaches out to the same external
address on a steady, machine-like interval, rather than the bursty,
irregular pattern of an actual human browsing the web.

The capture mixes:
  - Several ordinary-looking HTTP conversations to a couple of
    legitimate-looking destinations, at irregular (randomized)
    intervals -- exactly like a person clicking around a few
    websites.
  - A handful of short, identical-shaped connections to ONE fixed
    external IP:port, spaced at a constant, unvarying interval --
    the unmistakable signature of an automated beacon checking in
    with a command-and-control server. Each one gets an "ACK:<flag>"
    response from that one server, carrying the flag in the clear.

Nothing here is hidden beyond "there are several conversations in
this capture, and one of them doesn't look like the others."
"""
import os
import random
import sys

from flask import Flask, Response, render_template_string

sys.path.insert(0, "/opt")
from pcap_writer import PcapWriter, TcpStream  # noqa: E402

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

WORKSTATION_IP = "10.40.0.23"
WORKSTATION_MAC = b"\x02\x00\x00\x00\x40\x17"

NORMAL_SITES = [
    ("93.184.216.34", 80, b"\x02\x00\x00\x00\x00\x01", "GET /index.html HTTP/1.1\r\nHost: example-news.test\r\n\r\n"),
    ("198.51.100.9", 80, b"\x02\x00\x00\x00\x00\x02", "GET /search?q=weather HTTP/1.1\r\nHost: search-engine.test\r\n\r\n"),
    ("198.51.100.44", 443, b"\x02\x00\x00\x00\x00\x03", "GET /feed HTTP/1.1\r\nHost: social-feed.test\r\n\r\n"),
]

BEACON_IP = "203.0.113.77"
BEACON_PORT = 4444
BEACON_MAC = b"\x02\x00\x00\x00\x00\x99"
BEACON_INTERVAL = 30.0  # seconds, unvarying -- the tell


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_pcap() -> bytes:
    flag = read_current_flag()
    rng = random.Random(1337)  # deterministic-looking "normal" traffic shape
    writer = PcapWriter()

    # A dozen or so ordinary, irregularly-timed HTTP requests to a
    # couple of normal-looking sites, interleaved with the beacon.
    normal_events = []
    t = 0.0
    for _ in range(14):
        t += rng.uniform(1.5, 9.0)
        normal_events.append(t)

    beacon_events = [BEACON_INTERVAL * i for i in range(1, 7)]

    events = sorted(
        [(t, "normal") for t in normal_events] + [(t, "beacon") for t in beacon_events]
    )

    last_t = 0.0
    client_ports = {}
    for t, kind in events:
        dt = max(t - last_t, 0.05)
        last_t = t
        if kind == "normal":
            ip, port, mac, request = rng.choice(NORMAL_SITES)
            client_port = client_ports.get(ip, 50000 + rng.randint(0, 9000))
            client_ports[ip] = client_port + 1
            stream = TcpStream(
                client_mac=WORKSTATION_MAC, server_mac=mac,
                client_ip=WORKSTATION_IP, server_ip=ip,
                client_port=client_port, server_port=port,
            )
            stream.client_to_server(writer, request.encode(), dt=dt)
            response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            stream.server_to_client(writer, response.encode(), dt=0.05)
        else:
            client_port = 60000 + int(t)  # a fresh ephemeral port each beacon, like a real reconnect
            stream = TcpStream(
                client_mac=WORKSTATION_MAC, server_mac=BEACON_MAC,
                client_ip=WORKSTATION_IP, server_ip=BEACON_IP,
                client_port=client_port, server_port=BEACON_PORT,
            )
            stream.client_to_server(writer, b"BEACON", dt=dt)
            stream.server_to_client(writer, f"ACK:{flag}".encode(), dt=0.05)

    return writer.to_bytes()


INDEX_PAGE = """
<!doctype html>
<title>SOC Triage - Suspicious Workstation Capture</title>
<h2>SOC Triage: Workstation 10.40.0.23</h2>
<p>A user reported their machine "acting weird." IT pulled a short
network capture before reimaging it. Nothing in it is encrypted or
hidden -- somewhere in here is a conversation that doesn't belong.</p>
<p><a href="/capture.pcap">Download capture.pcap</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/capture.pcap")
def capture():
    data = build_pcap()
    return Response(data, mimetype="application/vnd.tcpdump.pcap",
                     headers={"Content-Disposition": "attachment; filename=capture.pcap"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
