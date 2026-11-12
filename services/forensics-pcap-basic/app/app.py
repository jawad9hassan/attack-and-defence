"""
forensics-pcap-basic: the easiest challenge in the Digital Forensics
category. A tiny web page offers one thing: a "network capture" from a
legacy internal monitoring tool. Nothing about the page asks you to
decode or extract anything -- it's a single plaintext HTTP exchange,
with the flag sitting in a form field in the clear. The entire exercise
is "open the capture and read it."

This mirrors a very real, very common finding in actual network
security assessments: an internal tool talking plain HTTP (not HTTPS)
that happens to put something sensitive in a request body or query
string, visible to literally anyone who can see the traffic.
"""
import os
import sys

from flask import Flask, Response, render_template_string

sys.path.insert(0, "/opt")
from pcap_writer import PcapWriter, TcpStream  # noqa: E402

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

CLIENT_MAC = b"\x02\x00\x00\x00\x00\x0a"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x0b"
CLIENT_IP = "10.20.0.15"
SERVER_IP = "10.20.0.200"


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_pcap() -> bytes:
    flag = read_current_flag()
    writer = PcapWriter()
    stream = TcpStream(
        client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
        client_ip=CLIENT_IP, server_ip=SERVER_IP,
        client_port=53214, server_port=80,
    )
    request_body = f"user=svc_monitor&session_debug_token={flag}"
    http_request = (
        "POST /internal/debug-echo HTTP/1.1\r\n"
        "Host: legacy-monitor.internal\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(request_body)}\r\n"
        "\r\n"
        f"{request_body}"
    ).encode()
    http_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "ok"
    ).encode()
    stream.client_to_server(writer, http_request)
    stream.server_to_client(writer, http_response)
    return writer.to_bytes()


INDEX_PAGE = """
<!doctype html>
<title>Legacy Monitor - Capture Export</title>
<h2>Legacy Monitor Tool</h2>
<p>This internal tool was replaced years ago, but the box is still
running. Someone left packet capturing on for "debugging" and never
turned it off.</p>
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
