"""
forensics-pcap-ftp: the hardest challenge in the Digital Forensics
category. The capture contains TWO separate TCP conversations:

  1. An FTP-style control conversation (plaintext USER/PASS/RETR
     commands and server replies) on port 21 -- readable, but it
     doesn't contain the flag, just the login and the request for a
     file.
  2. A SEPARATE data conversation, on a different port pair, carrying
     the raw bytes of the file that got "transferred" -- that's where
     the flag actually is.

Unlike forensics-pcap-basic (rung 1), where the whole answer is in the
first and only stream, this one requires noticing that a capture can
contain more than one conversation, and specifically following the
*other* one. This mirrors how real FTP works: commands go over one TCP
connection, the actual file bytes go over a second one.
"""
import os
import sys

from flask import Flask, Response, render_template_string

sys.path.insert(0, "/opt")
from pcap_writer import PcapWriter, TcpStream  # noqa: E402

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

CLIENT_MAC = b"\x02\x00\x00\x00\x00\x1a"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x1b"
CLIENT_IP = "10.30.0.15"
SERVER_IP = "10.30.0.200"


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def build_pcap() -> bytes:
    flag = read_current_flag()
    writer = PcapWriter()

    # --- Conversation 1: FTP control channel (port 21) ---
    control = TcpStream(
        client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
        client_ip=CLIENT_IP, server_ip=SERVER_IP,
        client_port=52110, server_port=21,
    )
    control.server_to_client(writer, b"220 Welcome to ArchiveFTP\r\n")
    control.client_to_server(writer, b"USER anonymous\r\n")
    control.server_to_client(writer, b"331 Please specify the password.\r\n")
    control.client_to_server(writer, b"PASS guest@example.com\r\n")
    control.server_to_client(writer, b"230 Login successful.\r\n")
    control.client_to_server(writer, b"RETR flag.txt\r\n")
    control.server_to_client(
        writer, b"150 Opening BINARY mode data connection for flag.txt (data port 20).\r\n"
    )
    control.server_to_client(writer, b"226 Transfer complete.\r\n")

    # --- Conversation 2: FTP data channel (separate port pair) ---
    # This is where the actual file contents travel -- a different TCP
    # stream than the control conversation above.
    data_chan = TcpStream(
        client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
        client_ip=CLIENT_IP, server_ip=SERVER_IP,
        client_port=52111, server_port=20,
    )
    data_chan.server_to_client(writer, flag.encode() + b"\n")

    return writer.to_bytes()


INDEX_PAGE = """
<!doctype html>
<title>ArchiveFTP - Network Capture</title>
<h2>ArchiveFTP Monitoring</h2>
<p>A capture of someone downloading a file from the old archive FTP
server. The capture includes both the login/command traffic and the
actual file transfer.</p>
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
