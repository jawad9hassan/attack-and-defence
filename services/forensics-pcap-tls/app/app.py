"""
forensics-pcap-tls: an "encrypted" capture where the key itself is
recoverable from metadata sent in the clear during the handshake.

This is the capstone of the Digital Forensics ladder: everything
earlier in the category (forensics-pcap-basic, forensics-pcap-ftp)
was about FINDING the right plaintext data in a capture. This one
goes a step further -- the application data really is encrypted
(a stream cipher keystream XORed over the payload), but the toy
protocol's handshake hands you everything needed to derive the key
yourself, in cleartext, right there in the same capture:

  1. Client sends  "HELLO proto=sessionsec/1"
  2. Server sends  "SERVER_NONCE=<32 hex chars>"
  3. Client sends  "READY"
  4. Server sends the encrypted application data: a short stream
     of bytes that is the flag XORed against a repeating keystream.

The keystream is derived as:

    key = sha256(SERVER_NONCE_bytes + PROTOCOL_LABEL)

...where PROTOCOL_LABEL is the literal ASCII bytes of the protocol
string the client sent in step 1 ("sessionsec/1") -- a fixed,
publicly-documented label, not a secret. SERVER_NONCE is sent in
plaintext in step 2. Everything needed to reproduce `key` is sitting
directly in the capture; nothing needs to be brute-forced or guessed.
This mirrors a real, surprisingly common mistake: deriving a
"session key" entirely from values transmitted in the clear, with no
actual secret contributing to it at all.
"""
import hashlib
import os
import sys

from flask import Flask, Response, render_template_string

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

sys.path.insert(0, "/opt")
from pcap_writer import PcapWriter, TcpStream  # noqa: E402

PROTOCOL_LABEL = b"sessionsec/1"

CLIENT_MAC = b"\x02\x00\x00\x00\x50\x11"
SERVER_MAC = b"\x02\x00\x00\x00\x50\x22"
CLIENT_IP = "10.50.0.14"
SERVER_IP = "10.50.0.200"


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def _keystream(key: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def build_pcap() -> bytes:
    flag = read_current_flag()

    server_nonce = os.urandom(16)
    server_nonce_hex = server_nonce.hex().encode()

    key = hashlib.sha256(server_nonce_hex + PROTOCOL_LABEL).digest()
    keystream = _keystream(key, len(flag))
    ciphertext = bytes(a ^ b for a, b in zip(flag.encode(), keystream))

    w = PcapWriter()
    stream = TcpStream(
        client_mac=CLIENT_MAC, server_mac=SERVER_MAC,
        client_ip=CLIENT_IP, server_ip=SERVER_IP,
        client_port=52311, server_port=9443,
    )

    stream.client_to_server(w, b"HELLO proto=sessionsec/1\n")
    stream.server_to_client(w, b"SERVER_NONCE=" + server_nonce_hex + b"\n")
    stream.client_to_server(w, b"READY\n")
    stream.server_to_client(w, b"DATA " + ciphertext)

    return w.to_bytes()


INDEX_PAGE = """
<!doctype html>
<title>Capture: session-sec handshake</title>
<h2>Incident Capture: workstation-14</h2>
<p>A capture of a short "secure session" handshake and its encrypted
application data. The protocol is proprietary but its handshake is
plaintext -- work out how the session key is derived from what you
can see.</p>
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
