"""
forensics-log-analysis: a fabricated SSH authentication log
(syslog-style text, the same format real `/var/log/auth.log` uses)
built to practice the most basic log-analysis workflow: scroll past a
day's worth of normal logins, notice a burst of failures from one IP
that doesn't belong, and see what the attacker did right after they
finally got in.

The log mixes:
  - A handful of ordinary logins throughout the day from a few
    regular employee IPs, each succeeding on the first try.
  - A dense burst of "Failed password" lines for the `admin` account,
    all from ONE IP, spaced a fraction of a second apart -- the
    unmistakable signature of an automated brute-force tool, not a
    person mistyping a password a couple of times.
  - One "Accepted password" line for `admin` from that same IP,
    right after the burst -- the brute force succeeded.
  - A final line recording the very next thing that IP did once
    logged in: read the flag file. The flag is right there in the
    clear.
"""
import os
import random

from flask import Flask, Response, render_template_string

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

HOST = "prod-web-03"
EMPLOYEE_IPS = ["10.1.2.14", "10.1.2.31", "10.1.2.9"]
ATTACKER_IP = "198.51.100.66"


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def _fmt(month, day, hh, mm, ss):
    return f"{month} {day:2d} {hh:02d}:{mm:02d}:{ss:02d}"


def build_log() -> bytes:
    flag = read_current_flag()
    rng = random.Random(777)
    lines = []
    pid_counter = [8000]

    def next_pid():
        pid_counter[0] += 1
        return pid_counter[0]

    # Ordinary logins scattered through the day.
    for hh in (8, 11, 13, 16):
        mm, ss = rng.randint(0, 59), rng.randint(0, 59)
        ip = rng.choice(EMPLOYEE_IPS)
        user = rng.choice(["deploy", "jsmith", "aortiz"])
        port = rng.randint(40000, 60000)
        pid = next_pid()
        lines.append(
            f"{_fmt('Jun', 14, hh, mm, ss)} {HOST} sshd[{pid}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2"
        )

    # The brute-force burst against `admin`, all from one IP, all
    # within about 20 seconds.
    burst_hh, burst_mm, burst_ss = 3, 12, 0
    for i in range(40):
        burst_ss += rng.randint(0, 1)
        if burst_ss >= 60:
            burst_ss -= 60
            burst_mm += 1
        pid = next_pid()
        port = 51000 + i
        lines.append(
            f"{_fmt('Jun', 14, burst_hh, burst_mm, burst_ss)} {HOST} sshd[{pid}]: "
            f"Failed password for admin from {ATTACKER_IP} port {port} ssh2"
        )

    # The burst succeeds.
    burst_ss += 1
    pid = next_pid()
    lines.append(
        f"{_fmt('Jun', 14, burst_hh, burst_mm, burst_ss)} {HOST} sshd[{pid}]: "
        f"Accepted password for admin from {ATTACKER_IP} port 51099 ssh2"
    )

    # And the very next thing the attacker does once in.
    burst_ss += 2
    pid = next_pid()
    lines.append(
        f"{_fmt('Jun', 14, burst_hh, burst_mm, burst_ss)} {HOST} bash[{pid}]: "
        f"admin ran: cat /root/flag.txt => {flag}"
    )

    # A couple more ordinary logins after, so the attack isn't the
    # literal last line of the file.
    for hh in (18, 20):
        mm, ss = rng.randint(0, 59), rng.randint(0, 59)
        ip = rng.choice(EMPLOYEE_IPS)
        user = rng.choice(["deploy", "jsmith"])
        port = rng.randint(40000, 60000)
        pid = next_pid()
        lines.append(
            f"{_fmt('Jun', 14, hh, mm, ss)} {HOST} sshd[{pid}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2"
        )

    lines.sort(key=lambda l: l.split(f"{HOST}")[0])
    return ("\n".join(lines) + "\n").encode()


INDEX_PAGE = """
<!doctype html>
<title>SOC Triage - Authentication Log</title>
<h2>SOC Triage: prod-web-03 Authentication Log</h2>
<p>A production box's authentication log for the day. Something in
here isn't a normal login.</p>
<p><a href="/auth.log">Download auth.log</a></p>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/auth.log")
def auth_log():
    data = build_log()
    return Response(data, mimetype="text/plain",
                     headers={"Content-Disposition": "attachment; filename=auth.log"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
