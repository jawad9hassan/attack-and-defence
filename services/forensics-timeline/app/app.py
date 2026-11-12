"""
forensics-timeline: reconstructing an attack from THREE separate log
sources that each only tell part of the story.

A single log analysis (see `forensics-log-analysis`) is enough when
the whole attack shows up in one file. Real incidents rarely work
that way -- the firewall sees a port scan, the web server sees an
exploit attempt, and the auth system sees whatever account got
created or taken over, and nothing in any ONE of those logs says
"these three events are the same incident." You have to correlate
them yourself: same source IP, in the right time order, close enough
together to plausibly be one continuous attack.

The service serves a zip with three independent logs:

  - firewall.log   -- perimeter alerts: port scans, blocked connections
  - web_access.log -- nginx-style access log for the web app
  - auth.log       -- account-management events on the backend

Several IPs show up as "suspicious" across these files, but most of
them are decoys: an IP that port-scanned but never came back, an IP
that hit a weird URL once with no scan beforehand, an account change
with no corresponding web or firewall activity nearby. Only ONE IP
appears in all three logs, in the right order, within a tight enough
time window to be a single continuous attack -- a scan, then an
exploit attempt against the same host, then an admin account created
moments later. The flag is inside that one auth.log line.
"""
import io
import os
import random
import zipfile
from datetime import datetime, timedelta

from flask import Flask, Response, render_template_string

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

BASE_DAY = datetime(2026, 7, 9, 0, 0, 0)
REAL_ATTACKER_IP = "203.0.113.141"


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _nginx_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def build_logs() -> dict:
    """Returns {filename: text} for the three correlated logs."""
    flag = read_current_flag()
    rng = random.Random(2026)

    firewall_lines = []
    web_lines = []
    auth_lines = []

    # --- Decoy 1: a port scan that never leads anywhere. ---
    scan_ip = "198.51.100.23"
    scan_start = BASE_DAY + timedelta(hours=2, minutes=10)
    for i in range(6):
        t = scan_start + timedelta(seconds=i * 2)
        port = rng.choice([22, 23, 3389, 8080, 5900, 445])
        firewall_lines.append(
            f"{_ts(t)} ALERT src={scan_ip} dst_port={port} action=BLOCKED reason=port_scan"
        )

    # --- Decoy 2: a weird web hit with no preceding scan. ---
    odd_ip = "198.51.100.77"
    odd_t = BASE_DAY + timedelta(hours=5, minutes=30, seconds=12)
    web_lines.append(
        f'{odd_ip} - - [{_nginx_ts(odd_t)}] "GET /../../etc/passwd HTTP/1.1" 404 162'
    )

    # --- Decoy 3: an account change with nothing nearby. ---
    stray_t = BASE_DAY + timedelta(hours=9, minutes=5, seconds=0)
    auth_lines.append(
        f"{_ts(stray_t)} AUTH action=password_reset user=jsmith requested_by=10.1.2.14"
    )

    # --- Ordinary background traffic throughout the day. ---
    normal_ips = ["10.1.2.14", "10.1.2.31", "10.1.2.9", "10.1.2.52"]
    for hh in range(1, 23):
        t = BASE_DAY + timedelta(hours=hh, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ip = rng.choice(normal_ips)
        path = rng.choice(["/", "/catalog", "/login", "/api/status", "/static/app.css"])
        web_lines.append(
            f'{ip} - - [{_nginx_ts(t)}] "GET {path} HTTP/1.1" 200 {rng.randint(400, 5000)}'
        )
        if rng.random() < 0.3:
            auth_lines.append(
                f"{_ts(t)} AUTH action=login_success user={rng.choice(['jsmith','aortiz','deploy'])} from={ip}"
            )

    # --- The real attack chain, all REAL_ATTACKER_IP, tightly timed. ---
    attack_start = BASE_DAY + timedelta(hours=14, minutes=0, seconds=0)

    # Step 1: port scan against the web host.
    for i in range(5):
        t = attack_start + timedelta(seconds=i * 3)
        port = rng.choice([21, 22, 80, 443, 8443])
        firewall_lines.append(
            f"{_ts(t)} ALERT src={REAL_ATTACKER_IP} dst_port={port} action=BLOCKED reason=port_scan"
        )
    # One port gets through -- 443, the web app.
    t = attack_start + timedelta(seconds=16)
    firewall_lines.append(
        f"{_ts(t)} ALLOW src={REAL_ATTACKER_IP} dst_port=443 action=ALLOWED reason=web_app"
    )

    # Step 2: the exploit attempt against the web app, ~20s after the
    # scan wraps up.
    t2 = attack_start + timedelta(seconds=35)
    web_lines.append(
        f'{REAL_ATTACKER_IP} - - [{_nginx_ts(t2)}] '
        f'"POST /admin/users/create?role=admin HTTP/1.1" 201 88'
    )

    # Step 3: the account that exploit created, ~10s after the request
    # completes. This line has the flag.
    t3 = t2 + timedelta(seconds=11)
    auth_lines.append(
        f"{_ts(t3)} AUTH action=account_created user=svc-admin role=admin "
        f"created_by={REAL_ATTACKER_IP} note=\"{flag}\""
    )

    # A few more ordinary events after, so the attack isn't at the
    # literal end of every file.
    for hh in range(15, 23):
        t = BASE_DAY + timedelta(hours=hh, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ip = rng.choice(normal_ips)
        firewall_lines.append(f"{_ts(t)} ALLOW src={ip} dst_port=443 action=ALLOWED reason=web_app")

    firewall_lines.sort()
    web_lines.sort(key=lambda l: l.split("[")[1])
    auth_lines.sort()

    return {
        "firewall.log": "\n".join(firewall_lines) + "\n",
        "web_access.log": "\n".join(web_lines) + "\n",
        "auth.log": "\n".join(auth_lines) + "\n",
    }


def build_zip() -> bytes:
    logs = build_logs()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in logs.items():
            zf.writestr(name, text)
    return buf.getvalue()


INDEX_PAGE = """
<!doctype html>
<title>Incident Response Bundle</title>
<h2>Incident Response: prod-web-07, July 9</h2>
<p>Three independent log sources collected for the same day. Nothing
in any single file says which events belong to the same incident --
that's your job.</p>
<p><a href="/logs.zip">Download logs.zip</a></p>
<ul>
  <li><code>firewall.log</code> -- perimeter alerts</li>
  <li><code>web_access.log</code> -- web application access log</li>
  <li><code>auth.log</code> -- account management events</li>
</ul>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/logs.zip")
def logs_zip():
    data = build_zip()
    return Response(data, mimetype="application/zip",
                     headers={"Content-Disposition": "attachment; filename=logs.zip"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
