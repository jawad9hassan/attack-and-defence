"""
web-ssrf: a "fetch a URL and show me its contents" link-preview feature
with a classic Server-Side Request Forgery vulnerability.

The main app listens on 0.0.0.0:5000 (reachable from outside the
container). A SEPARATE, internal-only admin API listens on
127.0.0.1:6677 -- bound to loopback only, inside the same container --
and was never meant to be reachable by anything outside this box at
all. It has no authentication, because the entire design assumes
"nothing outside this container can reach 127.0.0.1 on this box, so it
doesn't need auth" -- a very common (and very wrong) real-world
assumption.

The main app's /fetch feature makes an outbound HTTP request to
whatever URL the user gives it, with no restriction at all on the
target host. Since the request happens server-side, "whatever URL the
user gives it" includes 127.0.0.1 -- the server's own loopback
interface -- letting an external attacker reach the internal-only
admin API they could never have connected to directly.
"""
import os
import threading

from flask import Flask, render_template_string, request
import requests

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "6677"))


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


# --- The internal-only admin API. Bound to 127.0.0.1 ONLY, so it is
# never reachable from outside this container no matter what ports
# docker-compose publishes -- the only way in is from a process running
# INSIDE this same container, which is exactly what /fetch below is. ---
internal_app = Flask("internal-admin-api")


@internal_app.route("/secret")
def internal_secret():
    return read_current_flag()


def run_internal_api():
    internal_app.run(host="127.0.0.1", port=INTERNAL_PORT)
# -------------------------------------------------------------------------


PAGE = """
<!doctype html>
<title>LinkPeek</title>
<h2>LinkPeek - URL Preview</h2>
<form method="GET" action="/fetch">
  Paste a URL to preview: <input name="url" size="50" value="{{ url or '' }}">
  <button type="submit">Preview</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if content is not none %}
<hr>
<pre>{{ content }}</pre>
{% endif %}
"""


@app.route("/")
def index():
    return render_template_string(PAGE, url=None, content=None, error=None)


@app.route("/health")
def health():
    return "ok"


# --- VULNERABLE: fetches whatever URL the caller supplies, with no
# allowlist of hosts/schemes and no block on loopback/private ranges. --
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return render_template_string(PAGE, url=url, content=None, error="Give a URL.")
    try:
        resp = requests.get(url, timeout=5)
        content = resp.text[:2000]
    except requests.RequestException as e:
        return render_template_string(PAGE, url=url, content=None, error=f"Could not fetch: {e}")
    return render_template_string(PAGE, url=url, content=content, error=None)
# -------------------------------------------------------------------------


if __name__ == "__main__":
    threading.Thread(target=run_internal_api, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
