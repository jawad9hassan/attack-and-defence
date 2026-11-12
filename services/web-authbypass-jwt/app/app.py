"""
web-authbypass-jwt: a tiny site that logs you in as an ordinary "guest"
user and hands you a JWT (JSON Web Token) session cookie. An /admin page
checks that token's "role" claim and shows the flag only if it says
"admin". Nothing here lets you log in as an admin -- there is no admin
account at all.

The bug is in how the server VERIFIES the token, not in the login form.
A JWT has three base64url parts: header.payload.signature. The header
names which algorithm was used to sign it ("alg"). This server trusts
whatever "alg" the token itself claims, including the special value
"none" -- which means "this token isn't signed at all, don't check a
signature". A correct implementation pins exactly ONE expected
algorithm on the server side and rejects anything else; this one lets
the attacker pick "none" and hands back whatever payload they want,
completely unverified.

This is "alg confusion" / the classic "alg: none" JWT vulnerability,
one of the most common real-world JWT implementation mistakes.
"""
import base64
import hashlib
import hmac
import json
import os

from flask import Flask, make_response, render_template_string, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
# A real deployment would keep this secret and never let an attacker
# brute-force or guess it. It doesn't matter here: the "alg": "none"
# bypass skips signature checking entirely, so this secret is never
# even looked at on the exploit path.
SECRET = os.environ.get("JWT_SECRET", "dev-secret-not-that-it-matters")


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"


def verify_token(token: str):
    """Returns the payload dict if the token is valid, else None."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "")

    # --- VULNERABLE: the server branches on an algorithm the ATTACKER
    # chose, instead of pinning one expected algorithm. "none" means
    # skip signature verification entirely. -----------------------------
    if alg == "none":
        return payload
    # ---------------------------------------------------------------------
    elif alg == "HS256":
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected_sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
        try:
            given_sig = b64url_decode(s_b64)
        except Exception:
            return None
        if hmac.compare_digest(given_sig, expected_sig):
            return payload
        return None
    else:
        return None


INDEX_PAGE = """
<!doctype html>
<title>MiniCorp Portal</title>
<h2>MiniCorp Internal Portal</h2>
<p><a href="/login">Log in</a> to get a session token.</p>
<p><a href="/admin">Admin panel</a> (admins only).</p>
"""

LOGIN_PAGE = """
<!doctype html>
<title>Log in</title>
<h2>Log in</h2>
<form method="POST" action="/login">
  <button type="submit">Log in as guest</button>
</form>
{% if token %}
<p>Your session token (also set as a cookie <code>token</code>):</p>
<pre style="word-break:break-all">{{ token }}</pre>
{% endif %}
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE, token=None)

    token = issue_token({"user": "guest", "role": "user"})
    resp = make_response(render_template_string(LOGIN_PAGE, token=token))
    resp.set_cookie("token", token)
    return resp


@app.route("/admin")
def admin():
    token = request.cookies.get("token") or request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[len("Bearer "):]

    if not token:
        return "No session token. <a href='/login'>Log in</a> first.", 401

    payload = verify_token(token)
    if payload is None:
        return "Invalid session token.", 401

    if payload.get("role") != "admin":
        return f"Access denied: role '{payload.get('role')}' is not admin.", 403

    flag = read_current_flag()
    return f"Welcome, admin. The flag is: {flag}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
