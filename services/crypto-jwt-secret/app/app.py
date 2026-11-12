"""
crypto-jwt-secret: a JWT-based session, correctly signed and correctly
verified (HS256, pinned, no "alg: none" bypass -- that bug already
lives at web-authbypass-jwt, this is a different one) -- but signed
with a WEAK, GUESSABLE secret key instead of a long random one.

Unlike web-authbypass-jwt, the server here does everything "right" at
the protocol level: it only ever accepts HS256, and it verifies the
signature with `hmac.compare_digest` before trusting anything in the
payload. The entire bug is the VALUE of the secret itself -- short
enough and common enough that an attacker who captures a valid guest
token can brute-force the signing key offline (by trying candidate
secrets and re-signing the same payload until the signature matches),
then use the recovered key to forge their OWN token with
`"role": "admin"`.
"""
import base64
import hashlib
import hmac
import json
import os

from flask import Flask, make_response, render_template_string, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

# --- VULNERABLE: short, guessable secret -- the kind of value that
# shows up near the top of any common-password/common-secret wordlist.
# Everything ELSE about this JWT implementation is done correctly. -----
SECRET = os.environ.get("JWT_SECRET", "letmein")
# -------------------------------------------------------------------------


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
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
        given_sig = b64url_decode(s_b64)
    except Exception:
        return None

    # --- Correctly pinned: ONLY HS256 is ever accepted, no "none",
    # no algorithm confusion. This service does not have that bug. -----
    if header.get("alg") != "HS256":
        return None
    signing_input = f"{h_b64}.{p_b64}".encode()
    expected_sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(given_sig, expected_sig):
        return None
    return payload


INDEX_PAGE = """
<!doctype html>
<title>MiniCorp Portal v2</title>
<h2>MiniCorp Internal Portal v2</h2>
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
