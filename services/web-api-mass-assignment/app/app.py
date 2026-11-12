"""
web-api-mass-assignment: a tiny JSON signup API with a classic Mass
Assignment vulnerability.

The intended signup flow only asks for `username` and `password`. But
the handler builds the new user record by blindly merging the ENTIRE
parsed JSON body into a dict with defaults, instead of picking out
only the fields it actually meant to accept:

    user = {"role": "user", **request.get_json()}

Any extra field the client includes -- say, `"role": "admin"` -- rides
along and overwrites the default. Nothing in the signup form's HTML/UI
ever shows a role field; the only way to notice this is by reading (or
guessing) how the API itself is implemented and trying a field that
was never offered to you.

/api/admin requires the caller's account to have role == "admin" and
returns the flag.
"""
import os
import secrets
import threading

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")

USERS = {}       # username -> {"password": ..., "role": ...}
SESSIONS = {}     # token -> username
_lock = threading.Lock()


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


@app.route("/")
def index():
    return (
        "FileDrop API. POST /api/register {\"username\":..,\"password\":..} "
        "then POST /api/login with the same body to get a token, then "
        "GET /api/profile with header Authorization: Bearer <token>."
    )


# --- VULNERABLE: merges the ENTIRE client-supplied JSON body into the
# new user record. Only username/password are documented/intended, but
# any other key the client sends (e.g. "role") rides straight through
# and overwrites the server-chosen default. ------------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    with _lock:
        if username in USERS:
            return jsonify({"error": "username taken"}), 409
        user = {"role": "user", "password": password}
        user.update(data)  # <-- the bug: trusts the whole body, not an allowlist
        user["password"] = password  # password itself still can't be spoofed post-hoc
        USERS[username] = user
    return jsonify({"status": "registered", "username": username}), 201
# -------------------------------------------------------------------------


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    with _lock:
        user = USERS.get(username)
        if not user or user.get("password") != password:
            return jsonify({"error": "invalid credentials"}), 401
        token = secrets.token_hex(16)
        SESSIONS[token] = username

    return jsonify({"status": "ok", "token": token})


def _auth_user():
    auth = request.headers.get("Authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    with _lock:
        username = SESSIONS.get(token)
        return username, USERS.get(username) if username else None


@app.route("/api/profile")
def profile():
    username, user = _auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"username": username, "role": user.get("role", "user")})


@app.route("/api/admin")
def admin():
    username, user = _auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    if user.get("role") != "admin":
        return jsonify({"error": f"role '{user.get('role')}' is not admin"}), 403
    return jsonify({"flag": read_current_flag()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
