"""
crypto-weak-hash: a login system that hashes passwords with a single
unsalted, fast general-purpose hash (SHA-256) and nothing else -- no
salt, no per-user randomness, no slow/memory-hard KDF (bcrypt, scrypt,
Argon2). A "debug" endpoint (a very common real-world leftover) leaks
the raw password hash for any username, which should never happen --
but the deeper bug this challenge teaches is that even WITH that leak,
a properly-hashed password (salted + a slow KDF) would still be
infeasible to crack in any reasonable time, whereas a bare SHA-256
hash of a common password is crackable in milliseconds with an
ordinary wordlist.

The admin's password is a common, real-world top-100-style password --
deliberately weak, because the lesson here is "weak hash function
choice", not "unguessable secret kept otherwise safe".
"""
import hashlib
import os

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def weak_hash(password: str) -> str:
    # --- VULNERABLE: a single round of a fast, general-purpose hash,
    # with no salt and no per-user randomness at all. -------------------
    return hashlib.sha256(password.encode()).hexdigest()
    # -------------------------------------------------------------------


USERS = {
    "alice": weak_hash("correct-horse-battery-staple-99"),
    "admin": weak_hash("sunshine1"),  # a real top-100 common password
}

PAGE = """
<!doctype html>
<title>MiniAuth</title>
<h2>MiniAuth</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Log in</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if flag %}<p>Welcome, admin. The flag is: {{ flag }}</p>{% endif %}
<p style="color:gray">Debug endpoint for support engineers:
/debug/hash?username=&lt;name&gt; (yes, this really should not exist
in production -- it's how real incidents like this happen).</p>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, error=None, flag=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    expected = USERS.get(username)
    if expected is None or weak_hash(password) != expected:
        return render_template_string(PAGE, error="Invalid credentials", flag=None)
    flag = read_current_flag() if username == "admin" else None
    return render_template_string(PAGE, error=None, flag=flag)


# --- The "debug" leftover: leaks the raw stored hash for any username,
# with no auth of its own. A real incident class (support/debug
# tooling left reachable in production). --------------------------------
@app.route("/debug/hash")
def debug_hash():
    username = request.args.get("username", "")
    h = USERS.get(username)
    if h is None:
        return jsonify({"error": "no such user"}), 404
    return jsonify({"username": username, "sha256": h})
# -------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
