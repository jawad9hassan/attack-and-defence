import sqlite3
import os
from flask import Flask, request, render_template_string, g

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag():
    """Read the live flag fresh on every request.

    The flag file is owned by the `flagd` sidecar (see
    platform/common/flagd.py), which the checker rewrites once per
    round. Reading it fresh here (instead of caching it at startup)
    is what makes flag rotation actually work without restarting the
    app.
    """
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )"""
    )
    # Seed data. The 'admin' row holds the flag-bearing role.
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("guest", "guestpass", "guest"),
            ("alice", "alicepass123", "user"),
            ("bob", "bobsecurepw", "user"),
            ("admin", os.environ.get("ADMIN_PASSWORD", "sup3rSecretAdminPW!"), "admin"),
        ],
    )
    conn.commit()
    conn.close()


LOGIN_PAGE = """
<!doctype html>
<title>Notes App - Login</title>
<h2>Notes App Login</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if result %}<pre>{{ result }}</pre>{% endif %}
"""

WELCOME_PAGE = """
<!doctype html>
<title>Welcome</title>
<h2>Welcome, {{ username }}!</h2>
<p>Your role: {{ role }}</p>
{% if role == 'admin' %}
<p><b>FLAG:</b> {{ flag }}</p>
{% else %}
<p>Only admins can see the flag.</p>
{% endif %}
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, error=None, result=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- VULNERABLE QUERY: raw string formatting instead of parameters ---
    query = "SELECT username, role FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    # ----------------------------------------------------------------------

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(query)
        row = cur.fetchone()
    except Exception as e:
        return render_template_string(LOGIN_PAGE, error=f"DB error: {e}", result=None)

    if row:
        uname, role = row
        return render_template_string(
            WELCOME_PAGE, username=uname, role=role, flag=read_current_flag()
        )
    else:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials", result=None)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
