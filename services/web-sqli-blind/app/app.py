"""
web-sqli-blind: a "is this username available?" signup check with a
BLIND boolean-based SQL Injection vulnerability.

Unlike web-notes (visible auth bypass) and web-sqli-union (a database
error message handed to you on a plate when something's wrong), this
service shows NO error messages at all, ever. It only ever answers one
of two fixed sentences: "Username already taken." or "Username is
available.". That's it. That's the entire interface.

This is much closer to how a well-built real-world app leaks almost
nothing -- and yet is still fully exploitable, one true/false bit at a
time, because the underlying query is still built by raw string
concatenation.
"""
import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "signup.db")
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag_value TEXT)")
    cur.execute("INSERT INTO users (username) VALUES ('admin')")
    cur.execute("INSERT INTO secrets (id, flag_value) VALUES (1, ?)", ("FLAG{waiting_for_first_round}",))
    conn.commit()
    conn.close()


PAGE = """
<!doctype html>
<title>Sign Up - Username Check</title>
<h2>Check username availability</h2>
<form method="GET" action="/check">
  Desired username: <input name="username" value="{{ username or '' }}">
  <button type="submit">Check</button>
</form>
<p><b>{{ message }}</b></p>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, username=None, message="")


@app.route("/check")
def check():
    username = request.args.get("username", "")
    db = get_db()
    try:
        # Keep secrets.flag_value in sync with the live flag file, so
        # flag rotation is reflected immediately.
        db.execute("UPDATE secrets SET flag_value = ? WHERE id = 1", (read_current_flag(),))
        db.commit()

        # --- VULNERABLE QUERY: raw string formatting instead of parameters ---
        query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
        # ----------------------------------------------------------------------
        count = db.execute(query).fetchone()[0]
        message = "Username already taken." if count > 0 else "Username is available."
    except Exception:
        # Deliberately NO error detail at all -- this is what makes it
        # "blind". Any failure (syntax error, anything) just looks like
        # the username is available.
        message = "Username is available."
    finally:
        db.close()

    return render_template_string(PAGE, username=username, message=message)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
