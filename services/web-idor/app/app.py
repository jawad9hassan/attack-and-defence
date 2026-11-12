"""
web-idor: a tiny "private notes" app with a classic IDOR
(Insecure Direct Object Reference) vulnerability.

Each user has a numeric account id and can view their own note at
GET /note/<id> after "logging in" by just setting a cookie with their id
(no real auth — this mirrors how IDOR bugs actually happen: the code
checks *that* you're logged in, but never checks *which* object you're
allowed to look at).

The flag lives in the note belonging to the "admin" account (id 1).
"""
import os
import sqlite3
from flask import Flask, g, make_response, redirect, render_template_string, request

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag():
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
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    cur.execute(
        "CREATE TABLE notes (user_id INTEGER PRIMARY KEY, content TEXT)"
    )
    cur.executemany(
        "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
        [
            (1, "admin", "do-not-guess-this-either"),
            (2, "alice", "alicepass123"),
            (3, "bob", "bobsecurepw"),
        ],
    )
    cur.executemany(
        "INSERT INTO notes (user_id, content) VALUES (?, ?)",
        [
            (1, "ADMIN_NOTE_PLACEHOLDER"),  # filled in dynamically below
            (2, "Reminder: water the plants on Friday."),
            (3, "Shopping list: eggs, bread, coffee."),
        ],
    )
    conn.commit()
    conn.close()


LOGIN_PAGE = """
<!doctype html>
<title>Private Notes</title>
<h2>Private Notes - Sign in</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Sign in</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<p style="color:gray">Demo accounts: alice/alicepass123, bob/bobsecurepw</p>
"""

NOTE_PAGE = """
<!doctype html>
<title>Note</title>
<h2>Note for user #{{ user_id }} ({{ username }})</h2>
<pre>{{ content }}</pre>
<p><a href="/note/{{ my_id }}">Back to my note</a></p>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    row = db.execute(
        "SELECT id FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    if row is None:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")

    resp = make_response(redirect(f"/note/{row[0]}"))
    # Session is just "which user id are you" — nothing cryptographically
    # tied to the account. That's the setup; the bug is in what /note/<id>
    # does (or rather, doesn't) check below.
    resp.set_cookie("user_id", str(row[0]))
    return resp


@app.route("/note/<int:note_id>", methods=["GET"])
def view_note(note_id):
    my_id = request.cookies.get("user_id")
    if my_id is None:
        return redirect("/")

    db = get_db()
    # --- VULNERABLE: the code checks that *a* user is logged in, but
    # never checks that note_id == my_id (the logged-in user's own id).
    # Any authenticated user can view ANY note just by changing the URL.
    row = db.execute(
        "SELECT u.username, n.content FROM notes n "
        "JOIN users u ON u.id = n.user_id WHERE n.user_id = ?",
        (note_id,),
    ).fetchone()
    # ------------------------------------------------------------------

    if row is None:
        return "No such note", 404

    username, content = row
    if note_id == 1:
        content = read_current_flag()

    return render_template_string(
        NOTE_PAGE, user_id=note_id, username=username, content=content, my_id=my_id
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
