"""
web-idor-tokens: a "harder IDOR" -- instead of guessing a sequential
numeric id (web-idor), you have to guess a *token*. The catch: the
token isn't a real secret, it's a deterministic hash of a public value
(the account's username) with no secret salt or key mixed in at all.

Each account gets a "share link" of the form /n/<token> that shows its
note without logging in (a common real feature: "share this note with
anyone who has the link"). The token is generated as

    token = sha256(username)[:16]

which LOOKS random (16 hex chars) but is completely reproducible by
anyone who can guess or learn the target username -- no session, no
cookie, no secret key involved anywhere. The admin account's username
is never shown in the UI, but it's an extremely predictable value
("admin"), and the flag lives in the admin's note.

This is a step up from web-idor: there, the object id was already given
to you in your own URL and you just had to change a visible number.
Here, the identifier is a hash that *looks* unguessable, and the lesson
is that "looks random" and "is unforgeable" are not the same thing --
a token has to be generated from an actual secret (a server-side key,
or real CSPRNG state that isn't derivable from public input) to be
useful as an access-control credential.
"""
import hashlib
import os
import threading

from flask import Flask, render_template_string, request

app = Flask(__name__)
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
_lock = threading.Lock()


def read_current_flag() -> str:
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


# --- VULNERABLE: the "share token" is a hash of a PUBLIC value (the
# username) and nothing else. No secret key, no random salt, no server
# state -- just a deterministic function of information an attacker can
# guess or already knows. -----------------------------------------------
def make_token(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()[:16]
# -------------------------------------------------------------------------


NOTES = {
    "admin": None,  # filled in dynamically with the live flag on each request
    "alice": "Grocery list: oat milk, bread, coffee beans.",
    "bob": "Remember to renew the gym membership this month.",
}

INDEX_PAGE = """
<!doctype html>
<title>QuickNote - Shared Notes</title>
<h2>QuickNote</h2>
<p>Every note has a private "share link" at <code>/n/&lt;token&gt;</code>.
Anyone with the link can view the note -- no login needed. That's the
whole feature.</p>
<form method="GET" action="/n/{{ my_token }}">
  <button type="submit">Open my note (alice)</button>
</form>
<p style="color:gray">Demo account: alice. Her share link is shown above
for convenience -- in a real deployment this link would normally only
reach you by email/chat, not be printed on the homepage.</p>
"""

NOTE_PAGE = """
<!doctype html>
<title>Note</title>
<h2>Shared note</h2>
<pre>{{ content }}</pre>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_PAGE, my_token=make_token("alice"))


@app.route("/n/<token>")
def view_note(token):
    with _lock:
        NOTES["admin"] = read_current_flag()
        for username, content in NOTES.items():
            if make_token(username) == token:
                return render_template_string(NOTE_PAGE, content=content)
    return "No note behind that link.", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
