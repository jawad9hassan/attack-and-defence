"""
web-path-traversal: a tiny "note viewer" with a classic Directory /
Path Traversal vulnerability.

The feature is simple: pick a note by filename from `/view?file=<name>`,
and the server reads `notes/<name>` off disk and shows it. The bug is
that "<name>" is joined onto the notes directory with a plain string
join and never checked for `..` path segments or an absolute path --
so a filename like `../../../../flag.txt` walks straight out of the
`notes/` directory and reads whatever file the attacker asks for,
anywhere on the filesystem the process can read.

The flag is written to `/flag.txt` (standard platform location,
updated by flagd) -- the same absolute path every other service uses,
and the only interesting part of this challenge is proving you can
read a file that was never meant to be served through `/view` at all.
"""
import os

from flask import Flask, render_template_string, request

app = Flask(__name__)
NOTES_DIR = os.path.join(os.path.dirname(__file__), "notes")

PAGE = """
<!doctype html>
<title>FileDrop</title>
<h2>FileDrop - Note Viewer</h2>
<form method="GET" action="/view">
  File name: <input name="file" value="{{ file or '' }}">
  <button type="submit">View</button>
</form>
<p style="color:gray">Available notes: welcome.txt, changelog.txt</p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if content is not none %}
<hr>
<pre>{{ content }}</pre>
{% endif %}
"""


@app.route("/")
def index():
    return render_template_string(PAGE, file=None, content=None, error=None)


# --- VULNERABLE: the requested filename is joined onto NOTES_DIR with
# plain string concatenation / os.path.join, with no check that the
# result still lives inside NOTES_DIR. A value like "../../flag.txt"
# (or an absolute path like "/flag.txt") escapes the intended directory
# entirely. ---------------------------------------------------------------
@app.route("/view")
def view():
    filename = request.args.get("file", "")
    if not filename:
        return render_template_string(PAGE, file=filename, content=None, error="Give a file name.")

    path = os.path.join(NOTES_DIR, filename)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read(4000)
    except OSError as e:
        return render_template_string(PAGE, file=filename, content=None, error=f"Could not read file: {e}")
    return render_template_string(PAGE, file=filename, content=content, error=None)
# -------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
