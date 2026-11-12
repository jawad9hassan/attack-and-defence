"""
web-sqli-union: a tiny product search page with a UNION-based SQL
Injection vulnerability.

Unlike web-notes (where the goal was just to bypass a login check), here
the goal is to actually EXTRACT data from a completely different table
than the one the application normally queries -- a step up in both
technique and consequence: this is what SQLi looks like when the target
isn't "log in as someone else" but "read data you were never shown any
UI for at all".

The flag lives in a `secrets` table that the normal search feature never
touches.
"""
import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def read_current_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "FLAG{missing_flag_file}"


def get_db():
    db = sqlite3.connect(DB_PATH)
    return db


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER)")
    cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag_value TEXT)")
    cur.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [
            ("Laptop", 999),
            ("Wireless Mouse", 20),
            ("Mechanical Keyboard", 75),
            ("4K Monitor", 350),
            ("USB-C Hub", 30),
        ],
    )
    cur.execute("INSERT INTO secrets (id, flag_value) VALUES (1, ?)", ("FLAG{waiting_for_first_round}",))
    conn.commit()
    conn.close()


PAGE = """
<!doctype html>
<title>Gadget Shop - Search</title>
<h2>Gadget Shop</h2>
<form method="GET" action="/search">
  Search products: <input name="q" value="{{ q or '' }}">
  <button type="submit">Search</button>
</form>
{% if error %}<p style="color:red">DB error: {{ error }}</p>{% endif %}
{% if rows is not none %}
<table border="1" cellpadding="6">
  <tr><th>Name</th><th>Price</th></tr>
  {% for r in rows %}
  <tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td></tr>
  {% endfor %}
</table>
{% endif %}
"""


@app.route("/")
def index():
    return render_template_string(PAGE, q=None, rows=None, error=None)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    try:
        # Keep the secrets table in sync with the current flag file, so
        # flag rotation (via flagd) is reflected immediately without
        # restarting the service.
        db.execute("UPDATE secrets SET flag_value = ? WHERE id = 1", (read_current_flag(),))
        db.commit()

        # --- VULNERABLE QUERY: raw string formatting instead of parameters ---
        query = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
        # ----------------------------------------------------------------------
        cur = db.execute(query)
        rows = cur.fetchall()
        return render_template_string(PAGE, q=q, rows=rows, error=None)
    except Exception as e:
        return render_template_string(PAGE, q=q, rows=None, error=str(e))
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
