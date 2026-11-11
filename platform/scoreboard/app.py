"""
Scoreboard — the flag submission server and live-score page.

Two kinds of callers:
  - the checker engine, which calls the /internal/* endpoints (protected
    by CHECKER_SECRET) to record each round's SLA results and to register
    newly-planted flags
  - everyone else (players), who call POST /api/submit to turn a captured
    flag into points, and GET / to watch the live scoreboard

All state lives in a single SQLite file, which is fine at this scale
(a handful of services, a handful of players, rounds every 60-120s).
"""
import os
import sqlite3
import time
from functools import wraps

from flask import Flask, g, jsonify, render_template, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/scoreboard.db")
CHECKER_SECRET = os.environ.get("CHECKER_SECRET")
ATTACK_POINTS_PER_FLAG = int(os.environ.get("ATTACK_POINTS_PER_FLAG", "10"))
DEFENSE_POINTS_PER_ROUND = int(os.environ.get("DEFENSE_POINTS_PER_ROUND", "1"))

if not CHECKER_SECRET:
    raise RuntimeError("CHECKER_SECRET environment variable is required")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sla_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            status TEXT NOT NULL,      -- 'up' or 'down'
            detail TEXT,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL UNIQUE,
            service TEXT NOT NULL,
            round_id INTEGER NOT NULL,
            expires_round INTEGER NOT NULL,
            captured_by TEXT,
            captured_at REAL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS leaderboard (
            submitter TEXT PRIMARY KEY,
            points INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    db.commit()
    db.close()


def require_checker_secret(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-Checker-Secret") != CHECKER_SECRET:
            return jsonify(error="forbidden"), 403
        return fn(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------
# Internal API (checker only)
# --------------------------------------------------------------------------


@app.post("/internal/round/start")
@require_checker_secret
def start_round():
    db = get_db()
    cur = db.execute("INSERT INTO rounds (started_at) VALUES (?)", (time.time(),))
    db.commit()
    return jsonify(round_id=cur.lastrowid)


@app.post("/internal/sla")
@require_checker_secret
def report_sla():
    data = request.get_json(force=True)
    db = get_db()
    db.execute(
        "INSERT INTO sla_results (round_id, service, status, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (data["round_id"], data["service"], data["status"], data.get("detail", ""), time.time()),
    )
    if data["status"] == "up":
        # Defense points accrue to a per-service pseudo-submitter so they
        # show up on the same leaderboard as attack points.
        submitter = f"defense:{data['service']}"
        db.execute(
            "INSERT INTO leaderboard (submitter, points) VALUES (?, ?) "
            "ON CONFLICT(submitter) DO UPDATE SET points = points + excluded.points",
            (submitter, DEFENSE_POINTS_PER_ROUND),
        )
    db.commit()
    return jsonify(ok=True)


@app.post("/internal/flag")
@require_checker_secret
def register_flag():
    data = request.get_json(force=True)
    db = get_db()
    db.execute(
        "INSERT INTO flags (value, service, round_id, expires_round, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (data["value"], data["service"], data["round_id"], data["expires_round"], time.time()),
    )
    db.commit()
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# Public API (players)
# --------------------------------------------------------------------------


@app.post("/api/submit")
def submit_flag():
    data = request.get_json(silent=True) or request.form
    flag_value = (data.get("flag") or "").strip()
    submitter = (data.get("submitter") or "anonymous").strip()[:32]

    if not flag_value:
        return jsonify(ok=False, reason="missing flag"), 400

    db = get_db()
    row = db.execute("SELECT * FROM flags WHERE value = ?", (flag_value,)).fetchone()
    if row is None:
        return jsonify(ok=False, reason="no such flag"), 404

    current_round = db.execute(
        "SELECT COALESCE(MAX(id), 0) AS r FROM rounds"
    ).fetchone()["r"]

    if current_round > row["expires_round"]:
        return jsonify(ok=False, reason="flag expired"), 410

    if row["captured_by"] is not None:
        return jsonify(ok=False, reason="already captured"), 409

    db.execute(
        "UPDATE flags SET captured_by = ?, captured_at = ? WHERE id = ?",
        (submitter, time.time(), row["id"]),
    )
    db.execute(
        "INSERT INTO leaderboard (submitter, points) VALUES (?, ?) "
        "ON CONFLICT(submitter) DO UPDATE SET points = points + excluded.points",
        (submitter, ATTACK_POINTS_PER_FLAG),
    )
    db.commit()
    return jsonify(ok=True, points_awarded=ATTACK_POINTS_PER_FLAG, service=row["service"])


# --------------------------------------------------------------------------
# Live scoreboard page
# --------------------------------------------------------------------------


@app.get("/api/state")
def state():
    db = get_db()
    current_round = db.execute(
        "SELECT COALESCE(MAX(id), 0) AS r FROM rounds"
    ).fetchone()["r"]

    services = db.execute(
        """
        SELECT service,
               (SELECT status FROM sla_results s2
                WHERE s2.service = s1.service
                ORDER BY id DESC LIMIT 1) AS latest_status,
               SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) AS up_rounds,
               COUNT(*) AS total_rounds
        FROM sla_results s1
        GROUP BY service
        ORDER BY service
        """
    ).fetchall()

    leaderboard = db.execute(
        "SELECT submitter, points FROM leaderboard ORDER BY points DESC LIMIT 25"
    ).fetchall()

    captures = db.execute(
        """
        SELECT value, service, captured_by, captured_at FROM flags
        WHERE captured_by IS NOT NULL
        ORDER BY captured_at DESC LIMIT 15
        """
    ).fetchall()

    return jsonify(
        round=current_round,
        services=[dict(r) for r in services],
        leaderboard=[dict(r) for r in leaderboard],
        recent_captures=[dict(r) for r in captures],
    )


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
