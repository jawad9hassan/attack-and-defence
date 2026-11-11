# Challenge 1: Notes App (SQL Injection)

A small web app with a login page and a SQL Injection vulnerability in
`app/app.py`. Train both roles: **attacker** (extract the flag) and
**defender** (patch the bug without breaking the service).

## Running it

Standalone (its own compose file):

```bash
cd services/web-notes
docker compose up --build
```

Or as part of the full platform (recommended — gives you round-based flag
rotation and the live scoreboard):

```bash
# from the repo root
docker compose up --build web-notes
```

Then open `http://localhost:5000`.

## Attacker role

**Goal:** log in as `admin` without knowing the real password, and read
the flag.

### Suggested analysis steps

1. Open the page and try a normal login. `guest` / `guestpass` is seeded
   in the database, so it works, and shows you what the form posts to
   (`POST /login` with `username` and `password`).
2. The server builds a SQL query directly from your input. Try putting a
   single quote `'` in the `username` field and see what happens. A SQL
   error message back from the server is a strong signal the injection
   works.
3. Think about how to craft a value that makes the `WHERE` clause always
   true, or that selects the `admin` row regardless of the password.
   Review basic SQL: `OR`, comments (`--`), and how to close the quote the
   code already opened for you.
4. Try your payload through the form, or with curl:
   ```bash
   curl -X POST http://localhost:5000/login \
     -d "username=<your payload>" \
     -d "password=anything"
   ```
5. On success, the response shows `role: admin` and the current flag.

**Don't ask for the exact payload.** Try it yourself first. If you're
stuck for more than 20-30 minutes, come back and say exactly where you got
stuck, and you'll get a sharper hint (not the solution).

## Defender role

Once the team has found the bug (or even before, as a separate exercise):

1. **Fix** `app/app.py` without breaking normal login (`guest` /
   `guestpass` must keep working).
2. The correct fix for SQLi is **parameterized queries** instead of
   building the SQL string by hand. Look at Python's `sqlite3` docs for
   placeholders (`?`).
3. After patching, redeploy and confirm:
   - the legitimate login still works (the checker's SLA check will tell
     you immediately if you broke it)
   - the exact payload that worked before now fails

## Flag rotation

If you're running this as part of the full platform (not standalone),
the flag shown on the admin page changes every round — the checker
rotates it automatically via `flagd` (see `docs/ARCHITECTURE.md`). The
exploit technique stays identical; only the reward changes each round,
exactly like a real attack-defense game. Submit whatever flag you
currently extract — stale ones expire (`config/game.yml`'s
`flag_lifetime_rounds`).
