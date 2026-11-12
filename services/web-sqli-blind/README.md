# Challenge 8: Signup Check — Blind Boolean SQL Injection (SQLi rung 3 of 3)

**Ladder:** this is step 3, the last and hardest step, of the SQL
Injection progression. Step 1 is `services/web-notes` (bypass a login
check). Step 2 is `services/web-sqli-union` (extract data via a
database error message that leaks structure). Do those two first.

A "check if this username is available" form — the kind every signup
page has. It is vulnerable to SQL Injection, but **there is no error
message anywhere, ever**. The service only ever says one of two things:

- "Username already taken."
- "Username is available."

That's the entire interface. No stack traces, no "DB error: ...", no
extra data in the response. This is what SQLi looks like against a
reasonably well-built app that just happens to still build its query
with string concatenation.

## Running it

Standalone:

```bash
cd services/web-sqli-blind
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-sqli-blind   # from the repo root
```

Then open `http://localhost:5003`.

## The code (read it, that's the point)

Look at `app/app.py`. The query:

```python
query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
```

If the count is greater than 0, you see "already taken". Otherwise (or
if the query fails for ANY reason — the `except` block hides every
detail) you see "available". There's exactly one known username seeded
in the database: `admin`.

## Background: what "blind boolean-based" means

You can't see any data directly, and you can't see error messages. All
you get back, per request, is **one bit of information**: true or
false — "taken" or "available". That's still enough to extract an
entire flag, one character at a time, by asking the database a long
series of yes/no questions.

The trick: instead of asking "what is the flag?", you ask "does the
flag's first character equal `F`?", over and over, for every character
and every guess, until each position is pinned down.

A condition like:
```sql
admin' AND <something that's true or false>-- 
```
only reports "taken" (since `admin` really does exist) when the part
after `AND` is **also** true. That's your true/false signal.

## What you need to work out

### Suggested analysis steps

1. Confirm the baseline behavior:
   - `username=admin` → "already taken" (the row exists)
   - `username=some_totally_made_up_name` → "available"
2. Confirm you can control a boolean condition. Try `admin' AND 1=1-- `
   (should say taken) versus `admin' AND 1=2-- ` (should say available).
   If both match what you'd expect, you have a working true/false
   oracle.
3. The flag lives in a `secrets` table, column `flag_value` — same idea
   as `web-sqli-union`, just without the error messages to confirm
   anything. You'll need a subquery inside your condition, e.g. testing
   something about `(SELECT flag_value FROM secrets)`.
4. Two SQL functions you'll need:
   - `LENGTH(x)` — the length of a string
   - `SUBSTR(x, start, len)` — a substring starting at position `start`
     (1-indexed), `len` characters long
5. **This requires scripting, not clicking.** Doing this by hand,
   one character at a time, through a form, is impractical. Write a
   Python script using `requests` that:
   - first finds the flag's length (try `LENGTH(...) = 1`, `= 2`, `= 3`,
     ... until one comes back "taken")
   - then, for each position 1 through that length, tries every
     printable character in `SUBSTR(..., position, 1) = '<char>'`
     until one comes back "taken"
   - concatenates the results into the full flag

**Don't ask for the exact payload or the script.** You have the
technique, the table name, the column name, and the two SQL functions
you need. If you're stuck for more than 30-45 minutes, come back with
exactly what your `admin' AND 1=1-- ` / `admin' AND 1=2-- ` test showed,
and you'll get a sharper hint.

## Defender role

Same fix as every other SQLi challenge: **parameterized queries**.
Notice that this service was already "safer-looking" than the others
(no error details leaked) — and it was still just as exploitable. That's
the lesson: hiding error messages is not a fix, it only makes the attack
slower, not impossible. The only real fix is never building SQL out of
raw string concatenation in the first place.

After patching, confirm:
- `admin` still correctly reports "already taken"
- an unused username still correctly reports "available"
- `admin' AND 1=1-- ` and `admin' AND 1=2-- ` now report the **same**
  thing as each other (both "available", since the input is just a
  literal string with no SQL meaning anymore)

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd`. This service re-syncs the `secrets` table from that
file on every request, so your extraction script works unmodified every
round — you just need to re-run it each time, since the flag text (and
therefore its length and characters) changes.
