# Challenge 7: Gadget Shop — UNION-based SQL Injection (SQLi rung 2 of 3)

**Ladder:** this is step 2 of the SQL Injection progression. Step 1 is
`services/web-notes` (bypass a login check). Step 3 is
`services/web-sqli-blind` (extract data with no visible error messages
at all). Do this one after `web-notes`.

A product search page with a SQL Injection vulnerability — but this time
the goal isn't to bypass a login, it's to **read data from a completely
different table** than the one the search feature was ever meant to
touch. This is closer to what SQLi actually looks like in the wild: an
attacker pulling out data the application never intended to expose
through any UI at all.

## Running it

Standalone:

```bash
cd services/web-sqli-union
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-sqli-union   # from the repo root
```

Then open `http://localhost:5002`.

## The code (read it, that's the point)

Look at `app/app.py`. The search feature builds its query like this:

```python
query = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
```

Your search term `q` goes straight into the query string, between the
`%` wildcards. There are **two tables** in this database: `products`
(what the search feature shows you) and `secrets` (where the flag
lives) — the search feature never queries `secrets` on its own.

## Background: what UNION-based SQLi actually does

`web-notes` (step 1) was about breaking a `WHERE` clause so it always
matched. UNION injection is a different move: SQL's `UNION SELECT` lets
you **stack a second, entirely different query** onto the first one, and
get both results merged into one result set — as long as the second
query returns **the same number of columns**, in a compatible order, as
the first.

So the attack has two parts:

1. **Figure out how many columns the original query returns.** You can't
   see the query's source from here (pretend you can't, even though you
   technically can in this training repo) — you have to discover it
   through the app's behavior alone.
2. **Write a `UNION SELECT` that returns that many columns, pulling from
   the `secrets` table instead of `products`.**

## What you need to work out

### Suggested analysis steps

1. Try a normal search (e.g. `lap`) and see the two-column table that
   comes back: name, price.
2. **Find the column count without reading the source.** A classic,
   reliable technique: `ORDER BY <n>`. If you add `' ORDER BY 1-- ` to
   your search term, the query still has exactly one more clause than it
   expects — does it error? Try `ORDER BY 2`, `ORDER BY 3`, etc. One of
   them will produce a database error like "ORDER BY term out of range"
   — the number just below that is your column count. (You'll need a
   closing `'` before `ORDER BY` to end the `LIKE` pattern, and a
   trailing `-- ` with a space after it to comment out the rest of the
   original query.)
3. Once you know the column count, write a `UNION SELECT` that:
   - closes the `LIKE` pattern's opening quote
   - selects from `secrets` instead of `products`
   - returns exactly that many columns (pad extra columns with a
     placeholder value like `0` if `secrets` doesn't have that many)
   - comments out whatever's left of the original query after your
     injected text
4. Submit it through the search box, or with curl:
   ```bash
   curl -G "http://localhost:5002/search" --data-urlencode "q=<your payload>"
   ```
5. The flag should show up as if it were just another "product" in the
   results table.

**Don't ask for the exact payload.** You now have everything you need
(the column-count technique, the table name, the comment syntax) to
build it yourself. If you're stuck for more than 20-30 minutes, come
back with what you tried for the `ORDER BY` step specifically and what
happened.

## Defender role

Same root cause as `web-notes`, same fix: **parameterized queries**
instead of string concatenation. But notice something extra this time —
even with parameters, think about whether the `secrets` table needs to
be reachable from this code path **at all**. A second layer of defense
(not strictly required to pass the checker, but worth discussing as a
team): least-privilege database access, so even a successful injection
in one feature can't reach tables that feature has no legitimate reason
to touch.

After patching, confirm:
- a normal search (e.g. `lap`) still returns matching products
- a search containing a single quote `'` no longer causes a "DB error" —
  it should just return zero results, like a literal apostrophe search
- the `UNION SELECT ... FROM secrets` payload that worked before no
  longer returns the flag

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd`. This service re-syncs the `secrets` table from that
file on every search request, so the exploit technique and column count
stay exactly the same each round; only the flag text itself rotates.
