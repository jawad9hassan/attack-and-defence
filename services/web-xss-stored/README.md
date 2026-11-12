# Challenge: Guestbook (Web, ladder rung 7 of 10)

A public guestbook. Post a name and a message, and it shows up for
everyone who visits — including an "admin" who checks in on the
guestbook periodically with a privileged session. The flag lives behind
`/admin`, which only the admin's own session cookie can open.

## Running it

Standalone:

```bash
cd services/web-xss-stored
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-xss-stored   # from the repo root
```

Open `http://localhost:5006/board`.

## Attacker role

1. Post a comment with your name and a plain message. Notice it's
   rendered with **no escaping at all** — if you post something that
   looks like HTML, it comes back as real HTML.
2. There's no obvious way to log in as admin, and no password to
   guess. But something *does* periodically load this same page with
   the admin's session attached — otherwise `/admin` would be
   unreachable by anyone, ever, including the people running this
   challenge.
3. Think about what a comment could contain that doesn't just display
   something, but makes the *victim's own browser* send a request
   somewhere on the attacker's behalf, carrying something the victim
   has and the attacker doesn't: their session cookie.
4. The classic shape of that payload is an image tag whose `src`
   deliberately fails to load, with an `onerror` handler that fires
   instead — standard, widely documented "steal `document.cookie` via
   XSS" syntax. Stand up something to receive that request (even
   `python3 -m http.server` works), point the payload at it, post it,
   and wait a couple of seconds.
5. Whatever cookie value lands on your listener is the admin's. Use it
   against `/admin`.

**Don't ask for the exact payload string.** The shape above
(`<img src=x onerror="...">` with a `fetch(...)` call whose URL is
your listener and whose argument also includes `document.cookie`) is
standard, publicly documented XSS cookie-theft syntax — look it up by
name ("XSS cookie stealer payload") if you're unsure of the exact
characters, then post it as a guestbook message.

## Defender role

Open `app/app.py` and look at how comments are rendered:

```python
<p><b>{{ c.name|safe }}</b>: {{ c.message|safe }}</p>
```

The `|safe` filter tells Jinja2 "trust this completely, do not
HTML-escape it" — on attacker-controlled input. That's the entire bug:
Flask/Jinja2 autoescapes by default; this template explicitly turns
that protection back off.

The fix is simply removing `|safe` (letting Jinja2's default
autoescaping convert `<`, `>`, `"`, `'` and `&` in user content into
harmless entities) — or, if some formatting needs to be allowed, running
untrusted input through a real HTML sanitizer allowlist instead of
rendering it raw.

After patching, confirm:
- a plain-text comment (no markup) still displays exactly as typed
- a comment containing `<img ...>`/`<script>` now displays as literal
  text (you'll see the angle brackets on the page, not an image icon
  or a silently-executed tag)

## A note on the "admin bot"

No real browser or JavaScript engine runs in this container — see
`app/app.py`'s module docstring for exactly what the simulated admin
visitor does and doesn't recognize. It is a faithful model of the one
specific payload shape this challenge is built around, not a shortcut
around the vulnerability: a correctly escaped page behaves identically
to a patched page in front of a real browser (nothing fires, nothing
leaks), and an unescaped page leaks the cookie exactly as it would to a
real admin clicking a real link.

## Flag rotation

As part of the full platform, the flag `/admin` returns reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The admin's session cookie itself is generated
once per process start and does not rotate with the flag — only the
flag you read through it changes.

## Where this sits in the Web ladder

`web-idor-tokens` (rung 6) → **`web-xss-stored` (rung 7)** →
`web-ssrf` (rung 8). See `main.md` for the full ladder.
