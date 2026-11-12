# Challenge: LinkPeek (Web, ladder rung 8 of 10)

A "paste a URL and I'll show you what's there" preview tool — the kind
of feature real apps build for link unfurling, thumbnail generation,
or webhook validation. It fetches whatever URL you give it, server-side,
with no restriction on where that URL points.

## Running it

Standalone:

```bash
cd services/web-ssrf
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-ssrf   # from the repo root
```

Open `http://localhost:5007`.

## Attacker role

1. Try previewing a few ordinary URLs. The feature does exactly what
   it says: the server fetches the URL and shows you the response.
2. The request happens **server-side** — from inside the container,
   not from your browser. That means "any URL you can type" includes
   addresses your own browser could never reach directly: the
   server's own loopback interface.
3. There is exactly one other thing listening inside this container
   besides the app you can already see on your published port — an
   "internal admin API" that was designed assuming nothing outside the
   box could ever reach it, so it skipped authentication entirely.
4. Point the preview feature at that same loopback address, on a
   different port, and see what's being served there. (If you're not
   sure what port, think about why an SSRF-vulnerable preview tool
   would be a genuinely dangerous bug in the first place — it's
   usually because *something* sensitive is listening somewhere an
   external attacker normally can't reach. Try a handful of plausible
   "internal admin API" ports and a couple of plausible paths like
   `/secret`, `/admin`, `/internal`.)

**Don't ask for the exact port or path.** You have a working URL-fetch
primitive and the general idea (something internal-only is listening
on loopback) — scanning a short list of common ports/paths yourself is
the exercise, not a secret to be handed to you.

## Defender role

Open `app/app.py` and look at `/fetch`:

```python
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    ...
    resp = requests.get(url, timeout=5)   # <-- no restriction at all
```

There is no check on the target host, scheme, or IP range before the
server makes the request on the caller's behalf. The fix is an
**allowlist**, not a denylist — resolve the hostname, and reject the
request unless the resolved address is outside private/loopback/
link-local ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `169.254.0.0/16`, and IPv6 equivalents), and ideally
unless the host is on an explicit allowlist of known-safe destinations.
Blocking by hostname string alone (e.g. just rejecting the literal text
`"localhost"`) is not enough — a raw IP, a DNS name that resolves to a
private address, or alternate encodings of `127.0.0.1` all bypass a
naive string check.

The internal admin API itself should also not ship with zero
authentication just because it's "internal-only" — defense in depth
means a compromised/pivoted request still shouldn't get something for
free. But the primary, intended fix for this challenge is closing the
SSRF itself.

After patching, confirm:
- previewing an ordinary external-looking URL still works
- previewing `http://127.0.0.1:<internal-port>/...` (or any other
  loopback/private-range target) is now rejected

## Flag rotation

As part of the full platform, the internal admin API's `/secret`
response reflects `/flag.txt`'s current content, rotated every round
via `flagd` (see `docs/ARCHITECTURE.md`).

## Where this sits in the Web ladder

`web-xss-stored` (rung 7) → **`web-ssrf` (rung 8)** →
`web-path-traversal` (rung 9). See `main.md` for the full ladder.
