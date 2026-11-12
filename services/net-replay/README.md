# Challenge: MiniBank Terminal (Network, ladder rung 3 of 3)

The hardest challenge in the Network category. A tiny "bank terminal"
over plain TCP. Ordinary (unauthenticated) customers can check their
balance and make small withdrawals. Only an **admin session** can
approve a large, "privileged" withdrawal — and that privileged
withdrawal is what reveals the flag.

You never log in as admin. You never guess a password. You exploit the
fact that a previously-valid admin credential can simply be **reused**
— from a totally different, later connection — because the server
never invalidates it.

## Running it

Standalone:

```bash
cd services/net-replay
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build net-replay   # from the repo root
```

```bash
nc localhost 8002
```

## Background: what a replay attack actually is

A replay attack works like this: an attacker captures a piece of a
**legitimate** authentication exchange — a token, a signed request,
a session cookie, whatever the protocol uses — and later resends
("replays") that exact same piece of data to impersonate whoever it
belonged to. It works whenever a protocol doesn't bind that credential
to one specific use (a nonce), one specific time window (an
expiry), or one specific session.

In the real world, the "capture" step usually means something like
sniffing unencrypted network traffic. Here, to keep the challenge
self-contained, the service does something equally real and arguably
worse: it **logs the admin token straight into its own debug output**,
which every connection's banner includes.

## Attacker role

1. Connect and read the banner carefully — all of it, not just the
   command list.
2. `WITHDRAW 1000000` without authenticating — confirm you get denied.
3. Notice what's in that first debug line. Does it look like something
   that's supposed to only matter to the server's own logs — or
   something you could actually use?
4. Open a **second, separate connection** (this part matters: the
   point is that the same captured token works from an entirely
   different session, not just within the one it appeared in).
5. Send `AUTH <the token you captured>`.
6. Send `WITHDRAW 1000000` again.

**Don't ask for the exact token.** It's printed to you the moment you
connect — the exercise is recognizing that it's a usable credential,
not finding it.

## Defender role

Open `src/bank.py`. The bug:

```python
ADMIN_TOKEN = secrets.token_hex(8)   # generated ONCE, at process start
...
self.wfile.write(b"[debug] last admin session token=" + ADMIN_TOKEN.encode() + ...)
```

Two separate problems compound here:

1. **Leaking the token at all** — verbose/debug output that includes
   live credentials should never run in production.
2. **The token never changes.** Even without the debug leak, a real
   admin session should issue a fresh, single-use or short-lived token
   per login — never one static value good forever for the life of
   the process.

The fix: stop logging the token in the banner, AND make `AUTH` issue a
genuinely fresh, single-use (or short-expiry) token per real admin
login, instead of comparing against one static value.

After patching, confirm:
- the banner no longer contains anything resembling a usable
  credential
- a captured-from-nowhere "AUTH" attempt is rejected

## Flag rotation

As part of the full platform, the "audit receipt" shown on a
successful privileged withdrawal reflects `/flag.txt`'s current
content — rotated every round via `flagd`, same as every other
service.

## This completes the Network category ladder (for now)

`net-auth` (rung 1, a left-over default password) → `net-proto`
(rung 2, shell command injection) → `net-replay` (rung 3, a leaked,
replayable session token). See `main.md` for what's planned as rung 4
and beyond.
