# Challenge: NetGuard Device Console (Network, ladder rung 1 of 3)

The easiest challenge in the Network category. A tiny "device admin
console" over plain TCP, protected by a username/password login. No
injection, no scripting, no forged tokens — this is the simplest, and
also one of the most real-world-common, network security findings
there is: **a default account that was never disabled.**

## Running it

Standalone:

```bash
cd services/net-auth
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build net-auth   # from the repo root
```

```bash
nc localhost 8000
```

## Attacker role

There's a real admin account on this device with a strong, randomly
generated password — you will never guess it, and you're not meant to.
But devices like this very often ship with a second account:
a maintenance/support login the vendor enables by default, that
whoever deployed the device forgot (or didn't know) to disable.

**Think about what the single most common admin username/password
combination in the world is** — the one that shows up at the very top
of every "worst passwords" / "default device credentials" list — and
try it.

```bash
nc localhost 8000
Username: ...
Password: ...
```

**Don't ask for the exact credentials.** If you've genuinely tried the
obvious one and it didn't work, come back and say exactly what you
tried.

## Defender role

Open `src/console.py`. The bug:

```python
DEFAULT_CREDS = {
    "admin": "admin",
}
...
authenticated = (
    (username == REAL_ADMIN_USER and password == REAL_ADMIN_PASS)
    or DEFAULT_CREDS.get(username) == password
)
```

The fix is exactly what it looks like: remove the `DEFAULT_CREDS`
check entirely, so only the real (random, unguessable) admin password
works. In the real world, this means: **every account a device ships
with by default must be disabled or forced to change its password
before it ever goes into production** — not "nice to have," since
default-credential scanning is one of the very first things any
automated attacker (and most malware, like the Mirai botnet) tries.

After patching, confirm:
- the real admin credentials (if your team's checker/grading setup
  exposes them) still work
- `admin`/`admin` — and any other default pair you can think of — no
  longer grants access

## Flag rotation

As part of the full platform, the flag shown on successful login
reflects `/flag.txt`'s current content — rotated every round via
`flagd`, same as every other service.

## What's next in this ladder

- `net-proto` (rung 2) — command injection, needs understanding shell
  metacharacters rather than guessing a password.
- `net-replay` (rung 3) — a static, replayable session token leaked in
  a debug banner.
