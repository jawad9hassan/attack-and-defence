# Challenge 5: Network Diagnostics (Command Injection)

A tiny service that "pings" a hostname you give it and returns the
output. It tries to be safe by filtering out one dangerous character —
which is exactly why it's still vulnerable.

## Running it

```bash
cd services/net-proto
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build net-proto   # from the repo root
```

```bash
nc localhost 9200
```

## The bug class: incomplete blacklisting

A very common (and very real) mistake: someone realizes that building a
shell command from user input is dangerous, thinks "I'll just block the
dangerous character," blocks ONE of them, and calls it done. The problem
is that a shell has many ways to chain or substitute commands, not just
one:

- `;` — run a second command (this one IS blocked here)
- `&&` / `||` — conditionally chain commands
- `|` — pipe output into another command
- `` ` `` or `$(...)` — command substitution
- a newline — also starts a new command, same as `;`

Blocking only `;` leaves every other option open.

## Attacker role

**Goal:** get the service to reveal the current flag, which lives in a
file on the server, without ever being given direct file access.

### Suggested analysis steps

1. Connect and try a normal input (an IP or hostname) to see the expected
   response format.
2. Try a semicolon — confirm it gets stripped (no second command runs).
3. Think about the other ways a shell lets you chain or combine commands
   that **aren't** a semicolon (see the list above).
4. The flag lives at `/flag.txt` on the server. What command would print
   its contents? How do you get the diagnostics service to run that
   command *in addition to* (or instead of) the ping?

```bash
nc localhost 9200
# then type your crafted input
```

**Don't ask for the exact payload.** Think through the metacharacter
list above — one of them gets you there in a single line of input. If
you're stuck for more than 15-20 minutes, come back and say which
metacharacters you've already tried.

## Defender role

Open `src/diag.py`. The real fix isn't "block more characters" (that's a
losing game — there's always one more way to inject). The correct fixes,
in order of preference:

1. **Never build a shell command string from user input at all.** Call
   `subprocess.run(["ping", "-c", "1", "-W", "2", host], shell=False, ...)`
   with the hostname as a separate argument, not glued into a shell
   string. Shell metacharacters in `host` then have no special meaning —
   they're just literal text passed to `ping`, which will simply fail to
   resolve a nonsense hostname instead of being interpreted by a shell.
2. If you must keep `shell=True` for some reason, **validate with an
   allowlist** (e.g. `host` must match `^[a-zA-Z0-9.-]+$`) instead of a
   blacklist.

After patching, confirm:
- a normal hostname still returns ping-style output (or a clean "unknown
  host" error — either is fine, as long as it's not a crash)
- none of the injection techniques above leak the flag anymore

## Flag rotation

As part of the full platform, `/flag.txt`'s content changes every round
via `flagd` (see `docs/ARCHITECTURE.md`). Submit whatever you currently
extract.
