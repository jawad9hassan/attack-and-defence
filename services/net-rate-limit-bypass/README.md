# Challenge: SecureVault PIN Terminal (Network, ladder rung 4 of 10)

A tiny "PIN vault" over plain TCP. Enter the correct 4-digit PIN and
get the flag. You only get 3 wrong guesses... per connection. That
"per connection" is the entire bug.

## Running it

Standalone:

```bash
cd services/net-rate-limit-bypass
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build net-rate-limit-bypass   # from the repo root
```

```bash
nc localhost 8003
```

## Attacker role

1. Connect and try 3 wrong PINs. Confirm you get disconnected after
   the third wrong guess ("Too many attempts. Disconnecting.").
2. **Reconnect**, and try 3 more guesses. Did your attempt count carry
   over from the last connection, or did you get a fresh 3 tries?
3. If it's a fresh 3 every time: a 4-digit PIN only has 10,000
   possible values. At 3 guesses per connection, that's roughly 3,334
   reconnects to guarantee finding it.
4. Write a script that reconnects, tries the next 3 PINs, and repeats
   until one of them says `Correct!`. This will take a real amount of
   time to run (a genuine brute force, just not an instant one) — let
   it run in the background while you work on something else.

**Don't ask for the exact script.** You have the protocol (send a PIN
line, read the response, reconnect after 3 wrong guesses) and the
search space (0000–9999). Writing the ~15 lines that automate it is
the exercise.

## Defender role

Open `src/vault.py`. The bug:

```python
class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        ...
        for attempt in range(MAX_ATTEMPTS):   # <-- resets to 0 every
            ...                                #     time handle() runs,
                                                 #     i.e. every new
                                                 #     connection
```

The attempt counter lives entirely inside one call to `handle()` —
which runs fresh for every new TCP connection. Nothing tracks how many
wrong guesses have come from this same attacker (by IP, by some
persistent identity, anything) across *separate* connections.

The fix: rate-limit by something that survives a reconnect — most
simply, the source IP, kept in a dictionary (or a proper store like
Redis in a real deployment) outside the per-connection handler, with
counts that persist and ideally expire after a cooldown window.

After patching, confirm:
- 3 wrong guesses still disconnects within one connection (unchanged
  behavior for a normal user who mistypes)
- reconnecting immediately after does **not** grant 3 fresh guesses

## Flag rotation

As part of the full platform, the flag shown on a correct guess
reflects `/flag.txt`'s current content — rotated every round via
`flagd`, same as every other service. The PIN itself is generated once
per process start and does **not** rotate with the flag — only the
flag you receive on success changes.

## Where this sits in the Network ladder

`net-auth` (rung 1) → `net-proto` (rung 2) → `net-replay` (rung 3) →
**`net-rate-limit-bypass` (rung 4)**. See `main.md` for what's next.
