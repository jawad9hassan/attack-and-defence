# Challenge 7: net-tls-downgrade (Forcing a Weak Protocol Fallback)

A toy, plain-text stand-in for a TLS-style handshake — not real TLS,
but it reproduces the exact mechanics of a real downgrade attack: the
server supports a strong mode and a weak mode, and *something* about
how it negotiates between them lets a client steer it toward the weak
one even though the strong one was available the whole time.

## Running it

Standalone:

```bash
cd services/net-tls-downgrade
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-tls-downgrade
```

The service listens on port `6004` (mapped to `8006` externally):

```bash
nc localhost 8006
```

## The code (not hidden from you — read it, that's the point)

Look at `src/handshake.py`:

```python
SUPPORTED_VERSIONS = ["SECURE-V2", "PLAIN-V1"]  # server's own preference order
```

`HELLO <comma-separated versions>` negotiates a version by walking
**the client's list, in the client's order**, and picking the first
one the server also supports. A real, correctly-implemented server
should always insist on its own strongest mutually supported option,
regardless of what order the client listed things in (that's exactly
what a real on-path downgrade attacker tries to defeat — rewriting
the ClientHello to only *offer* weak options). This one doesn't: it
just trusts whatever order the client sends.

Separately, `GET_FLAG` only checks `self.established` — whether *any*
version was successfully negotiated at all, not which one.

## What you need to work out

Two things, and they compound:

1. Can you get the server to agree to its own **weakest** supported
   version, even though it also supports a stronger one?
2. Once you have, does the command that hands out the flag actually
   care which version you're on?

### Suggested analysis steps

1. **Try the "proper" handshake first.** Send `HELLO
   SECURE-V2,PLAIN-V1`, offering the strong option first, and confirm
   with `STATUS` that `SECURE-V2` was negotiated.

2. **Now try offering only the weak option.** What happens if your
   `HELLO` doesn't even mention `SECURE-V2`? Does the server refuse,
   or does it just... go along with it?

3. **Check what `GET_FLAG` actually looks at.** Read the handler code
   for that command specifically — what condition does it check
   before handing over the flag? Is it the same condition you'd
   expect from the comment in `SUPPORTED_VERSIONS`' usage, or
   something weaker?

## Tools you'll need

| Tool | Why |
|---|---|
| Python `socket` (or `nc`) | Send `HELLO`/`STATUS`/`GET_FLAG` and read the server's responses |

**Don't ask whether `GET_FLAG` checks the version.** Read
`src/handshake.py` — it's a short file, and the answer is right there
in the `GET_FLAG` handler. If you're stuck for more than 15 minutes,
come back with exactly what you tried.

## Defender role

Once you have the flag, think about how to fix `src/handshake.py`
without breaking the legitimate `SECURE-V2` flow:

- **Fix the negotiation logic first**: the server should walk *its
  own* preference order (`SUPPORTED_VERSIONS`, as already written —
  strongest first) and pick the first one the client also supports,
  instead of walking the client's order. That alone stops a client
  from steering the server into a version it didn't have to accept.
- **Fix the access check too, independently**: `GET_FLAG` should
  check `self.version == "SECURE-V2"` specifically, not just
  `self.established`. Even with the negotiation logic fixed, a
  security check that only confirms "some session exists" rather than
  "the SPECIFIC strong session exists" is a standing risk — the next
  weak mode anyone adds to `SUPPORTED_VERSIONS` would silently also
  pass this same check.

After patching both, redeploy and confirm that offering only
`PLAIN-V1` either gets refused outright, or negotiates successfully
but `GET_FLAG` then correctly refuses — while the legitimate
`SECURE-V2` flow keeps working exactly as before.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique stays exactly the same; only
the flag text rotates. Submit whatever you currently extract; stale
ones expire.

## Where this sits in the Network Protocols ladder

`net-dns-spoof-sim` (rung 6) → **`net-tls-downgrade` (rung 7)** →
`net-protocol-fuzzing` (rung 8). See `main.md` for the full ladder.
