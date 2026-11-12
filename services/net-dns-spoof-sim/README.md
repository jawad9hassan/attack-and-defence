# Challenge 6: net-dns-spoof-sim (Simulated DNS Cache Poisoning)

A toy, plain-text stand-in for a DNS resolver — not real DNS (no wire
format, no port 53), but it reproduces the exact idea that makes real
DNS cache poisoning possible: a resolver can only tell a genuine
answer from a forged one by checking a **transaction ID** on the
outstanding query. If that ID is predictable, you don't need to be
"on the path" and see the real query at all — you just need to be
able to send the resolver *something*, with the right ID, before the
real (and deliberately slower) upstream server answers.

## Running it

Standalone:

```bash
cd services/net-dns-spoof-sim
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-dns-spoof-sim
```

The service listens on port `6003` (mapped to `8005` externally):

```bash
nc localhost 8005
```

## The code (not hidden from you — read it, that's the point)

Look at `src/resolver.py`. The commands:

- `QUERY <domain>` — resolve a domain. Ordinary domains resolve
  **immediately** and tell you their transaction ID in the response.
  The one special domain, `flag.internal`, is deliberately **slow** —
  it goes "pending" and only resolves once a separate
  `UPSTREAM_RESPOND` call simulates the real upstream server's answer
  finally arriving.
- `SPOOF <domain> <txid> <ip>` — simulate a forged response arriving
  on the wire. Accepted only if it exactly matches a currently pending
  query's domain and transaction ID.
- `UPSTREAM_RESPOND <domain> <ip>` — the real, slow upstream's genuine
  answer. Rejected if the query has already resolved by the time it
  arrives (whether legitimately or via `SPOOF`).
- `LOOKUP <domain>` — shows what's currently cached.
- `GET_FLAG` — only works if `flag.internal`'s cache entry was set by
  a successful `SPOOF`, not by the real upstream.

The bug: transaction IDs come from **one global counter**, shared
across every domain and every query, incremented by exactly one each
time. There's no randomness anywhere.

## What you need to work out

You can't see `flag.internal`'s own transaction ID directly — its
`QUERY` response deliberately withholds it (it's "pending", not
resolved). But you don't need to see it. You need to **predict** it.

### Suggested analysis steps

1. **Send one throwaway query first**, for any domain you make up —
   something like `QUERY decoy.example.com`. Because it's an ordinary
   domain, it resolves instantly and the response tells you its own
   transaction ID.

2. **Think about what that tells you about the NEXT query anyone
   makes**, for any domain, given that the counter is global and
   increments by exactly one every time.

3. **Trigger the sensitive query** with `QUERY flag.internal`. Based
   on what you learned in step 1, what transaction ID should this
   query have been assigned?

4. **Race it.** Send `SPOOF flag.internal <your predicted txid>
   127.0.0.1` *before* anything calls `UPSTREAM_RESPOND` for that
   domain — there's no real time pressure here (nothing resolves
   `flag.internal` on its own), so you have as long as you need to get
   the command right.

5. **Collect the flag** with `GET_FLAG`.

## Tools you'll need

| Tool | Why |
|---|---|
| Python `socket` (or `nc`) | Send `QUERY`/`SPOOF`/`GET_FLAG` and read the resolver's responses |

**Don't ask what the starting counter value is.** Discover the pattern
yourself with one throwaway query, exactly like an attacker probing an
unfamiliar resolver would. If you're stuck for more than 15-20
minutes, come back with exactly what you tried.

## Defender role

Once you have the flag, think about how to fix `src/resolver.py`
without changing its normal behavior (ordinary domains should still
resolve, and should still be fast):

- The real fix is **randomizing transaction IDs** — draw each one from
  a wide, unpredictable range (e.g. `secrets.randbelow(65536)`) instead
  of a shared, sequential counter, so observing one query's ID tells
  you nothing about any other query's ID.
- A deeper, defense-in-depth fix real DNS resolvers also rely on:
  checking that a response additionally arrives on the *same source
  port* the query went out from (also randomized), not just the
  transaction ID — two independent values an off-path attacker has to
  guess simultaneously, not one.

After patching, redeploy and confirm that observing one query's
transaction ID no longer helps you predict another's, even though
ordinary resolution still works exactly as before.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique stays exactly the same; only
the flag text rotates. Submit whatever you currently extract; stale
ones expire.

## Where this sits in the Network Protocols ladder

`net-ssrf-pivot` (rung 5) → **`net-dns-spoof-sim` (rung 6)** →
`net-tls-downgrade` (rung 7). See `main.md` for the full ladder.
