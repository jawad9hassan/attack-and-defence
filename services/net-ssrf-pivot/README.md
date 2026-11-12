# Challenge 5: net-ssrf-pivot (Pivoting Through an Exposed Gateway)

A plain TCP "gateway" that's meant to let you reach exactly one
internal helper service without exposing that service's port directly.
You send it `CONNECT <host>:<port>`, and it relays raw bytes between
you and whatever you asked for. The only problem: it never checks
*which* host and port you asked for.

## Running it

Standalone:

```bash
cd services/net-ssrf-pivot
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-ssrf-pivot
```

The gateway listens on port `6002` (mapped to `8004` externally):

```bash
nc localhost 8004
```

## The setup (not hidden from you — read it, that's the point)

Look at `src/gateway.py`. Three things run inside this one container:

1. **`echo_service`**, bound to `127.0.0.1:6000` only — the gateway's
   *intended* target. Echoes back whatever text you send it.
   Completely harmless, and the only thing the gateway was ever
   actually tested against.
2. **`admin_service`**, bound to `127.0.0.1:6001` only — **not meant
   to be reachable from outside this container at all.** There's no
   port published for it anywhere. It serves the flag to anyone who
   sends `GET_FLAG`, with no authentication, because whoever wrote it
   assumed "nothing outside this box can reach localhost" made that
   safe.
3. **The gateway itself**, on the one externally published port. It
   reads `CONNECT <host>:<port>`, opens a new connection to *exactly*
   that host and port — no allowlist, no check that it's the echo
   service — and relays bytes in both directions until either side
   disconnects.

The gateway runs *inside the same container* as both of the services
behind it, so from the gateway's point of view, `admin_service` is
just as reachable as `echo_service` — both are on `127.0.0.1`, just
different ports.

## What you need to work out

Nothing about the protocol itself is hidden — you can see exactly what
`CONNECT` does by reading the source. The question is simply: **what
else, besides port 6000, can you ask this gateway to connect you to?**

### Suggested analysis steps

1. **Try the intended path first.** Connect to the gateway and send
   `CONNECT 127.0.0.1:6000`, then send some text. You should see it
   echoed back — this confirms the relay mechanism works and shows
   you the exact response format (`CONNECTED`, then whatever the
   upstream service prints).

2. **Think about what "internal-only" really means here.** The admin
   service binds to `127.0.0.1`, which keeps it unreachable from
   *outside the container* directly — but the gateway process is
   *inside* the container too. From its perspective, is there
   anything structurally different between port 6000 and port 6001?

3. **Try a different target.** The gateway doesn't validate the
   `host:port` you ask for at all. What happens if you ask it to
   `CONNECT` somewhere else on `127.0.0.1`?

## Tools you'll need

| Tool | Why |
|---|---|
| Python `socket` (or `nc`) | Talk to the gateway directly and watch what it relays |

**Don't ask which port the admin service is on.** It's a small,
sequential port number right next to the echo service's — work it out
by reading the source and trying nearby ports, the same way you'd
enumerate an internal network you'd just gained a foothold in. If
you're stuck for more than 15-20 minutes, come back with exactly what
you tried.

## Defender role

Once you have the flag, think about how to fix `src/gateway.py`
without breaking its legitimate job (relaying to the echo service):

- The real fix is an **allowlist**: before dialing anything, check
  that `(host, port)` exactly matches the one destination the gateway
  is actually supposed to reach, and reject everything else.
- A deeper fix: don't rely on "it's on localhost" as a security
  boundary at all for a service as sensitive as one that hands out a
  flag with zero authentication. Even with the gateway's allowlist
  fixed, `admin_service` itself has no credential check — anything
  that *can* reach `127.0.0.1:6001` inside this container (a future
  bug, a different misconfigured gateway, a compromised neighboring
  process) gets the flag for free. Real internal services should
  still authenticate their callers.

After patching the allowlist, redeploy and confirm that `CONNECT
127.0.0.1:6001` is now rejected while `CONNECT 127.0.0.1:6000` still
works exactly as before.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique stays exactly the same; only
the flag text rotates. Submit whatever you currently extract; stale
ones expire.

## Where this sits in the Network Protocols ladder

`net-rate-limit-bypass` (rung 4) → **`net-ssrf-pivot` (rung 5)** →
`net-dns-spoof-sim` (rung 6). See `main.md` for the full ladder.
