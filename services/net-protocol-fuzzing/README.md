# Challenge 8: net-protocol-fuzzing (Info-Leak from Malformed Input)

A tiny, custom length-prefixed echo protocol. Send it some bytes and
tell it how many bytes you want back — it's supposed to just echo
your own bytes back to you. It doesn't check that the number you asked
for actually matches how much you sent.

## Running it

Standalone:

```bash
cd services/net-protocol-fuzzing
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build net-protocol-fuzzing
```

The service listens on port `6005` (mapped to `8007` externally):

```bash
nc localhost 8007
```

## The code (not hidden from you — read it, that's the point)

Look at `src/echo_proto.py`. The protocol is `ECHO <claimed_len>
<hex_payload>`. The handler:

```python
internal_buffer = build_internal_buffer()
combined = actual + internal_buffer[len(actual):]
response = combined[:claimed_len]
```

If `claimed_len` is exactly how many bytes you sent, `response` is
just your own bytes back — completely normal, boring echo behavior.
But `claimed_len` is **never checked against how many bytes you
actually sent** (only against an overall maximum, `MAX_CLAIMED_LEN`).
Ask for more than you sent, and the shortfall gets padded out of
`internal_buffer` — a buffer you were never given permission to read
any of, and that happens to have the flag sitting inside it.

This is a deliberately simplified version of the real **Heartbleed**
bug (CVE-2014-0160): a TLS heartbeat message carried a claimed payload
length that OpenSSL trusted without checking it against the actual
payload sent, causing it to echo back adjacent heap memory —
sometimes including private keys or session data.

## What you need to work out

1. **Confirm the normal behavior first.** Send `ECHO 4 41414141`
   (hex for `"AAAA"`) and confirm you get exactly `"AAAA"` back.

2. **Ask for more than you sent.** What happens if you send an empty
   payload (`ECHO 256`, no hex bytes at all) but claim you want
   `256` bytes back? Where do those 256 bytes come from, if you
   didn't send any of them?

3. **Look for the flag in what comes back.** The leaked buffer has
   random bytes before and after the flag — you're looking for a
   `FLAG{...}`-shaped chunk somewhere inside a few hundred bytes of
   otherwise meaningless hex.

## Tools you'll need

| Tool | Why |
|---|---|
| Python `socket` (or `nc`) | Send `ECHO` requests and read the raw hex response |
| A regex or simple string search | Pull the `FLAG{...}` pattern out of the leaked bytes |

**Don't ask how big the internal buffer is or where the flag sits
inside it.** Just ask for the maximum allowed length with an empty
(or short) payload and search what comes back. If you're stuck for
more than 15 minutes, come back with exactly what you tried.

## Defender role

Once you have the flag, think about how to fix `src/echo_proto.py`
without losing the ability to echo exactly what's sent:

- The real fix is simple: reject (or silently clamp) any
  `claimed_len` that doesn't match `len(actual)`. There is never a
  legitimate reason for this protocol to hand back more bytes than
  the client sent in — the "claimed length bigger than real payload"
  case should never happen in a correct implementation.
- More generally: any time a server trusts a client-supplied *length*
  field to decide how much of some buffer to return, without
  separately verifying that much data was actually provided, that gap
  is worth checking for an over-read, in this codebase or any other.

After patching, redeploy and confirm that asking for more bytes than
you send now gets rejected (or silently truncated to what you sent) —
while the exact-length echo still works precisely as before.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique stays exactly the same; only
the flag text (and the random padding around it) rotates. Submit
whatever you currently extract; stale ones expire.

## Where this sits in the Network Protocols ladder

`net-tls-downgrade` (rung 7) → **`net-protocol-fuzzing` (rung 8)** →
`net-arp-spoof-sim` (rung 9). See `main.md` for the full ladder.
