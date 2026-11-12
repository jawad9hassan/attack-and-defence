# Challenge: MiniCorp Portal v2 (Crypto, ladder rung 7 of 10)

Another JWT-based login, but this time the server does everything
right at the protocol level: it only ever accepts `HS256`, and it
verifies the signature properly with a constant-time comparison. If
you're coming from `web-authbypass-jwt`, the `"alg":"none"` trick
**will not work here** — don't waste time on it.

## Running it

Standalone:

```bash
cd services/crypto-jwt-secret
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-jwt-secret   # from the repo root
```

Open `http://localhost:6006`.

## Attacker role

1. Log in as a guest and grab your token (three base64url parts
   separated by `.`). Decode the header and payload — notice `role`
   is `"user"`, and the signature is a real HMAC-SHA256, correctly
   computed.
2. The signature was computed as `HMAC-SHA256(secret, header.payload)`.
   You know `header.payload` (you have the token) and you know the
   resulting signature (also in the token). The only unknown is
   `secret` itself.
3. If that secret is short and happens to be a common, guessable
   string, you can brute-force it completely offline: for each
   candidate secret in a wordlist, recompute `HMAC-SHA256(candidate,
   header.payload)` and compare against the token's real signature.
   A match means you've found the actual signing key.
4. Once you have the real secret, you can sign **anything you want**
   — including a payload with `"role": "admin"` — and the server will
   accept it as perfectly valid, because cryptographically, it is.

**Don't ask for the exact secret or wordlist.** It is a very short,
very common single English word — the kind of thing that shows up near
the top of any "most common passwords/secrets" list. Trying a few
dozen such guesses against the known signature takes milliseconds.

## Defender role

Open `app/app.py`:

```python
SECRET = os.environ.get("JWT_SECRET", "letmein")
```

The protocol-level implementation is correct (`alg` is pinned to
`HS256`, the signature check uses `hmac.compare_digest`). The entire
bug is the **value** of the secret: short, guessable, effectively a
password that was never meant to be brute-forceable but is.

The fix is to generate a genuinely random, sufficiently long secret —
`secrets.token_hex(32)` (256 bits) is the Python stdlib equivalent of
what any real deployment should use — and keep it only in server-side
configuration, never hardcoded or committed anywhere.

After patching, confirm:
- a normal guest login and the resulting token still work exactly as
  before (`/admin` still correctly reports "not admin" for a guest
  token)
- a brute-force attempt against a short/common-secret wordlist no
  longer finds a match (because the real secret isn't in any wordlist
  that's actually feasible to search)

## Flag rotation

As part of the full platform, `/admin`'s response reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The signing secret itself does not rotate —
only the flag you read once you've forged a valid admin token does.

## Where this sits in the Crypto ladder

`crypto-weak-hash` (rung 6) → **`crypto-jwt-secret` (rung 7)** →
`crypto-nonce-reuse` (rung 8). See `main.md` for the full ladder.
