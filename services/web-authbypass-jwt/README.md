# Challenge: MiniCorp Portal (Web — Broken Auth / JWT, ladder rung 5 of 5)

A tiny portal logs you in as an ordinary "guest" user and gives you a
JWT (JSON Web Token) as your session. The `/admin` page checks that
token's `role` claim and only shows the flag if it says `"admin"`.
There is no admin login anywhere — your job is to make the server
*believe* you're an admin without ever having admin credentials.

This is the last and hardest rung of the Web & Application Security
ladder on this platform, and it's a different family of bug from the
SQLi ladder (`web-notes` → `web-sqli-union` → `web-sqli-blind`): this
one is about **broken authentication/authorization logic**, which the
original skills survey also called out as its own area (alongside API
testing).

## Running it

Standalone:

```bash
cd services/web-authbypass-jwt
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-authbypass-jwt   # from the repo root
```

Then open `http://localhost:5004`.

## Background: what a JWT actually is

A JWT is just three base64url-encoded chunks joined by dots:

```
header.payload.signature
```

- **header** — a tiny JSON object, e.g. `{"alg": "HS256", "typ": "JWT"}`.
  `alg` says which algorithm was used to sign this token.
- **payload** — the actual claims, e.g. `{"user": "guest", "role": "user"}`.
- **signature** — proves the header+payload weren't tampered with,
  *if* the server checks it correctly.

Anyone can **decode** a JWT (it's not encrypted, just base64) — paste
one into a tool like [jwt.io](https://jwt.io) or decode it yourself:

```python
import base64, json
def b64url_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
header, payload, sig = your_token.split(".")
print(json.loads(b64url_decode(header)))
print(json.loads(b64url_decode(payload)))
```

Decoding isn't the vulnerability — **forging** a token the server will
*accept* is.

## Attacker role

1. Log in at `/login` and look at the token you get back. Decode its
   header and payload (above). Notice the `role` claim.
2. Think about what the `alg` field in the header actually means: it's
   telling the server *how to verify this token* — but the server read
   that field from the token the attacker sent. What happens if the
   server trusts whatever algorithm the token claims, instead of only
   ever expecting one specific algorithm?
3. One special value for `alg` exists in the JWT spec precisely to mean
   "this token isn't signed — don't check anything": `"none"`.
4. Build your own token:
   - header: `{"alg": "none"}` — base64url-encode it
   - payload: `{"role": "admin"}` — base64url-encode it
   - signature: **leave it empty** — the full token is
     `<header>.<payload>.` (note the trailing dot, empty third part)
5. Send that as your `token` cookie (or `Authorization: Bearer <token>`
   header) to `/admin`.

**Don't ask for the exact script.** You now have the token structure,
the encoding (base64url, strip `=` padding), and the exact header value
that disables signature checking. Writing the ~10 lines to build and
send that token yourself is the exercise.

## Defender role

Open `app.py`'s `verify_token()`. The bug:

```python
alg = header.get("alg", "")
if alg == "none":
    return payload          # <-- no signature check at all!
elif alg == "HS256":
    ...  # verifies the signature correctly
```

The server is letting the **token itself** decide how it gets
verified. That's backwards. The fix: the server should hardcode the
one algorithm it expects (`HS256` here) and reject *any* token whose
header says something else — never branch on an attacker-controlled
field to decide whether to check a signature at all. Most real JWT
libraries (PyJWT, etc.) have had exactly this class of bug reported
against them historically, which is why modern versions require you to
explicitly pass the list of algorithms you accept.

After patching, confirm:
- a normal guest token still reaches `/admin` and gets denied (403)
- a forged `alg: none` / `role: admin` token now also gets rejected

## Flag rotation

As part of the full platform, the flag shown on `/admin` reflects
`/flag.txt`'s current content every request — rotated every round via
`flagd`, same as every other service.

## This completes the Web & Application Security ladder (for now)

`web-idor` → `web-notes` → `web-sqli-union` → `web-sqli-blind` →
`web-authbypass-jwt`. See `main.md` for what's planned next in this
category (API/IDOR variants, stored XSS, and more).
