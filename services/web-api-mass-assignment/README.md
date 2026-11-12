# Challenge: FileDrop API (Web, ladder rung 10 of 10)

A minimal JSON signup API: `POST /api/register`, `POST /api/login`,
`GET /api/profile`. No HTML form at all — this is an API-only
challenge, so everything is done with raw JSON requests (`curl` or
Python's `requests`).

## Running it

Standalone:

```bash
cd services/web-api-mass-assignment
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-api-mass-assignment   # from the repo root
```

```bash
curl -s http://localhost:5009/
```

## Attacker role

1. Register a normal account:
   ```bash
   curl -s -X POST http://localhost:5009/api/register \
     -H "Content-Type: application/json" \
     -d '{"username":"you","password":"yourpass"}'
   ```
2. Log in with the same credentials to get a token, then check
   `GET /api/profile` with `Authorization: Bearer <token>`. Note the
   `role` field it reports.
3. Nothing in the documented API (the message `GET /` returns) ever
   mentions a `role` field. That silence is the hint, not an
   assurance that it's safe — many real-world signup APIs accept more
   fields in the request body than their own docs or frontend ever
   send, because the handler was written to just store "whatever came
   in" instead of picking specific fields out one at a time.
4. Register a *second* account, but this time add one extra field to
   the JSON body alongside `username`/`password` — the same field
   name `/api/profile` showed you in step 2 — set to the value you'd
   want it to be. Log in as that account and check `/api/profile`
   again.
5. `GET /api/admin` with that account's token.

**Don't ask for the exact field name or value.** You already have it:
it's the key `/api/profile` returned in step 2, and the value you want
is the obvious opposite of whatever default you were given.

## Defender role

Open `app/app.py` and look at `/api/register`:

```python
user = {"role": "user", "password": password}
user.update(data)   # <-- the bug: merges the WHOLE client body in
```

`data` is the raw, fully attacker-controlled JSON body. `update`
overwrites `role` with anything the client included, even though
`role` was never meant to be a client-settable field at all. This is
**Mass Assignment**: binding an entire request payload onto an
internal object/record instead of explicitly allowlisting which fields
a given endpoint is allowed to set.

The fix is to build the new user record from an explicit allowlist of
fields the endpoint actually accepts, and nothing else:

```python
user = {
    "password": password,
    "role": "user",   # never taken from the client at all
}
USERS[username] = user
```

If a role genuinely needs to be settable by *some* caller (e.g. an
existing admin creating another admin), that has to be its own
separate, authenticated, authorized endpoint — never a bonus field
quietly accepted by the public signup endpoint.

After patching, confirm:
- a normal `{"username":...,"password":...}` registration still works
  and still defaults to role `"user"`
- a registration body that also includes `"role":"admin"` no longer
  grants that role

## Flag rotation

As part of the full platform, `/api/admin`'s response reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`).

## Where this sits in the Web ladder

`web-path-traversal` (rung 9) → **`web-api-mass-assignment` (rung 10,
final rung)**. See `main.md` for the Crypto ladder next.
