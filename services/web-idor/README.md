# Challenge 3: Private Notes (IDOR)

A tiny "private notes" app. Each account has a private note, and you can
log in as one of two seeded non-admin accounts. The flag lives in the
`admin` account's note (account id `1`).

## Running it

```bash
cd services/web-idor
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build web-idor   # from the repo root
```

Open `http://localhost:5001` (standalone) or `:5000` inside the platform
network.

Seeded accounts: `alice` / `alicepass123`, `bob` / `bobsecurepw`.

## What IDOR means

**Insecure Direct Object Reference**: the app correctly checks that
*someone* is logged in, but never checks that the object they're asking
for (here, a note) actually belongs to *them*. This is one of the most
common real-world web vulnerabilities — way more common than SQL
injection in practice — because it's easy to write code that "checks
authentication" and forget to also "check authorization."

## Attacker role

1. Log in as `alice` or `bob` (not `admin` — you don't know that password,
   and you don't need it).
2. Look at the URL you land on after logging in: `/note/<some number>`.
   That number is your own account id.
3. Think about what happens if you just... change the number in the URL.
4. The admin account's note holds the flag. What id do you think it has?

```bash
curl -c cookies.txt -X POST http://localhost:5001/login \
  -d "username=alice" -d "password=alicepass123"
curl -b cookies.txt http://localhost:5001/note/<try something>
```

**Don't ask for the exact id to try.** This one barely needs a hint — if
you're stuck here, re-read "What IDOR means" above and think about what a
reasonable "first" account id would be in any database.

## Defender role

Open `app/app.py` and find the `/note/<int:note_id>` route. The bug is
that it trusts `note_id` from the URL without ever comparing it against
the logged-in user's own id (stored in the `user_id` cookie).

A correct fix checks that the requested note belongs to the logged-in
user **before** returning it — e.g., reject the request (or redirect) if
`note_id != int(request.cookies.get("user_id"))`, unless you deliberately
want to support an admin role that *can* see everyone's notes (in which
case the check becomes "is this the owner, or an actual admin role" — not
"is someone logged in").

After patching, confirm:
- `alice` and `bob` can each still view **their own** note normally
- neither can view the admin's note (id `1`) anymore

## Flag rotation

As part of the full platform, the admin note's content changes every
round via `flagd` (see `docs/ARCHITECTURE.md`). Submit whatever you
currently extract.
