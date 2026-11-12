# Challenge: MiniAuth (Crypto, ladder rung 6 of 10)

A login page with a "support debug" endpoint left reachable in
production — `/debug/hash?username=<name>` — that leaks the stored
password hash for any account. Normally that alone wouldn't matter
much... if the hash had been computed correctly.

## Running it

Standalone:

```bash
cd services/crypto-weak-hash
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-weak-hash   # from the repo root
```

Open `http://localhost:6005`.

## Attacker role

1. Fetch `/debug/hash?username=admin`. You get back a 64-character hex
   string.
2. That length and character set is the signature of a single,
   unsalted SHA-256 hash of the plaintext password — nothing more.
   Hash a handful of extremely common real-world passwords yourself
   with SHA-256 and compare against what you got back.
3. Once one of your guesses matches, log in as `admin` with that
   password on the login form.

**Don't ask for the password.** It's an extremely common, real-world
top-100-style password — any small list of the most popular leaked
passwords (there are many publicly published ones, like
"rockyou.txt"-style lists) will contain it near the top. Checking a
few dozen guesses against the leaked hash takes milliseconds.

## Defender role

Two separate problems, both worth understanding:

1. `/debug/hash` should not exist in production at all — it's a
   leftover support/debug tool. Remove it, or at minimum put it behind
   real authentication and an internal-only network boundary.
2. Even with that leak fixed as defense-in-depth, look at `weak_hash`:

```python
def weak_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
```

A single round of a fast, general-purpose hash with **no salt** means
two accounts with the same password get the identical hash (rainbow
tables work), and a fast hash means billions of guesses per second are
feasible on cracking hardware even without any leak at all. The fix is
a password-specific KDF built to be slow and memory-hard, with a
random salt baked in per account — `bcrypt`, `scrypt`, or `argon2` (for
example, Python's own `hashlib.scrypt`, or the `bcrypt` package).
General-purpose hashes like SHA-256/SHA-3 are excellent at their actual
job (integrity, fingerprinting) and a bad fit for passwords precisely
*because* they're fast.

After patching, confirm:
- `alice`'s existing password still logs her in (if you re-hash
  existing accounts, make sure the migration preserves working logins)
- the admin account's new hash no longer matches a plain
  `hashlib.sha256(password)` of the same password

## Flag rotation

As part of the full platform, logging in as `admin` reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The admin account's password itself does not
rotate — only the flag you get after successfully logging in does.

## Where this sits in the Crypto ladder

`crypto-padding-oracle` (rung 5) → **`crypto-weak-hash` (rung 6)** →
`crypto-jwt-secret` (rung 7). See `main.md` for the full ladder.
