# Challenge: Timing-Leaky Token Check (Crypto, ladder rung 10 of 10)

A tiny token-check service: guess an 8-character secret token
(lowercase letters and digits only), and it tells you `MATCH` or
`NO MATCH`. The content of the response gives nothing away — but how
*long it takes to respond* does.

```bash
nc localhost 6009
```

## Running it

Standalone:

```bash
cd services/crypto-timing
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-timing   # from the repo root
```

## Attacker role

This is a **timing side-channel** attack. The service compares your
guess to the real token one character at a time and stops as soon as
it hits a mismatch — so a guess that gets the first 3 characters right
before failing takes measurably longer to answer than one that's wrong
on the very first character.

1. Send a handful of guesses and **time** each response (note when
   you sent the request and when the reply arrived).
2. For position 0, try every possible first character (holding the
   rest of the guess fixed/arbitrary) and note which one produces the
   slowest response. That's a strong signal about the real first
   character.
3. Fix that character in place, and repeat for position 1, then 2, and
   so on — each correct character you lock in makes every *subsequent*
   correct guess at the next position take even longer, which is how
   you confirm you're on the right track and not a timing fluke.
4. Once you've recovered all 8 characters, send the full guess and
   confirm you get `MATCH` plus the flag.

**Don't ask for the exact threshold or script.** The delay this
particular service adds per matched character is deliberately large
and easy to see even with simple timing (see `app/app.py`'s module
docstring for why) — comparing response times across the ~36-character
alphabet at each position, and keeping the slowest, is the entire
technique.

## Defender role

Open `src/oracle.py` and look at `leaky_compare`:

```python
def leaky_compare(guess, secret):
    for i in range(len(secret)):
        if i >= len(guess) or guess[i] != secret[i]:
            return False          # <-- bails out IMMEDIATELY
        time.sleep(PER_CHAR_DELAY)
    return len(guess) == len(secret)
```

Returning (and therefore finishing) the instant a mismatch is found
means the TIME TAKEN leaks exactly how many characters matched before
that point — a side channel that has nothing to do with the response's
actual content.

The fix is to use a constant-time comparison that always inspects
every byte, regardless of where (or whether) a mismatch occurs:

```python
import hmac
hmac.compare_digest(guess.encode(), secret.encode())
```

(`hmac.compare_digest` is specifically designed and documented for
this — comparing secrets safely — never use `==` or a hand-written
loop for anything security-sensitive.)

After patching, confirm:
- a correct guess still returns `MATCH` and the flag
- guesses with a correct 1-character prefix, a correct 7-character
  prefix, and a completely wrong first character all now take
  (approximately) the same amount of time to get a `NO MATCH`

## Flag rotation

As part of the full platform, a successful `MATCH` reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The secret token itself is generated once per
process start and does not rotate with the flag.

## Where this sits in the Crypto ladder

`crypto-rsa-small-e` (rung 9) → **`crypto-timing` (rung 10, final
rung)**. See `main.md` for the Binary/RE ladder next.
