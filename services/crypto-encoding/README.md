# Challenge 9: Encoding Puzzle (Crypto rung 1 of 2)

**Ladder:** this is step 1, the easiest crypto challenge on the
platform. Step 2 is `services/crypto-xor`, where you actually break a
cryptographic weakness (key reuse). This one has no key, no secret, and
nothing to "crack" — it's about recognizing standard, reversible
encodings and undoing them in the right order. Do this one first if
crypto is new to your team.

## Running it

Standalone:

```bash
cd services/crypto-encoding
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-encoding   # from the repo root
```

```bash
nc localhost 9100
```

Just connect — the service immediately sends you a blob and closes the
connection. Nothing to type.

## Background: encoding vs. encryption

These are NOT the same thing, and mixing them up is a common beginner
mistake:

- **Encoding** (hex, Base64, URL-encoding, reversing a string, ROT13...)
  is just a different *representation* of data. No key, no secret —
  anyone who recognizes the format can reverse it instantly with a
  standard tool. It is **not** a security mechanism.
- **Encryption** (what `crypto-xor` covers) uses a secret key, and
  without that key, reversing it should be computationally infeasible
  (or, as `crypto-xor` demonstrates, sometimes isn't, if the crypto is
  used wrong).

This challenge stacks a few encodings on top of each other. There's
nothing to "break" — you just need to recognize each layer by its
shape and know which tool undoes it.

## What you need to work out

### Suggested analysis steps

1. Connect and look at the blob you get back. What does it look like?
   Does it contain only letters and digits? Any `=` padding characters?
   Where are they positioned — does that look like a normal Base64
   string, or does something look off (e.g. padding `=` not at the very
   end)?
2. If the `=` characters are in the wrong place for normal Base64 (they
   should only ever appear at the very end), what simple, one-line
   operation on the whole string would fix that?
3. Once you've undone that, try decoding what's left as Base64 (Python:
   `base64.b64decode(...)`, or the `base64 -d` command-line tool). What
   do you get? Does it look like readable text, or like another
   encoding format (all characters `0-9a-f`)?
4. If it's all `0-9a-f` characters, that's a strong signal it's **hex**.
   Decode it (Python: `bytes.fromhex(...)`, or `xxd -r -p`) and see what
   comes out.

**Don't ask for the exact order of operations or a ready script.** You
have everything you need: look carefully at the shape of the data at
each stage, and let that tell you what to try next. If you're stuck for
more than 15-20 minutes, tell me exactly what the blob looked like and
what you tried, and you'll get a sharper hint.

## Defender role

This one's a bit different from the others — "encoding instead of a
real secret" IS the vulnerability here, by design, since there's no
actual encryption to break. The teaching point for defenders: **never
treat encoding as if it were security**. If `src/puzzle.py` is modified
to use this scheme to "hide" something that's actually meant to stay
secret, that would be the bug to flag in a real code review, even
though there's no single line to "patch" in the traditional sense.

As an exercise, you could extend `encode_layers()` in `src/puzzle.py`
to add a 4th or 5th layer (e.g. ROT13, ASCII-value listing, your own
custom reversible scheme) and see if a teammate who didn't write it can
still peel it apart with the same general approach.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the encoding scheme and the order of operations stay
exactly the same each round; only the flag text being encoded changes,
so you'll need a short script (not just manual steps) to keep up across
rounds.
