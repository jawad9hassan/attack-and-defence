# Challenge: CBC Padding Oracle (Crypto, ladder rung 5 of 10)

A service hands you an encrypted "cookie" on connect — the flag,
CBC-encrypted under a key you never see. It will also, on request,
tell you one single bit about anything you send it: whether decrypting
it under that same key results in valid PKCS#7 padding, or not. That
one bit is enough to decrypt the whole cookie.

```bash
nc localhost 6004
```

## Running it

Standalone:

```bash
cd services/crypto-padding-oracle
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-padding-oracle   # from the repo root
```

## Attacker role

This is the classic **CBC padding oracle attack**. If you haven't seen
it before, look up "padding oracle attack CBC" by name first — this is
one of the most well-documented crypto attacks that exists, and
working through a reference explanation alongside this live target is
the intended way to learn it, not reinventing it from first principles.

1. Note the cookie's structure: `IV || ciphertext block 1 || ciphertext
   block 2 || ...`. Every block is 16 bytes.
2. Recall how CBC decryption works: `plaintext_i = Decrypt(cipher_i) XOR
   cipher_{i-1}` (with `cipher_0` being the IV). You never need to know
   the key or the block cipher's internals — you only need to control
   `cipher_{i-1}` (the block right before the one you're attacking) and
   observe whether the final padding byte(s) come out valid.
3. By flipping bits in that preceding block and resending, you can make
   `Decrypt(cipher_i)[-1]` equal any value you choose, one byte at a
   time, learning it from whichever guess makes the oracle say GOOD
   PADDING. Once you have that intermediate byte, XOR it back with the
   ORIGINAL preceding block to recover the real plaintext byte.
4. Work backward through each block, byte by byte (last byte first),
   using already-recovered intermediate bytes to force the padding
   value up by one each time (`\x01`, then `\x02\x02`, then
   `\x03\x03\x03`, ...) so you can keep solving one new byte per
   attempt.
5. The IV block itself decrypts the first ciphertext block the same
   way — treat it exactly like any other "preceding block."

**Don't ask for the exact script.** The algorithm above, plus a
reference writeup of "CBC padding oracle attack" (there are many
excellent ones online, with diagrams), is everything you need — this
one runs against localhost and finishes in well under a minute.

## Defender role

Open `src/oracle.py` and look at `cbc_decrypt_check_padding`: it
decrypts attacker-supplied ciphertext and reports GOOD/BAD padding as
two visibly different outcomes. That distinguishable signal, combined
with letting the attacker submit ANY ciphertext they want (no integrity
check at all), is the entire vulnerability.

The real fix is **authenticated encryption**: compute a MAC (e.g.
HMAC-SHA256) over the IV and ciphertext at encryption time, and on
decryption, verify the MAC **first**, in constant time
(`hmac.compare_digest`), before ever touching the padding. If the MAC
doesn't match, respond with the exact same generic error you'd give
for invalid padding — never let an attacker distinguish "the MAC
failed" from "the padding failed," and never decrypt (or even attempt
to check padding on) anything whose MAC didn't check out first. This
is the "Encrypt-then-MAC" construction, and it's why real protocols use
authenticated modes like AES-GCM instead of raw CBC at all.

After patching, confirm:
- the service's own freshly-issued cookie still round-trips as valid
  (decrypts, MAC checks out, padding is fine)
- any bit-flipped version of that same cookie is now rejected with the
  exact same response regardless of whether the padding itself would
  have been valid or not

## Flag rotation

As part of the full platform, each freshly issued cookie encrypts
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The service's secret substitution table is
generated once per process start and does not rotate with the flag.

## Where this sits in the Crypto ladder

`crypto-ecb-oracle` (rung 4) → **`crypto-padding-oracle` (rung 5)** →
`crypto-weak-hash` (rung 6). See `main.md` for the full ladder.
