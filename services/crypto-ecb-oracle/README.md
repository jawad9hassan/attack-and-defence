# Challenge: ECB Encryption Oracle (Crypto, ladder rung 4 of 10)

A service that will encrypt anything you ask it to -- with one catch:
whatever you send gets a secret value appended to it *after* your own
input, before the whole thing is encrypted and handed back to you.

```bash
nc localhost 6003
```

Send a line of **hex-encoded bytes**. You get back a line of
hex-encoded ciphertext. Reuse the connection for as many requests as
you like.

## Running it

Standalone:

```bash
cd services/crypto-ecb-oracle
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-ecb-oracle   # from the repo root
```

## Attacker role

This is the classic "byte-at-a-time ECB decryption" exercise.

1. Send an empty line (hex of nothing). Note the ciphertext length —
   it's a multiple of 16 bytes. That's your first clue about how the
   secret is padded and chunked.
2. Send increasing amounts of filler (`"A"*1`, `"A"*2`, ...) and watch
   how the ciphertext's **length** changes. Separately, notice that
   when two requests share the same first N bytes of plaintext, the
   first few 16-byte **blocks** of ciphertext are byte-for-byte
   identical — that's ECB mode's defining property, and it is the
   entire vulnerability.
3. Because of that property, you can recover the secret one byte at a
   time: carefully choose how much filler you send so that exactly one
   unknown byte of the secret lands at the end of a block, then try
   all 256 possible values for that position (prefix + 256 one-byte
   guesses appended) and compare the resulting block of ciphertext
   against the "target" block you captured. A match tells you the
   byte, with zero decryption or key-cracking involved.
4. Repeat, one byte and one block at a time, sliding your known
   prefix forward as you go.

**Don't ask for the exact script.** You have the oracle, the two
observable facts above (block-aligned length, identical ciphertext for
identical plaintext blocks), and the general "256 guesses per byte"
technique. Writing the loop that automates it is the exercise — it
runs in well under a minute against this service.

## Defender role

Open `src/oracle.py` and look at `ecb_encrypt`:

```python
def ecb_encrypt(data: bytes) -> bytes:
    padded = pkcs7_pad(data)
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out += encrypt_block(padded[i:i + BLOCK_SIZE])   # <-- each
    return bytes(out)                                     #     block
                                                             #     independent
```

Every 16-byte block is transformed completely independently of every
other block — nothing from one block's output feeds into the next.
That's what ECB ("Electronic Codebook") mode means, and it's why
identical plaintext blocks always produce identical ciphertext blocks,
leaking structure even though each individual block's content is
hidden.

The fix is to never use ECB mode for anything beyond a single, fixed
16-byte value: use a mode that chains blocks together so that
identical plaintext blocks produce *different* ciphertext, such as
CBC with a fresh random IV per message (see `crypto-padding-oracle`,
the next rung, for what CBC's own failure mode looks like when
implemented carelessly) or a proper authenticated mode like GCM.

After patching, confirm:
- the service still successfully encrypts arbitrary input (the
  *feature* isn't broken, only the mode)
- two requests that share a long common prefix no longer produce
  identical leading ciphertext blocks

## Flag rotation

As part of the full platform, the secret suffix appended to every
request reflects `/flag.txt`'s current content, rotated every round
via `flagd` (see `docs/ARCHITECTURE.md`). The oracle's key is generated
once per process start and does not rotate with the flag.

## Where this sits in the Crypto ladder

`crypto-weak-rsa` (rung 3) → **`crypto-ecb-oracle` (rung 4)** →
`crypto-padding-oracle` (rung 5). See `main.md` for the full ladder.
