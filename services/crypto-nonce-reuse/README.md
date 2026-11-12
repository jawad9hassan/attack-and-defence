# Challenge: SecureMsg Oracle (Crypto, ladder rung 8 of 10)

A stream-cipher encryption oracle (think "AES-GCM/ChaCha20-style
counter mode", built here without any external crypto library). On
connect, it hands you the flag — already encrypted. Then it offers to
encrypt anything else you send, for free, in the same session.

```bash
nc localhost 6007
```

## Running it

Standalone:

```bash
cd services/crypto-nonce-reuse
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-nonce-reuse   # from the repo root
```

## Attacker role

Every stream cipher (real AES-GCM, ChaCha20, or this toy one) works by
XOR-ing the plaintext with a "keystream" derived from a secret key and
a nonce (a number used once). The security guarantee is literally in
the name: if the same (key, nonce) pair is EVER reused for two
different messages, the keystream for both messages is identical, and
XOR-ing the two ciphertexts together cancels the keystream out
entirely — leaving you with just the XOR of the two plaintexts.

1. You already have the flag's ciphertext (from the banner). You also
   have an oracle that will encrypt anything you send, in the exact
   same session — ask yourself whether it's reusing anything between
   those two encryptions.
2. If you give the oracle a plaintext of all zero bytes (same length
   as the flag's ciphertext), what does XOR-ing a zero byte with a
   keystream byte give you back, exactly?
3. Once you have that, combine it with the flag's ciphertext the way
   the stream-cipher XOR relationship above describes.

**Don't ask for the exact script.** You have the flag ciphertext, a
free encryption oracle, and the one-line math fact above
(`0 XOR k == k`) — assembling those three things is the exercise, and
it's a handful of lines.

## Defender role

Open `src/oracle.py`:

```python
NONCE = secrets.token_bytes(16)   # generated ONCE at process start,
                                    # reused for every message after
```

The nonce is generated exactly once, at startup, and every single
`encrypt()` call for the rest of the process's life reuses it. That's
the entire bug — the underlying stream cipher construction itself is
fine; "never reuse a (key, nonce) pair" is the one rule every stream
cipher and every authenticated mode built on one (AES-GCM,
ChaCha20-Poly1305) absolutely cannot survive being broken.

The fix is to generate a **fresh random nonce for every single
message** (not every connection — every message), and send it
alongside the ciphertext so the legitimate recipient can decrypt (most
real protocols literally prepend the nonce to the ciphertext for this
reason):

```python
nonce = secrets.token_bytes(16)   # fresh, every call
ciphertext = encrypt(plaintext, nonce)
# ship (nonce, ciphertext) together
```

After patching, confirm:
- the service still successfully encrypts both the flag and arbitrary
  attacker-supplied plaintext
- two different plaintexts encrypted in the same session no longer
  share a keystream (XOR-ing their ciphertexts together no longer
  reveals the XOR of the plaintexts)

## Flag rotation

As part of the full platform, the flag ciphertext sent on connect
reflects `/flag.txt`'s current content, rotated every round via
`flagd` (see `docs/ARCHITECTURE.md`). The service's key is generated
once per process start and does not rotate with the flag; the
(deliberately buggy) reused nonce is likewise fixed for the life of
the process.

## Where this sits in the Crypto ladder

`crypto-jwt-secret` (rung 7) → **`crypto-nonce-reuse` (rung 8)** →
`crypto-rsa-small-e` (rung 9). See `main.md` for the full ladder.
