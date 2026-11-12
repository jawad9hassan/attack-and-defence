# Challenge 4: XOR Encryption Oracle (key reuse)

A tiny network service that "encrypts" data by XORing it with a secret
key. It offers two operations: get the encrypted flag, or ask it to
encrypt data **of your own choosing** with the same key.

## Running it

```bash
cd services/crypto-xor
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-xor   # from the repo root
```

```bash
nc localhost 9000
```

## The crypto background

XOR "encryption" (`ciphertext = plaintext XOR key`) is only secure if the
key is **exactly as long as the message and never reused** — a one-time
pad. The moment the same key bytes get reused for a second message, XOR
becomes trivially breakable, because:

```
ciphertext_1 = plaintext_1 XOR key
ciphertext_2 = plaintext_2 XOR key
ciphertext_1 XOR ciphertext_2 = plaintext_1 XOR plaintext_2
```

The key cancels out entirely. If you already know (or control) one of
the two plaintexts, you immediately recover the other.

This service reuses the exact same key for every connection and every
message, and lets you submit your own plaintext to encrypt. That combination
(key reuse + a chosen-plaintext oracle) is the vulnerability.

## Attacker role

**Goal:** recover the flag without ever knowing the key directly from the
service — work it out from what the oracle gives you.

### Suggested analysis steps

1. Connect and try both commands to see the response format:
   ```bash
   nc localhost 9000
   GETFLAG
   ```
   You'll get back `CIPHERTEXT: <hex>`. Note its length in bytes (hex
   length ÷ 2).

2. Now think about the `ENC <hex bytes>` command. What happens if you
   encrypt a plaintext you already know? Specifically — what is
   `0x00 XOR key`?

3. Work out: if you ask the oracle to encrypt a string of all-zero bytes,
   **the same length as the flag's ciphertext**, what do you get back?

4. Once you have that, how do you combine it with the flag's ciphertext
   (from step 1) to recover the actual flag? (Hint: XOR is its own
   inverse — `(a XOR b) XOR b == a`.)

A short Python script using the `socket` module to automate steps 1-4 is
the practical way to do this (manual `nc` back-and-forth works too, but
you'll be XORing hex by hand, which gets tedious fast).

**Don't ask for the exact script.** The crypto reasoning above is the
whole challenge — once you see why "encrypt zeros" reveals the key, the
code to automate it is simple. If you're stuck on the Python/hex
mechanics specifically (not the crypto idea), come back and ask about
that part.

## Defender role

Open `src/oracle.py`. The real fix here isn't a small patch — it's a
design problem: **never reuse a key for XOR, and never let an untrusted
client control what gets encrypted with your secret key.** Two valid
directions:

- Use a proper authenticated cipher (e.g. AES-GCM) instead of raw XOR,
  with a fresh random nonce per encryption.
- At minimum, remove the `ENC` command entirely (or restrict it so it
  can never be used to bridge into the flag's keystream), and generate a
  fresh key for every connection rather than one shared key for the whole
  process lifetime.

After patching, confirm the service still responds to `GETFLAG`
correctly, but the chosen-plaintext technique above no longer recovers
anything useful.

## Flag rotation

As part of the full platform, the flag changes every round via `flagd`
(see `docs/ARCHITECTURE.md`); the XOR key itself does not rotate (it's
generated once at service startup) — only the flag you recover changes.
