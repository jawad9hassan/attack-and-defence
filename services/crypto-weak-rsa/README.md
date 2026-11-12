# Challenge: Weak-RSA Oracle (Cryptography, ladder rung 3 of 3)

The hardest crypto challenge on the platform, and the first one where
you're actually attacking real public-key cryptography, not just
decoding (`crypto-encoding`) or breaking a symmetric key-reuse bug
(`crypto-xor`).

Every time you connect, the service generates a **fresh RSA keypair**
and sends you your very own flag, encrypted under it:

```
N: <hex>
E: <hex>
C: <hex>
```

Then it closes the connection. Nothing to send — just connect, read,
and reconnect as many times as you like.

## Running it

Standalone:

```bash
cd services/crypto-weak-rsa
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-weak-rsa   # from the repo root
```

```bash
nc localhost 6002
```

## Background: the basics of RSA you need here

- `N = P * Q`, the product of two large random prime numbers. This is
  the public modulus — security depends entirely on N being hard to
  factor back into P and Q.
- `E` is the public exponent (always the same small number, e.g.
  65537).
- The ciphertext is `C = M^E mod N`, where `M` is the message (here,
  the flag, read as one big integer).
- If you know `P` and `Q`, you can compute `phi = (P-1)*(Q-1)`, then
  the private exponent `D = E^-1 mod phi` (modular inverse — Python's
  `pow(E, -1, phi)` does this directly), and recover
  `M = C^D mod N`.

Normally, factoring a large, properly-random N is computationally
infeasible — that's the entire point of RSA. **You are not expected to
factor one modulus here.**

## What you need to work out

### Suggested analysis steps

1. Connect once, note `N`, `E`, `C`.
2. **Reconnect and connect again** — note the new `N`, `E`, `C`. Keep
   going a few times if you want, but two connections are enough.
3. Compare the `N` values across connections. Are they ever related in
   a way that would be suspicious for two genuinely independent,
   randomly-generated RSA keys?
4. Python has a one-line function for finding the greatest common
   divisor of two numbers. What happens if you run it on two different
   `N` values from this service?
5. If that gives you something other than 1 or one of the N's
   themselves, you've found a shared factor. From there: divide it out
   of either N to get the other prime, compute `phi`, compute `D`, and
   decrypt `C` with the formula above. Convert the resulting integer
   back to bytes (`int.to_bytes`) and decode as text.

**Don't ask for the exact script.** Everything above — the formulas,
which built-in function to reach for, and what two connections will
give you — is the full recipe. Writing the ~15-20 lines of Python that
turns this into working code is the exercise.

If you're stuck for more than 30 minutes: tell me what `gcd(N1, N2)`
actually gave you, and you'll get a sharper hint.

## Defender role

Open `src/oracle.py`. The bug:

```python
P_SHARED = gen_prime(PRIME_BITS)   # generated ONCE, at module load time

def gen_keypair():
    q = gen_prime(PRIME_BITS)       # a NEW prime every call...
    n = P_SHARED * q                # ...but always multiplied by the SAME P
```

Every key this service ever issues shares one of its two prime
factors. The fix: generate **both** primes fresh, inside
`gen_keypair()`, for every single call — never reuse any prime-
generation output across more than one key.

This is a real documented vulnerability class. A 2012 academic study
("Mining Your Ps and Qs", USENIX Security) scanned deployed devices on
the public internet and found real RSA/DSA keys sharing primes with
each other, caused by exactly this kind of weak or insufficiently-
re-seeded randomness at key-generation time — not a contrived textbook
example.

After patching, confirm:
- the service still returns a valid-looking `N`/`E`/`C` triple
- `gcd()` of two fresh `N` values now returns 1

## Flag rotation

Every connection re-reads the current flag from `/flag.txt` before
encrypting it, so whichever flag is live when you connect is the one
you'll recover — same as every other service, rotated every round via
`flagd`.

## This completes the Cryptography ladder (for now)

`crypto-encoding` (rung 1, no key at all) → `crypto-xor` (rung 2, break
a reused symmetric key) → `crypto-weak-rsa` (rung 3, break a real
public-key scheme via a key-generation flaw). See `main.md` for what's
planned as rung 4 and beyond.
