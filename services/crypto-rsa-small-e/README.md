# Challenge: Textbook RSA, e=3 (Crypto, ladder rung 9 of 10)

Connect and the service hands you a full RSA public key (`N`, `E`) and
the flag encrypted under it (`C`) — textbook RSA, no padding scheme
applied to the message at all. Look closely at `E`.

```bash
nc localhost 6008
```

## Running it

Standalone:

```bash
cd services/crypto-rsa-small-e
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build crypto-rsa-small-e   # from the repo root
```

## Attacker role

RSA encryption is `C = M^E mod N`. This challenge uses `E = 3` — a
tiny, historically common "fast" public exponent — and applies **no
padding** to `M` before encrypting. Padding (OAEP in any real system)
exists specifically to make `M` close to the full bit-length of `N`,
so `M^E` always wraps around modulo `N` at least once. Without it:

1. Work out roughly how many bits `N` has, and roughly how many bits
   a typical flag (as a raw integer, `int.from_bytes(flag, "big")`)
   has. Compare `3 ×` that flag bit-length against `N`'s bit-length.
2. If `M^3` is smaller than `N`, the modulo operation in
   `C = M^3 mod N` never actually does anything — `C` **equals**
   `M^3` exactly, as ordinary integers, with no wraparound at all.
3. If that's true, what single, purely arithmetic operation on `C`
   (needing no factoring, no private key, nothing secret at all)
   would give you `M` back directly?
4. Python has no built-in integer cube root, but you don't need
   floating point (which loses precision at this size) — a binary
   search for the largest integer whose cube is `≤ C` is a handful of
   lines, and you can verify your answer by cubing it back and
   checking it equals `C` exactly.

**Don't ask for the exact cube-root code.** The math fact above (`C ==
M^3` exactly, no modular wraparound) and "write an integer cube root
via binary search" is the complete path — this is intentionally a very
short, very classic attack once you see why `E=3` without padding is
unsafe.

## Defender role

Open `src/oracle.py`. The combination that breaks this:

```python
E = 3
...
c = pow(m, E, N)   # no padding applied to m at all beforehand
```

Raising `E` alone (say, to the standard `65537`) is **not** a complete
fix by itself for arbitrarily short messages — it only raises the
message-length threshold at which this exact attack stops working.
The real fix, used by every real-world RSA implementation, is a proper
padding scheme (OAEP) applied to the message *before* the modular
exponentiation, which randomizes and expands the encoded message to
always be comparable in size to `N` — guaranteeing the modular
reduction actually happens, regardless of how short the original
message was.

After patching (switching to properly padded encryption), confirm:
- the service still successfully encrypts the flag and returns a
  well-formed `N`/`E`/`C` triple
- `C` is no longer a perfect cube over the integers (i.e. the modular
  reduction is doing real work again)

## Flag rotation

As part of the full platform, `C` reflects `/flag.txt`'s current
content, rotated every round via `flagd` (see `docs/ARCHITECTURE.md`).
The RSA keypair itself is generated once per process start and does
not rotate with the flag.

## Where this sits in the Crypto ladder

`crypto-nonce-reuse` (rung 8) → **`crypto-rsa-small-e` (rung 9)** →
`crypto-timing` (rung 10). See `main.md` for the full ladder.
