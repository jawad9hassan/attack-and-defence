#!/usr/bin/env python3
"""
crypto-weak-rsa: a tiny RSA "encrypt the flag for you" service, with a
real, historically-documented RSA key generation weakness: every
connection gets a FRESH keypair, but one of the two primes (`P_SHARED`)
is generated ONCE at startup and reused for every single connection.
Only the second prime changes each time.

Protocol (plain text over TCP):

    Connect, and the service immediately sends:
        N: <hex>
        E: <hex>
        C: <hex>
    then closes the connection. N and E are the public key for THIS
    connection, C is the flag encrypted under it (textbook RSA, no
    padding). There's nothing to send -- just connect and read, then
    reconnect as many times as you like.

This is ladder rung 3 of the Cryptography category -- the first
challenge where you have to actually factor/attack a real public-key
scheme, not just decode (rung 1, crypto-encoding) or break a symmetric
key-reuse bug (rung 2, crypto-xor).

Why this is broken: RSA security depends on N = P * Q being hard to
factor. If you collect TWO moduli, N1 = P*Q1 and N2 = P*Q2, that share
one prime factor, then gcd(N1, N2) = P instantly -- no factoring
algorithm needed at all, regardless of how large the primes are. This
exact class of bug (devices/services with weak entropy ending up
generating the SAME prime across multiple keys) has been found for
real in the wild (see: "Mining Your Ps and Qs", USENIX Security 2012 --
a large-scale study that found exactly this kind of shared-prime RSA
key in deployed devices).
"""
import os
import random
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
PRIME_BITS = int(os.environ.get("PRIME_BITS", "256"))


def read_current_flag() -> bytes:
    try:
        with open(FLAG_PATH, "rb") as f:
            return f.read().strip()
    except OSError:
        return b"FLAG{missing_flag_file}"


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


# --- THE BUG: this prime is generated ONCE and reused for every ---
# --- connection for the lifetime of the process. -------------------
P_SHARED = gen_prime(PRIME_BITS)


def gen_keypair():
    q = gen_prime(PRIME_BITS)
    while q == P_SHARED:
        q = gen_prime(PRIME_BITS)
    n = P_SHARED * q
    phi = (P_SHARED - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return n, e, d


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        n, e, d = gen_keypair()
        flag = read_current_flag()
        m = int.from_bytes(flag, "big")
        if m >= n:
            # Should never happen at 256-bit primes (512-bit modulus)
            # for a normal-length flag, but fail safe instead of
            # sending garbage if it ever does.
            self.wfile.write(b"ERROR: modulus too small for current flag\n")
            return
        c = pow(m, e, n)
        self.wfile.write(
            f"N: {n:x}\nE: {e:x}\nC: {c:x}\n".encode()
        )


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9300"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"weak-rsa oracle listening on 0.0.0.0:{port} (prime_bits={PRIME_BITS})")
        server.serve_forever()
