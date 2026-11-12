#!/usr/bin/env python3
"""
crypto-rsa-small-e: textbook RSA with a small public exponent (e = 3)
and NO padding -- a real, historically significant RSA implementation
mistake (this exact attack is why PKCS#1 padding exists at all).

Protocol (plain text over TCP):

    Connect, and the service immediately sends:
        N: <hex>
        E: <hex>
        C: <hex>
    then closes the connection. N and E are the public key, C is the
    current flag encrypted under it with textbook RSA (c = m^e mod N,
    no padding scheme applied to m at all).

Why this is broken: with e = 3 and no padding, if the message m is
small enough that m^3 is LESS than N (which it is here -- N is a
1024-bit modulus and the flag, as an integer, is only a few hundred
bits), then c = m^3 mod N is not actually a *modular* operation at
all -- m^3 never exceeds N, so the mod has no effect, and
c == m^3 exactly, as plain integers. That means m is simply the
integer cube root of c -- no factoring, no private key, no randomness
to break. This is the textbook "low public exponent attack" and is
exactly why every real RSA encryption scheme pads the message first
(OAEP) -- padding makes the effective message always close to the
full size of N, so m^3 always wraps around modulo N and the shortcut
disappears.
"""
import os
import random
import socketserver

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
PRIME_BITS = int(os.environ.get("PRIME_BITS", "512"))
E = 3


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
        # e=3 requires gcd(e, p-1) == 1, i.e. p != 1 (mod 3)
        if candidate % 3 == 1 and is_probable_prime(candidate):
            return candidate


def gen_keypair():
    p = gen_prime(PRIME_BITS)
    q = gen_prime(PRIME_BITS)
    while q == p:
        q = gen_prime(PRIME_BITS)
    n = p * q
    return n


# Generated once per process start -- the bug here is e/padding choice,
# not key reuse across connections, so a fixed key keeps the service
# fast while still demonstrating the actual vulnerability.
N = gen_keypair()


def int_cuberoot_floor(c: int) -> int:
    """Integer floor cube root, pure Python (no gmpy2 dependency)."""
    if c < 0:
        raise ValueError
    lo, hi = 0, 1
    while hi ** 3 <= c:
        hi *= 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= c:
            lo = mid
        else:
            hi = mid - 1
    return lo


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        flag = read_current_flag()
        m = int.from_bytes(flag, "big")
        if m >= N or m ** E >= N:
            self.wfile.write(b"ERROR: modulus too small for current flag\n")
            return
        c = pow(m, E, N)
        self.wfile.write(f"N: {N:x}\nE: {E:x}\nC: {c:x}\n".encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("ORACLE_PORT", "9990"))
    with Server(("0.0.0.0", port), Handler) as server:
        print(f"rsa-small-e oracle listening on 0.0.0.0:{port} (N bits ~{PRIME_BITS*2})")
        server.serve_forever()
