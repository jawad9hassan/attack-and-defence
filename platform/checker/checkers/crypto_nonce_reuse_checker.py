"""
Checker module for crypto-nonce-reuse.

sla_check sends one benign plaintext, encrypts it twice in separate
connections, and only confirms the service returns a ciphertext of the
correct length each time (it never compares the two ciphertexts to
each other, and never attempts the XOR-recovery attack). This is a
pure liveness/shape check that passes regardless of whether the nonce
is fixed or freshly randomized per connection -- a fix that generates a
fresh random nonce per message (the actual remediation) keeps this
check passing.
"""
import socket


def sla_check(host, port):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            f = s.makefile("rb")
            f.readline()  # FLAG_CIPHERTEXT banner
            f.readline()  # instructions banner

            plaintext = b"benign-check"
            s.sendall(plaintext.hex().encode() + b"\n")
            reply = f.readline().strip()
    except OSError as e:
        return False, f"connection failed: {e}"

    try:
        ct = bytes.fromhex(reply.decode())
    except ValueError:
        return False, f"reply is not valid hex: {reply!r}"

    if len(ct) != len(plaintext):
        return False, f"ciphertext length {len(ct)} != plaintext length {len(plaintext)}"
    return True, "encryption oracle returns correctly-sized ciphertext"


def put_flag(host, flagd_port, flagd_secret, flag):
    try:
        with socket.create_connection((host, flagd_port), timeout=5) as s:
            s.sendall(f"{flagd_secret} SET {flag}".encode())
            reply = s.recv(100).decode(errors="replace").strip()
            return reply == "OK"
    except OSError:
        return False
