# Challenge 10: forensics-pcap-tls (Key Recovery from a Handshake)

A short capture of a proprietary "secure session" protocol: a
handshake, followed by application data that really is encrypted —
not plaintext hiding in a stream like `forensics-pcap-basic`, and not
a matter of finding the right stream like `forensics-pcap-ftp`. This
is the capstone of the Digital Forensics ladder: the capture gives you
everything you need to derive the session key yourself.

## Running it

Standalone:

```bash
cd services/forensics-pcap-tls
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-pcap-tls
```

Then open `http://localhost:9009/` and download `capture.pcap`
(open it in Wireshark, or parse it with any pcap-reading library).

## The protocol

Following the TCP stream in the capture shows four messages:

```
client -> server:  HELLO proto=sessionsec/1
server -> client:  SERVER_NONCE=<32 hex characters>
client -> server:  READY
server -> client:  DATA <ciphertext bytes>
```

`DATA` is the flag, XORed against a keystream derived from a SHA-256-
based construction. **Nothing about the key derivation is secret** —
the protocol is proprietary, but its specification (which you can
infer entirely from what's visible in the handshake) is not.

## What you need to work out

1. **Follow the TCP stream** to read all four messages in order.
2. **Work out what goes into the key.** The only two things this
   protocol ever has to work with are the nonce the server sent in
   plaintext, and the protocol label the client itself sent in its
   `HELLO` — both of which you already have, right there in the
   capture.
3. **Reproduce the key derivation and the keystream it feeds**, then
   XOR it against the ciphertext bytes to recover the flag.

## Tools you'll need

| Tool | Why |
|---|---|
| Wireshark ("Follow TCP Stream") or a pcap-reading library (e.g. Python's `dpkt`, `scapy`, or even just slicing the raw file) | Extract the four messages and the raw ciphertext bytes |
| Python's `hashlib` | Reproduce a SHA-256-based key/keystream derivation once you've worked out its inputs |

**Don't ask what the key derivation function is.** Everything it
consumes is visible in the handshake; work out the construction from
what you can observe (hint: a keystream long enough for an
arbitrary-length flag can't come from a single hash output — think
about how you'd stretch one). If you're stuck for more than 20
minutes, come back with the exact bytes of all four messages you
extracted.

## Defender role

This is a forensics/analysis exercise built around a genuine
cryptographic design flaw rather than a server-side bug in how this
page serves the capture. The relevant defensive takeaway:

- **A session key must depend on something secret.** Here, every
  input to the key derivation — the nonce, the protocol label — is
  transmitted in the clear. Anyone who can see the handshake can
  compute the exact same key; there is no actual secret anywhere in
  the exchange.
- **Real key exchange needs a contribution neither side alone
  reveals** — a Diffie-Hellman exchange, a pre-shared secret that
  never crosses the wire, or at minimum a value derived from
  something an eavesdropper on the handshake can't fully observe.
  "Hash some public values together" is not key exchange, however
  it's dressed up.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a freshly generated `capture.pcap` (with
a new random nonce and the current flag freshly encrypted under the
key that nonce derives) is produced on every download — the key
derivation and recovery technique stay exactly the same; only the
flag text and nonce rotate. Submit whatever you currently extract;
stale ones expire.

## Where this sits in the Digital Forensics ladder

`forensics-malware-triage` (rung 9) → **`forensics-pcap-tls`
(rung 10)**. This is the final rung — see `main.md` for the full
ladder.
