# Challenge: Packed License Validator (Binary/RE, ladder rung 5 of 10)

Another license-key binary. Try `strings`/`objdump` on it the way you
did for `re-crackme` or `re-anti-debug`. You will not find anything
useful — no messages, no obfuscated key, nothing that looks like a
normal C program at all.

```bash
nc localhost 7004
```

## Running it

Standalone:

```bash
cd services/re-packed
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build re-packed   # from the repo root
```

## Attacker role

1. Connect over the network and try a wrong key. It still works
   completely normally — "Access denied", same as every other license
   challenge. Whatever the binary *is*, running it works fine.
2. Now look at the binary itself (you can rebuild it the same way the
   `Dockerfile` does, from `src/`). Run `strings` on `vault_packed` —
   the file you'd actually connect to. Compare that to running
   `strings` on a normal, un-packed program you've already seen (like
   `re-crackme`'s binary). Notice the difference: this one shows
   nothing human-readable at all, just noise.
3. That's a **packed** binary: the file on disk is not the real
   program — it's a small loader ("stub") wrapped around a compressed
   copy of the real program. The stub's whole job, every time it
   runs, is to decompress the real program into a temporary file and
   immediately run THAT instead. This is exactly what real-world
   packers like UPX do (used both legitimately, to shrink binaries,
   and by malware, to defeat static antivirus scanning — this is a
   real, common technique worth recognizing).
4. Static analysis of the packed file alone won't get you anywhere.
   But the stub still has to *produce* a real, runnable, unpacked copy
   of the program every single time it executes — somewhere on disk,
   even briefly. Think about where a program would put a temporary
   file it's about to run, and whether you could grab a copy of that
   file while the stub is running (even a single, very short-lived
   run is enough — you only need the file to exist on disk for a
   moment to copy it).
5. Once you have an unpacked copy, analyze and solve it exactly the
   same way you solved `re-crackme` (same single-byte-XOR-obfuscated
   key trick) — then use the recovered key against the **real,
   remote, packed** service; unpacking only ever needs to happen
   locally, once, against your own copy.

**Don't ask where exactly the temp file goes or what to name your
search.** "A program needs to write an executable file somewhere
before it can run it" is the whole hint — a well-known, standard
location on any Linux system, and a basic file-listing command while
the stub is mid-run, gets you there.

## Defender role

Open `src/stub.c`. This isn't really a "vulnerability" to patch in the
traditional sense — packing is a legitimate technique with real,
non-malicious uses. The lesson for a defender is recognition and
process: if you find a packed binary in an environment you're
investigating (a real incident, not a training exercise), that alone
is worth flagging, since malware very commonly packs itself to evade
signature-based detection. The response isn't "fix the packing," it's
"unpack it and analyze what's actually inside," exactly as you just
did here.

If you want to see what the real program looks like unpacked,
`src/inner.c` is the actual logic the stub wraps — same single-byte
XOR obfuscation on the key as `re-crackme`, nothing new there.

## Flag rotation

As part of the full platform, a correct key's response reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The license key itself is fixed at compile
time and does not rotate.

## Where this sits in the Binary/RE ladder

`re-anti-debug` (rung 4) → **`re-packed` (rung 5)** →
`pwn-canary-bypass` (rung 6). See `main.md` for the full ladder.
