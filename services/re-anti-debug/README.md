# Challenge: Vault Access Terminal (Binary/RE, ladder rung 4 of 10)

A "license key" style binary, like `re-crackme` -- except this one
notices if you try to debug it, and shuts the whole check down the
moment it does.

```bash
nc localhost 7003
```

## Running it

Standalone:

```bash
cd services/re-anti-debug
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build re-anti-debug   # from the repo root
```

## Attacker role

1. Connect and try a wrong key. Confirm it says "Access denied" — the
   program runs fine over the network, same as `re-crackme`.
2. Copy the binary locally (it's built from `src/vault.c`, right here
   in the repo — rebuild it yourself with the same `gcc` command the
   `Dockerfile` uses) and try running it under `gdb` to watch the
   comparison happen live, the way you might have for `re-crackme`.
   Notice something different happens almost immediately.
3. That's the anti-debug check. It calls `ptrace(PTRACE_TRACEME, ...)`
   on itself at startup — and that call fails if something is
   *already* tracing the process (a debugger can only ever be the one
   and only tracer). The program treats that failure as "someone's
   watching me" and bails out before the real key check even runs.
4. You have two completely valid ways past this:
   - **Don't run it under a tracer at all.** Pure static
     analysis — reading raw bytes out of the binary file without
     executing it (`objdump -s`, a hex editor, radare2's non-debug
     mode) — never triggers this check, because nothing is ever
     tracing anything.
   - **Defeat the check itself** — patch out the `ptrace` call in the
     binary, or intercept it with an `LD_PRELOAD` shim that makes
     `ptrace()` always report success, then debug normally.
5. Either way, the actual key is obfuscated the same way as
   `re-crackme`'s: a single-byte XOR over a short byte array. Find it,
   decode it, and use it against the **remote** service — the anti-debug
   check never affects a normal network connection, because nothing is
   tracing that process either.

**Don't ask for the XOR key or byte.** You already solved an identical
puzzle in `re-crackme`; the technique (dump the bytes, try XOR keys
until something printable and sensible comes out) is exactly the same
here.

## Defender role

Two layers worth understanding separately:

1. The anti-debug check (`src/vault.c`):
   ```c
   if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
       puts("Debugger detected. Exiting.");
       return 1;
   }
   ```
   This is a real, commonly-used technique, but it is **not** a
   security control on its own — it only raises the cost of *dynamic*
   analysis. It does nothing against static analysis, and a
   sufficiently motivated attacker can patch it out or intercept the
   syscall. Anti-debug checks belong in defense-in-depth, never as the
   only thing standing between an attacker and a secret.
2. The actual secret handling: just like `re-crackme`, embedding any
   secret in a binary at all (even obfuscated) means anyone with the
   binary can eventually recover it. The real fix for a genuine
   "license key" system is to never ship the secret in the client at
   all — verify it against a server you control instead.

After patching (if you choose to remove or rework the anti-debug
check as an exercise), confirm the service still accepts the correct
key and rejects an incorrect one exactly as before.

## Flag rotation

As part of the full platform, a correct key's response reflects
`/flag.txt`'s current content, rotated every round via `flagd` (see
`docs/ARCHITECTURE.md`). The vault key itself is fixed at compile time
and does not rotate.

## Where this sits in the Binary/RE ladder

`pwn-format` (rung 3) → **`re-anti-debug` (rung 4)** →
`re-packed` (rung 5). See `main.md` for the full ladder.
