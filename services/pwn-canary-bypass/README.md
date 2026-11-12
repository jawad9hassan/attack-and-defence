# Challenge 6: pwn-canary-bypass (Leaking and Bypassing a Stack Canary)

A small network service written in C with the same kind of stack buffer
overflow as `pwn-baby` — but this time the binary is compiled **with a
stack canary** (GCC's default stack-smashing protector). A naive overflow
that reaches the saved return address now crashes the process instead of
jumping anywhere. You need to defeat the canary first.

## Running it

Standalone:

```bash
cd services/pwn-canary-bypass
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-canary-bypass
```

The service listens on port `9992`:

```bash
nc localhost 9992
```

## The code (not hidden from you — read it, that's the point)

Look at `src/server.c`. A few things matter, in order:

1. `vulnerable_once()` has the same `char buf[64]` + unchecked `memcpy()`
   overflow as `pwn-baby`'s `gets()` bug — except this binary is compiled
   with `-fstack-protector`, so GCC inserts a canary check: a secret
   value is stored on the stack right after the buffer, and checked again
   right before the function returns. If it changed, the program aborts
   ("stack smashing detected") instead of returning normally — so a
   straightforward return-address overwrite just kills the connection.

2. **The server is its own TCP listener.** It does **not** use `socat` the
   way the other `pwn-*` challenges do. It calls `socket()`/`bind()`/
   `listen()`/`accept()` itself, and `fork()`s a child to handle each
   connection — but it never calls `exec()` again afterward. That one
   design choice is what makes this challenge solvable at all: the
   canary value (`__stack_chk_guard`) is picked **once**, when the
   process starts, from `/dev/urandom`. Every child `fork()`ed from that
   one long-running parent inherits an **identical copy** of that value,
   for as long as the parent keeps running. If this server instead
   restarted a fresh process (or a fresh `exec()`) per connection, like a
   normal `socat ...,fork EXEC:binary` setup, the canary would be
   re-randomized every single connection and brute-forcing it would be
   hopeless.

3. Within one connection you can send as many guesses as you like — the
   server reads one line at a time and calls `vulnerable_once()` again
   for each one. A wrong guess kills that connection (the process
   `abort()`s), but a fresh connection gets a fresh child with the
   **same** canary, so you lose nothing but one TCP handshake.

## What you need to work out

The canary sits between your buffer and the saved return address. You
cannot read it directly, but you don't have to guess all 8 bytes at
once: you can guess **one byte at a time**, from the first canary byte
to the last, because a wrong byte crashes the connection immediately
(right after the current call, before the server even replies) while a
right byte lets the function return normally (you get `"OK"` back) —
even if the following canary bytes are still wrong. That turns an
8-byte brute force (256^8 — impossible) into eight 1-byte brute forces
(256*8 = 2048 attempts — instant).

One shortcut: on this architecture (x86-64 Linux), the canary's lowest
byte is always `0x00` (so that a `%s`-style string read, like a classic
`printf`/`gets`-based leak, can never accidentally read past it as if it
were ordinary string data). You don't have to brute-force that byte.

### Suggested analysis steps

1. **Find the offset to the canary.** Same technique as `pwn-baby`:
   disassemble `vulnerable_once` (`objdump -d src/server | grep -A25
   "<vulnerable_once>:"`) and look at where `buf` is relative to `%rbp`,
   and where the canary is stored (`mov %fs:0x28,%rax` / `mov
   %rax,-0x8(%rbp)`). The byte offset from the start of `buf` to the
   start of the canary is the padding length you need before your
   guessed byte.

2. **Brute-force the canary one byte at a time.** For each position,
   from 1 to 7 (position 0 is the known `0x00` byte): try all 256
   values for that byte (keeping every earlier byte at its already-
   confirmed value and every later byte at `0x00`/anything, since it's
   not reached yet). Reconnect whenever a guess crashes the connection.
   Stop and move to the next position once you get `"OK"` back.

3. **Find `win()`'s address** the same way as in `pwn-baby`
   (`objdump -d src/server | grep -A2 "<win>:"` — fixed thanks to
   `-no-pie`).

4. **Watch out for one more thing before you jump to `win()`.** Simply
   overwriting the return address with `win()`'s address, right after
   the (now-correct) canary and 8 filler bytes for the saved RBP slot,
   will very likely still crash — not from the canary this time, but
   from a **stack alignment** fault deep inside `win()`'s own call to a
   glibc function. x86-64's calling convention requires the stack to be
   16-byte aligned at every function's entry point; a direct
   return-oriented jump into a function (rather than a normal `call`)
   shifts that alignment by 8 bytes, and glibc's optimized string/IO
   routines can use SSE instructions that fault on misaligned stack
   access. The classic, simple fix: don't jump straight to `win()` —
   jump to the address of a single stray `ret` instruction first (any
   bare `c3` byte already in the binary works; the end of
   `vulnerable_once` itself has one), and put `win()`'s address right
   after it. That extra `ret` "absorbs" one return and re-aligns the
   stack by 8 bytes before actually landing in `win()`.

5. **Put it all together**: `padding (72 bytes, or whatever you found)
   + canary (8 bytes, correctly guessed) + 8 filler bytes (saved RBP,
   doesn't matter what) + ret-gadget address (8 bytes) + win() address
   (8 bytes)`, sent as one hex-encoded line after the canary is fully
   known.

## Tools you'll need

| Tool | Why |
|---|---|
| `objdump -d` | Read the disassembly, find the canary offset, `win()`'s address, and a spare `ret` gadget |
| Python `socket` | Brute-force the canary byte-by-byte, then send the final payload |
| Python `struct` | Pack addresses as little-endian 8-byte values |

**Don't ask for the exact offset or the fix for the alignment crash.**
Both are discoverable with the steps above. If you're stuck for more
than 30-45 minutes, come back with exactly what you tried and what
happened, and you'll get a sharper hint.

## Defender role

Once you have the flag, think about how `src/server.c` could be fixed
without losing the stack canary (that's a defense, not the bug):

- The real problem is still the unchecked `memcpy()` with
  attacker-controlled length writing into a fixed-size buffer — replace
  it with a bounds-checked copy (clamp `len` to `sizeof(buf)`, not to
  some larger `PAYLOAD_LEN`).
- Separately, think about whether this server's `fork()`-without-`exec()`
  architecture is itself a secondary issue: it's what makes a canary
  brute force practical at all, by keeping the secret alive and
  identical across every connection for the server's whole lifetime. A
  production service that restarts/re-execs per connection (or re-reads
  `/dev/urandom` for a fresh canary at some interval) narrows the window
  in which this kind of brute force is even possible.

After patching the bounds check, redeploy and confirm the same payload
that worked before now fails safely (the overflow should be rejected or
truncated, never reach the return address region at all).

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique, offsets and gadget addresses
stay exactly the same; only the flag text rotates. Submit whatever you
currently extract; stale ones expire.

## Where this sits in the Binary/RE ladder

`re-packed` (rung 5) → **`pwn-canary-bypass` (rung 6)** →
`pwn-heap` (rung 7). See `main.md` for the full ladder.
