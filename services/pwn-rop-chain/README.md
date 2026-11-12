# Challenge 9: pwn-rop-chain (Full ROP Chain Construction)

The same stack buffer overflow bug family as every other `pwn-*`
challenge here — but this time `win()` takes **three arguments** and
actively rejects the call unless all three are exactly right. Reaching
it with a correct result means chaining **two separate gadgets**
together to set up `rdi`, `rsi` and `rdx`, not just overwriting one
return address with one address like `pwn-baby`.

## Running it

Standalone:

```bash
cd services/pwn-rop-chain
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-rop-chain
```

The service listens on port `9989`:

```bash
nc localhost 9989
```

## The code (not hidden from you — read it, that's the point)

Look at `src/vuln.c` and `src/gadgets.s`:

```c
void win(uint64_t a, uint64_t b, uint64_t c) {
    if (a != EXPECT_A || b != EXPECT_B || c != EXPECT_C) {
        printf("win() reached, but with the wrong arguments -- no flag.\n");
        return;
    }
    ... prints the flag ...
}
```

`vulnerable()` has the exact same unbounded `gets()` bug as `pwn-baby`.
`win()` exists and is reachable, but simply jumping to it (like
`pwn-baby`) prints a "wrong arguments" message instead of the flag —
`a`, `b` and `c` (the x86-64 calling convention's `rdi`, `rsi`, `rdx`)
all have to hold exact values the check expects.

`gadgets.s` provides two named gadgets:

```asm
pop_rdi_ret:        pop %rdi; ret
pop_rsi_rdx_ret:     pop %rsi; pop %rdx; ret
```

Like `pwn-ret2libc`, these are handed to you so the challenge stays
about **chaining gadgets correctly**, not about finding them. A real
target usually won't label convenient gadgets for you; you'd search
the disassembly yourself, or use a tool like `ROPgadget` or
`pwntools`' `ELF().search()`.

## What you need to work out

1. **The offset** to the saved return address — same technique as
   every other binary challenge: disassemble `vulnerable()`
   (`objdump -d src/vuln | grep -A15 "<vulnerable>:"`) and read the
   stack frame size off the `sub $0x.., %rsp` instruction.

2. **The expected values.** Read `vuln.c` — `EXPECT_A`, `EXPECT_B`,
   `EXPECT_C` are right there in the source. (In a real target you
   would not get this for free; you'd have to disassemble `win()`
   itself and read the comparison constants out of the instructions.)

3. **Find the three addresses you need to chain:**
   ```bash
   objdump -d src/vuln | grep -E "<pop_rdi_ret>:|<pop_rsi_rdx_ret>:|<win>:"
   ```

4. **Build the chain.** After your padding, lay out on the stack,
   in this exact order:
   ```
   pop_rdi_ret address
   EXPECT_A
   pop_rsi_rdx_ret address
   EXPECT_B
   EXPECT_C
   win() address
   ```
   Trace through it by hand once: the overflowed `ret` jumps to
   `pop_rdi_ret`, which pops `EXPECT_A` into `rdi` and then `ret`s —
   popping the *next* stack value, `pop_rsi_rdx_ret`'s address, and
   jumping there. That pops `EXPECT_B` into `rsi`, `EXPECT_C` into
   `rdx`, and `ret`s again — popping `win()`'s address last. By the
   time `win()` is actually entered, all three registers are already
   correctly set.

5. **One more thing to watch for**, same as `pwn-canary-bypass` and
   `pwn-ret2libc`: jumping straight into `win()` this way can crash
   inside its own calls to `fopen`/`printf` with what looks like a
   segfault, even though the chain above is logically correct. That's
   the stack-alignment issue again — a hijacked `ret` lands one 8-byte
   slot "off" from where a real `call` would, and some `libc`
   internals use SSE instructions that fault on the wrong alignment.
   Fix: insert the address of a spare, bare `ret` instruction
   (`objdump -d src/vuln | grep -E "^\s*[0-9a-f]+:\s*c3\s*ret"` finds
   several) right before `win()`'s address, to absorb one extra return
   and restore alignment.

## Tools you'll need

| Tool | Why |
|---|---|
| `objdump -d` | Find the offset, both gadgets' addresses, `win()`'s address, and a spare `ret` |
| Python `struct` | Pack each value as a little-endian 8-byte integer |
| Python `socket` | Send the full chain over the network |

**Don't ask for the exact offset or chain layout.** Work through it
with the steps above — tracing a short ROP chain by hand, one `pop`/
`ret` at a time, is the actual skill this challenge is teaching. If
you're stuck for more than 30-45 minutes, come back with exactly what
you tried and what happened.

## Defender role

Once you have the flag, think about how to fix `src/vuln.c`:

- The real bug, as always, is the unbounded `gets()` — replace it with
  a bounds-checked read (`fgets(buf, sizeof(buf), stdin)`) and the
  entire chain becomes irrelevant, because the overflow that let you
  control the return address and build any chain at all never happens.
- Requiring exact argument values on `win()` was never a real defense
  here — it's a teaching device that makes a one-address `pwn-baby`-
  style jump insufficient, forcing a genuine multi-gadget chain. Don't
  mistake "harder to call correctly" for "secure": the overflow is
  still the vulnerability.

After patching, redeploy and confirm the same chain that worked before
now fails safely — the oversized input should be rejected or truncated
long before it reaches the saved return address.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique, gadget addresses and
expected argument values stay exactly the same; only the flag text
rotates. Submit whatever you currently extract; stale ones expire.

## Where this sits in the Binary/RE ladder

`pwn-ret2libc` (rung 8) → **`pwn-rop-chain` (rung 9)** →
`re-mobile-apk` (rung 10). See `main.md` for the full ladder.
