# Challenge 8: pwn-ret2libc (Return-to-libc with ASLR Enabled)

A classic stack buffer overflow — same bug family as `pwn-baby` — but
this time there is **no `win()` function** anywhere in the binary. The
only "gift" code worth jumping to lives in `libc`, and `libc`'s load
address is randomized by ASLR **every time the process starts**. A
hardcoded address that works once will not work again on the next
connection.

## Running it

Standalone:

```bash
cd services/pwn-ret2libc
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-ret2libc
```

The service listens on port `9990`:

```bash
nc localhost 9990
```

## The code (not hidden from you — read it, that's the point)

Look at `src/vuln.c` and `src/gadgets.s`:

1. `vulnerable()` reads into `char buf[64]` with `gets()` — the exact
   same unbounded-read bug as `pwn-baby`.
2. The **executable itself** is built with `-no-pie`, so its own code
   — `vulnerable()`, the PLT stub for `puts`, its GOT entry, and a
   deliberately provided `pop_rdi_ret` gadget in `gadgets.s` — all sit
   at fixed, predictable addresses, exactly like every other binary
   challenge here. You don't need a gadget-finding tool for this one;
   `pop_rdi_ret` (`pop rdi; ret`) is handed to you so the challenge
   stays about the ret2libc *technique*, not about gadget hunting. A
   real target usually won't be this generous — you'd locate an
   equivalent sequence yourself with something like `ROPgadget` or
   `pwntools`' `ELF().search()`.
3. `libc` itself is **not** specially pinned or de-randomized. Every
   time the service restarts (which `socat ...,fork` does per
   connection), `libc` loads at a fresh random base address. This is
   the one piece of real ASLR in this challenge, and it's why
   `pwn-baby`'s approach (hardcode an address, send it once) cannot
   work here: there is no fixed address to hardcode for anything
   inside `libc`.

## What you need to work out

Since you can't know `libc`'s base address in advance, you need to
**leak** one real, this-connection address of a `libc` function first,
compute the base from it, and only then compute the addresses of
anything else inside `libc` (like `system()` and the string
`"/bin/sh"`) that you actually want to use. All of this has to happen
**within one TCP connection**, because the base address is picked once
per process and your connection *is* that one process (courtesy of
`socat`'s `fork` option) — reconnecting gets you a brand-new, freshly
randomized base.

### Suggested analysis steps

1. **Find the offset to the return address** the same way as
   `pwn-baby` — disassemble `vulnerable()` and look at the stack frame
   size and the saved-RBP/return-address layout.

2. **Stage 1 — leak a libc address.** Build a ROP chain that calls
   `puts()` on `puts`'s own **GOT entry** (not its PLT stub — the GOT
   entry holds the actual resolved runtime address once it's been
   called). That means: pop the GOT address into `rdi` (use the
   provided `pop_rdi_ret` gadget), then jump to `puts`'s PLT stub. The
   bytes `puts()` prints back to you ARE `puts`'s real address in this
   process's `libc`, written out byte-by-byte (not as a human-readable
   number). After this call returns, chain back into `vulnerable()`
   again so you get a second shot at the overflow *in the same
   process*.

   ```bash
   objdump -d src/vuln | grep -E "<pop_rdi_ret>:|puts@plt>:|<vulnerable>:"
   objdump -R src/vuln | grep puts   # puts's GOT address
   ```

3. **Compute the libc base.** You need to know the *offset* of `puts`
   within whatever `libc.so.6` the target container actually uses —
   not a number you should hardcode, since different systems ship
   different `libc` builds. Inside the running container (or an
   identical base image) you can look this up yourself:
   ```bash
   nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' puts$'
   nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' system$'
   strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh$'
   ```
   `leaked_address - puts_offset = libc_base`. From there,
   `libc_base + system_offset` and `libc_base + binsh_offset` give you
   everything you need for the next stage.

4. **Stage 2 — get a shell.** Build a second ROP chain: pop the
   `"/bin/sh"` address into `rdi`, then jump to `system()`. Since this
   process's stdin/stdout are the same network connection the whole
   time, `system("/bin/sh")` hands you an honest-to-goodness interactive
   shell **over that same TCP connection**. Send it `cat /flag.txt`.

5. **One gotcha you'll likely hit:** jumping straight into `system()`
   from this chain can crash with what looks like a segfault deep
   inside `libc`, even though everything about the chain "looks"
   correct. This is the same **stack-alignment** issue documented in
   `pwn-canary-bypass`'s README: redirecting control flow via a
   hijacked `ret` (instead of a real `call`) shifts the stack's 16-byte
   alignment by 8 bytes, and optimized `libc` internals can use SSE
   instructions that require that alignment. The fix is the same one:
   insert the address of a single spare `ret` instruction (any bare
   `0xc3` byte already in the binary works) right before `system()`'s
   address in your chain, to "absorb" one return and restore alignment.

## Tools you'll need

| Tool | Why |
|---|---|
| `objdump -d` / `-R` | Find the offset, the PLT/GOT addresses, and the gadget |
| `nm -D` / `strings` on `libc.so.6` | Find `puts`/`system`'s offsets and `"/bin/sh"`'s offset inside the **target's actual libc** |
| Python `socket` | Drive both stages of the exploit over the network |
| Python `struct` | Pack addresses as little-endian 8-byte values |
| Python `subprocess` | Shell out to `nm`/`strings` so your exploit computes offsets instead of hardcoding them |

**Don't ask for the exact offsets.** They come straight out of
whatever `libc.so.6` the container actually ships — compute them
yourself with the commands above, don't hardcode numbers you found
online for a different system. If you're stuck for more than 30-45
minutes on either stage, come back with exactly what you tried.

## Defender role

Once you have the flag, think about how to fix `src/vuln.c`:

- The real bug is still the same one as `pwn-baby`: an unbounded
  `gets()` into a fixed-size buffer. Replace it with a bounds-checked
  read (`fgets(buf, sizeof(buf), stdin)`), and the whole chain —
  leaking `libc`, computing offsets, building ROP — becomes irrelevant,
  because the overflow that made any of it possible never happens.
- Re-enabling the stack canary (removing `-fno-stack-protector`) would
  *also* stop a naive version of this attack, but it is not a complete
  fix on its own — see `pwn-canary-bypass` for why a canary alone can
  still be defeated given a way to leak or brute-force it. Fixing the
  actual bounds check is the right first move regardless.

After patching, redeploy and confirm the same two-stage payload that
worked before now fails safely — the oversized input should be
rejected or truncated well before it reaches the saved return address.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique, gadget addresses and offset
calculations stay exactly the same; only the flag text rotates. Submit
whatever you currently extract; stale ones expire.

## Where this sits in the Binary/RE ladder

`pwn-heap` (rung 7) → **`pwn-ret2libc` (rung 8)** →
`pwn-rop-chain` (rung 9). See `main.md` for the full ladder.
