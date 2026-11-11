# Challenge 2: pwn-baby (Stack Buffer Overflow / ret2win)

A small network service written in C that asks your name and echoes it
back. It has a classic **stack buffer overflow**, and the goal is to reach
a `win()` function that exists in the binary but is never called on the
normal code path.

## Running it

Standalone:

```bash
cd services/pwn-baby
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-baby
```

The service listens on port `9999`:

```bash
nc localhost 9999
```

## The code (not hidden from you — read it, that's the point)

Look at `src/vuln.c`. Two things matter:

1. `win()` exists and prints the flag, but `main()` never calls it.
2. `vulnerable_echo()` reads into a fixed-size buffer `char name[64]`
   using `gets(name)`. `gets` performs **no bounds checking whatsoever** —
   if your input is longer than 64 bytes, the extra data overwrites
   whatever comes after `name` on the stack, including the **saved return
   address**: where the program jumps back to once the current function
   returns.

## What you need to work out

If you can figure out **exactly** how many bytes of padding come before
the saved return address, and overwrite it with the address of `win()`
instead, the program jumps into `win()` instead of returning normally.

### Suggested analysis steps

1. **Find `win()`'s address:**
   ```bash
   objdump -d src/vuln | grep -A2 "<win>:"
   ```
   The binary is built with `-no-pie`, so `win()`'s address is **fixed**
   and doesn't change between runs — deliberately, to keep this approachable.

2. **Find the padding offset** before the return address. This is the part
   you need to work out yourself. The buffer is 64 bytes, but there's
   another saved value (`saved RBP`) on the stack between it and the
   return address. Try different input lengths (e.g. 64, 72, 80...) and
   watch when the program's behavior changes (prints the flag, crashes, or
   returns normally) — simple binary search. Or use `gdb` (with `pwndbg` if
   available) to watch the stack directly.

3. **Write a Python exploit** that builds the payload:
   ```python
   payload = b"A" * <padding_length> + struct.pack("<Q", <win_address>)
   ```
   The address must be **little-endian**, 8 bytes (`struct.pack("<Q",
   addr)`), since this is `x86-64`.

4. **Send the payload over the network** (not stdin directly — the
   service runs remotely in the container). Use Python's `socket` module,
   or `nc`:
   ```bash
   python3 -c "print('A'*72, end='')" | nc localhost 9999
   ```
   (this is a rough example — you still need to append the address in the
   right binary format, not as plain text).

## Tools you'll need

| Tool | Why |
|---|---|
| `objdump -d` | Read the disassembly, find `win()`'s address |
| `gdb` (+ `pwndbg` if available) | Run the binary locally and watch the stack live |
| Python `struct` | Convert addresses to bytes in the right byte order |
| Python `socket` | Send the payload over the network to port 9999 |

**Don't ask for the exact offset.** Work it out with the steps above. If
you're stuck for more than 30-45 minutes, come back with exactly what you
tried and what happened (e.g. "I tried 64 bytes and got a segfault", or
"I tried 72 and nothing changed") and you'll get a sharper hint.

## Defender role

Once you have the flag, think about how to fix `src/vuln.c` without
changing the program's normal behavior (it still has to greet you by
name). More than one correct approach exists:

- Replace `gets()` with a bounds-checked read (e.g. `fgets`).
- Making the buffer bigger alone isn't a fix — it just delays the problem.
- Add compiler flags that enable stack canary protection.

After patching, redeploy and confirm the same payload that worked before
now fails safely (the program should reject or safely reject the input,
never reach `win()`).

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique and offset stay exactly the
same; only the flag text rotates. Submit whatever you currently extract;
stale ones expire.
