# Challenge 7: pwn-heap (Basic Heap Overflow / Function Pointer Hijack)

A tiny "notes" service. It lets you create one note (`NEW`) and print it
back (`SHOW`). The note is a heap-allocated struct that happens to store
a function pointer right after the text buffer — and the text buffer
isn't bounds-checked against that struct's actual size.

## Running it

Standalone:

```bash
cd services/pwn-heap
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-heap
```

The service listens on port `9991`:

```bash
nc localhost 9991
```

## The code (not hidden from you — read it, that's the point)

Look at `src/notes.c`. The important part is the struct and the `NEW`
handler:

```c
struct note {
    char data[DATA_SIZE];              // 56 bytes
    void (*print)(struct note *);      // called by SHOW
};
```

`NEW <hex bytes>` heap-allocates one `struct note`, sets `print` to a
default printing function, then copies your hex-decoded bytes straight
into `note->data` with `memcpy()` — using a length taken from however
many bytes **you** sent, checked only against a generous wire-protocol
maximum (200 bytes), **not** against `DATA_SIZE` (56). `SHOW` calls
`current->print(current)`.

Because `data` and `print` sit in the **same heap allocation**, back to
back, there is nothing between them to stop an overflow: send more than
56 bytes in one `NEW` and the extra bytes land directly on top of
`print`. Whatever 8 bytes end up there is exactly what `SHOW` will call.

## What you need to work out

Everything you need is in the `struct note` definition above — this one
doesn't require any disassembly at all, unlike the other `pwn-*`
challenges.

### Suggested analysis steps

1. **Work out the offset.** `data` is first, `print` is immediately
   after. How many bytes of filler do you need before the 8 bytes that
   will become the function pointer? (Hint: it's exactly `DATA_SIZE`.)

2. **Find `win()`'s address**, the same way as every other binary
   challenge on this platform:
   ```bash
   objdump -d src/notes | grep -A2 "<win>:"
   ```
   The binary is built with `-no-pie`, so this address is fixed.

3. **Build the payload**: `filler (56 bytes) + win()'s address packed
   as little-endian 8 bytes`, hex-encode it, and send it as
   `NEW <hex>`.

4. **Send `SHOW`.** The server calls through what it thinks is still
   the default print function — but it's now `win()`.

Unlike `pwn-canary-bypass`, there's no stack-alignment trick to worry
about here: `current->print(current)` is an ordinary compiled function
call, not a hand-built return, so the compiler already set the stack up
correctly for whatever gets called.

## Tools you'll need

| Tool | Why |
|---|---|
| `objdump -d` | Find `win()`'s address |
| Python `struct` | Pack the address as a little-endian 8-byte value |
| Python `socket` | Send `NEW ...` and `SHOW` over the network |

**Don't ask for the exact offset.** It's derivable directly from the
struct definition above — no guessing or brute force needed for this
one. If you're stuck for more than 20-30 minutes, come back with
exactly what you tried.

## Defender role

Once you have the flag, think about how to fix `src/notes.c` without
losing the "store a function pointer alongside data" design (plenty of
real plugin/callback systems do exactly this):

- The real bug is the unchecked length in the `NEW` handler: it should
  reject or truncate anything longer than `DATA_SIZE`, not just the
  generous wire-protocol cap.
- A deeper layout fix: put `print` **before** `data` in the struct (or
  separate them into different allocations entirely) so that even an
  unbounded overflow of `data` can't reach a pointer that controls
  execution — it would just corrupt more of its own text buffer, or
  heap metadata belonging to the *next* allocation (still worth fixing,
  but no longer a direct, one-shot function-pointer hijack).
- This bug class generalizes: any time attacker-controlled, length-
  unchecked data shares a heap allocation with a pointer that later gets
  called, dereferenced, or `free()`'d, that pointer is a target.

After patching, redeploy and confirm the same payload that worked
before now fails safely — the oversized `NEW` should be rejected, and
`SHOW` should keep calling the real default print function.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique and offset stay exactly the
same; only the flag text rotates. Submit whatever you currently extract;
stale ones expire.

## Where this sits in the Binary/RE ladder

`pwn-canary-bypass` (rung 6) → **`pwn-heap` (rung 7)** →
`pwn-ret2libc` (rung 8). See `main.md` for the full ladder.
