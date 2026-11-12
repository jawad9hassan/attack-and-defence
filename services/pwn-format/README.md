# Challenge 6: pwn-format (Format String Vulnerability)

A small network service written in C that asks for your name, then asks
for feedback, and echoes a "thanks" message back. It has a classic
**format string vulnerability**, and the goal is to flip an internal
`unlocked` flag from false to true so the service hands you the flag as
a "reward."

This is a step up in difficulty from `pwn-baby`: instead of overwriting a
return address, you'll be overwriting an arbitrary value in memory using
nothing but `printf()`'s own formatting directives.

## Running it

Standalone:

```bash
cd services/pwn-format
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build pwn-format
```

The service listens on port `9998`:

```bash
nc localhost 9998
```

## The code (read it, that's the point)

Look at `src/vuln.c`. Three things matter:

1. `int unlocked = 0;` is a global variable. There is **no code path** in
   `main()` that ever sets it to anything else — the compiler would tell
   you if there were.
2. If `unlocked` is ever nonzero when the final check runs, `print_flag()`
   gets called.
3. Your feedback string is passed straight to `printf()` as the **format
   string itself**, not as data:
   ```c
   printf(feedback);   /* should have been printf("%s", feedback); */
   ```

## Background: how format strings get you arbitrary memory writes

`printf("%d", x)` works because `printf` is variadic — it trusts its
*format string* to tell it how many extra arguments follow, and of what
type. When the format string is attacker-controlled and there are no
real extra arguments, `printf` still goes looking for them: it just reads
whatever happens to be sitting in the registers and stack slots the
calling convention reserves for arguments 2, 3, 4...

Three directives matter here:

- `%p` / `%x` — read the next "argument" as a pointer/number and print
  it. Harmless on its own, but it tells you **what garbage is currently
  sitting in each argument slot** — useful for reconnaissance.
- `%N$p` — same as above, but for a *specific* argument slot `N`
  (direct parameter access), instead of just "the next one in order."
- `%N$n` — instead of printing, **writes** the number of characters
  printed *so far* into the memory address given by argument slot `N`.

The exploit works in two stages:

1. **Figure out which argument index `N` corresponds to a specific byte
   offset inside your own feedback string.** Since nothing else feeds
   `printf` any real arguments, enough of your own input eventually gets
   read back as "argument values" too. Probe with a recognizable 8-byte
   marker plus a bunch of `%1$p|%2$p|%3$p|...` and see which index echoes
   your marker back.
2. **Once you know that offset ↔ index mapping, replace the marker bytes
   with the address you actually want to write to**, and reference that
   same index with `%N$n` — placed *earlier* in your string, before the
   raw address bytes. `%n` doesn't care where in the string it's written
   textually; it reads whatever is currently in that argument slot's
   memory at the moment it executes.

## What you need to work out

### Suggested analysis steps

1. **Find `unlocked`'s address** — it's a global, so it has a fixed,
   discoverable address in the binary (built with `-no-pie`, same as
   `pwn-baby`):
   ```bash
   nm src/vuln | grep unlocked
   # or: objdump -t src/vuln | grep unlocked
   ```

2. **Connect and try something harmless first** — a plain name and
   feedback with no `%` characters — to see the normal flow.

3. **Probe for your own offset.** Send a feedback string containing a
   chunk of `%1$p|%2$p|%3$p|...` (say, up to `%20$p`) followed by an
   8-byte marker you'll recognize (e.g. `b"MARKMARK"`). Look through the
   leaked values for the one that matches your marker's bytes — that
   tells you which argument index `N0` lines up with the *start* of your
   buffer. From there, argument slots are spaced one 8-byte stack slot
   apart, so you can work out which index lines up with any later byte
   offset in your buffer too.

4. **Build the final payload.** You need, in this order, inside your
   feedback string:
   - a short literal prefix (so the character count isn't zero when `%n`
     fires — `%n` writing `0` is a no-op, since the flag starts at `0`
     anyway),
   - the `%N$n` directive, where `N` is the argument index that lines up
     with a *later* byte offset in your own buffer,
   - padding so that later offset is reached,
   - the 8 raw bytes of `unlocked`'s address (little-endian, via
     `struct.pack("<Q", addr)`), placed at exactly that offset.

   The address bytes will likely contain embedded `0x00` bytes (common
   for `-no-pie` addresses under `0x0000000000500000`) — that's fine, as
   long as they come **after** the `%N$n` text in your string, not
   before it. `printf` only needs to *scan past* the directive before it
   executes; what happens after is irrelevant to the write itself.

5. **Send it over the network**, not stdin directly:
   ```python
   import socket
   s = socket.create_connection(("localhost", 9998))
   s.recv(4096)
   s.sendall(b"attacker\n")
   s.recv(4096)
   s.sendall(payload + b"\n")
   print(s.recv(4096))
   ```

## Tools you'll need

| Tool | Why |
|---|---|
| `nm` / `objdump -t` | Find `unlocked`'s fixed address |
| Python `struct` | Pack the address as little-endian bytes |
| Python `socket` | Send the payload over the network to port 9998 |
| A scratch Python script | Automate the offset-probing step — doing it by hand one connection at a time is slow |

**Don't ask for the exact argument index or offset.** They depend on
exactly how you structure your probe, and working them out yourself is
the whole exercise. If you're stuck for more than 30-45 minutes, come
back with what your probe actually leaked (e.g. "argument 6 showed my
marker, but I'm not sure what offset that maps to for a later byte in my
buffer") and you'll get a sharper hint.

## Defender role

Once you have the flag, open `src/vuln.c` and think about the fix. The
real bug is a single line:

```c
printf(feedback);          /* vulnerable: feedback IS the format string */
printf("%s", feedback);    /* fixed: feedback is just data to print */
```

This is one of the most common real-world instances of this bug class —
any time user input reaches a `printf`-family function (or `syslog`,
`fprintf`, etc.) as the *format* argument rather than as a *value*
argument, the same class of attack applies. The fix is always the same
shape: never let attacker-controlled data become the format string.

After patching, confirm:
- a normal name/feedback round-trip still works and still says "Thanks
  for your feedback!"
- feedback containing `%` characters (e.g. `100% satisfied`) is printed
  back **literally**, not interpreted
- the exploit payload that worked before no longer unlocks the flag

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the exploit technique, the address, and the argument
index all stay exactly the same; only the flag text rotates. Submit
whatever you currently extract; stale ones expire.
