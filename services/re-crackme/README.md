# Challenge 10: License Validator (Binary RE, rung 1 of 3)

**Ladder:** this is step 1, the easiest binary challenge on the
platform — pure static/dynamic **analysis**, no memory corruption at
all. Step 2 is `services/pwn-baby` (stack buffer overflow, hijacking
control flow). Step 3 is `services/pwn-format` (format string,
arbitrary memory write). Do this one first if binary exploitation is
new to your team — it teaches the *tools* (disassembly, reading raw
bytes out of a binary) without needing memory-corruption theory yet.

A tiny C program that asks for a "license key" and checks it against a
hardcoded value — except the real key isn't stored as plain text in the
binary. It's lightly obfuscated, specifically so a quick `strings` scan
won't hand it to you. You'll need to actually read the binary's
disassembly to recover it.

## Running it

Standalone:

```bash
cd services/re-crackme
docker compose up --build
```

Or as part of the full platform:

```bash
docker compose up --build re-crackme   # from the repo root
```

```bash
nc localhost 9997
```

## The code — but you shouldn't need it

Unlike every other challenge on this platform, **don't look at
`src/crackme.c` for this one.** The whole point is practicing the skill
of recovering information from a compiled binary you don't have the
source for — exactly like a real reverse-engineering task. (The source
is still there for the defender step afterward, and for you to check
your work once you've solved it.)

## What you need to work out

### Suggested analysis steps

1. **Get the binary.** Build it yourself locally for analysis (same
   flags the service uses):
   ```bash
   cd services/re-crackme/src
   gcc -no-pie -o crackme crackme.c   # only if you peeked -- otherwise ask for a copy of the compiled binary
   ```
   Or just connect to the live service with `nc` and interact with it —
   either is a valid way to approach this, but for static analysis
   you'll want a local copy of the binary.

2. **Try the obvious thing first:**
   ```bash
   strings crackme | grep -i key
   ```
   Notice what's NOT there. The real key isn't a plain string
   anywhere in the binary — that's deliberate.

3. **Look at the raw bytes instead.** Somewhere in the binary's
   read-only data section, there's a fixed-size array of bytes that
   doesn't look like readable text. Find it:
   ```bash
   objdump -s -j .rodata crackme
   ```
   Scan the output for a short run of bytes that doesn't spell anything
   in the ASCII column on the right — that's a strong candidate for
   "something obfuscated lives here."

4. **Find out HOW it's obfuscated by reading the code around the
   comparison**, not the data:
   ```bash
   objdump -d crackme | less
   ```
   Look for the part of `main` that loops over those bytes before
   comparing your input. A single bitwise instruction there is doing
   all the obfuscation work — find it, and its constant operand.

5. **Reverse the obfuscation by hand** (or with a two-line Python
   script) using what you found in steps 3 and 4, and you'll have the
   real key.

6. Connect and send it:
   ```bash
   nc localhost 9997
   ```

**Don't ask for the exact key, the exact bytes, or the exact constant.**
Everything you need is visible in `objdump` output once you know where
to look — that's the entire exercise. If you're stuck for more than
20-30 minutes, come back with exactly what `objdump -s -j .rodata`
showed you and what instruction you found near the comparison, and
you'll get a sharper hint.

## Defender role

This is a reminder, not a classic "find the vulnerable line" fix: **any
secret baked into a client-distributed or attacker-reachable binary can
be recovered with enough reverse-engineering effort.** Light obfuscation
(like the single-byte XOR here) only raises the bar slightly against
casual inspection (`strings`) — it does nothing against someone willing
to read disassembly, which took only a few minutes.

As a team discussion (no code change required to pass the checker):
what would an *actually* defensible design look like here? (Hint: the
license check shouldn't live in a binary the "attacker" can download and
analyze offline at all — it should be verified by a server they don't
control, the same way `print_flag()` already reads `/flag.txt`
server-side rather than embedding the flag in the binary.)

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes every
round via `flagd` — the license key and the obfuscation never change,
only the flag text you get once you unlock it.
