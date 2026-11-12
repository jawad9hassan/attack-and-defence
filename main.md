# attack-and-defence — Challenge Index

**Start here.** This is the one-stop landing page for every challenge on
the platform: what it is, how hard it is relative to the others in its
category, which port/command reaches it, and a link to its own
`README.md` for the full walkthrough (no-spoiler analysis steps +
defender guidance).

For how the platform itself works (rounds, flag rotation, the checker,
the scoreboard), see `README.md` at the repo root and
`docs/ARCHITECTURE.md`.

```bash
docker compose up --build   # brings up everything at once
```

Scoreboard (live scores): **http://localhost:8080**

---

## How to read this page

Challenges are grouped by **category**, and within each category,
**ordered easiest → hardest**. A category with more than one challenge
is a **ladder** — do them in order, since each one assumes the skill
from the one before it. A category with only one challenge today will
grow a ladder of its own over time (see "What's next" at the bottom).

---

## 🌐 Web & Application Security

| # | Challenge | Difficulty | Skill | URL |
|---|---|---|---|---|
| 1 | [web-idor](services/web-idor/README.md) | Beginner | Broken Access Control (IDOR) | http://localhost:5001 |
| 2 | [web-notes](services/web-notes/README.md) | Beginner | SQL Injection — auth bypass | http://localhost:5000 |
| 3 | [web-sqli-union](services/web-sqli-union/README.md) | Beginner-Intermediate | SQL Injection — UNION data extraction | http://localhost:5002 |
| 4 | [web-sqli-blind](services/web-sqli-blind/README.md) | Intermediate | SQL Injection — blind boolean, no errors shown | http://localhost:5003 |

**SQLi ladder:** `web-notes` → `web-sqli-union` → `web-sqli-blind`. Each
step removes a crutch the last one gave you (visible error → generic
error → no signal but true/false at all). `web-idor` is a standalone
entry point into this category — do it first, it needs the least setup.

## 🔢 Binary Exploitation & Reverse Engineering

| # | Challenge | Difficulty | Skill | Command |
|---|---|---|---|---|
| 1 | [re-crackme](services/re-crackme/README.md) | Beginner | Static analysis — `strings`, `objdump`, no exploitation | `nc localhost 9997` |
| 2 | [pwn-baby](services/pwn-baby/README.md) | Intermediate | Stack buffer overflow — ret2win | `nc localhost 9999` |
| 3 | [pwn-format](services/pwn-format/README.md) | Intermediate-Advanced | Format string — arbitrary memory write | `nc localhost 9998` |

**Ladder:** `re-crackme` teaches the tools (reading a binary's data and
disassembly) with zero risk of crashing anything. `pwn-baby` is the
first real memory-corruption exploit. `pwn-format` is the hardest thing
on the platform today — do it last.

## 🔐 Cryptography

| # | Challenge | Difficulty | Skill | Command |
|---|---|---|---|---|
| 1 | [crypto-encoding](services/crypto-encoding/README.md) | Beginner | Recognizing & reversing stacked encodings (hex, Base64, reversal) | `nc localhost 9100` |
| 2 | [crypto-xor](services/crypto-xor/README.md) | Beginner-Intermediate | Breaking real crypto — XOR key reuse, chosen-plaintext attack | `nc localhost 9000` |

**Ladder:** `crypto-encoding` has no key and nothing to break — it's
encoding literacy. `crypto-xor` is the first challenge where you
actually defeat a cryptographic weakness. Don't confuse the two
categories of "hard to read" (step 1) and "actually secure until it's
broken" (step 2) — the README for step 1 explains why.

## 📡 Network Protocols

| # | Challenge | Difficulty | Skill | Command |
|---|---|---|---|---|
| 1 | [net-proto](services/net-proto/README.md) | Beginner-Intermediate | Command Injection via incomplete blacklist | `nc localhost 9200` |

No ladder yet — see "What's next" below.

## 🔍 Digital Forensics

| # | Challenge | Difficulty | Skill | URL |
|---|---|---|---|---|
| 1 | [forensics-stego](services/forensics-stego/README.md) | Beginner-Intermediate | LSB steganography — hidden data in image pixels | http://localhost:5004 |

No ladder yet — see "What's next" below. This category is also where
PCAP/network-traffic analysis (Wireshark-style) would eventually live,
if the team wants to go there before the competition.

---

## A suggested path through everything (optional)

If you're not sure where to start, a reasonable order that interleaves
categories (so you're not doing five SQLi challenges in a row) is:

1. `web-idor` — fastest possible first win, browser only
2. `web-notes` — classic SQLi, still browser only
3. `net-proto` — first time using `nc`, command injection
4. `crypto-encoding` — no exploitation yet, just careful observation
5. `re-crackme` — first binary challenge, still no exploitation
6. `web-sqli-union` — SQLi gets a level harder
7. `forensics-stego` — a different kind of "find the hidden thing"
8. `crypto-xor` — first real crypto break
9. `web-sqli-blind` — SQLi with (almost) no signal at all
10. `pwn-baby` — first real memory-corruption exploit
11. `pwn-format` — the hardest challenge on the platform today

This is a suggestion, not a requirement — the scoreboard tracks whoever
solves what, in whatever order your team actually goes.

---

## What's next (ladders still growing)

The architecture is built so a new rung in any ladder — or a whole new
category — is a small, self-contained addition (see
`docs/ADDING_A_SERVICE.md` and `services/_template/`). Planned next
steps, in no particular order:

- A 2nd Broken Access Control challenge (a harder variant than
  `web-idor`, e.g. predictable tokens instead of sequential IDs)
- A 2nd Command Injection challenge (network protocol category)
- A PCAP/network-traffic-analysis challenge (digital forensics category)
- A heap-based binary exploitation challenge (binary ladder, rung 4)
- A harder crypto challenge, e.g. weak RSA parameters (crypto ladder,
  rung 3)

This list grows as the team's skill grows — if a category starts
feeling easy, say so and the next rung gets built.
