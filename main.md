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

## Port scheme

Every category owns one **block of 1000 ports**, and within a block,
challenges are numbered in the order you should attempt them (rung 1
of a ladder gets the lowest port in its block, the hardest rung gets
the highest). Once you know the category, you know the port range:

| Category | Port block |
|---|---|
| 🌐 Web & Application Security | `5000`–`5999` |
| 🔐 Cryptography | `6000`–`6999` |
| 🔢 Binary Exploitation & Reverse Engineering | `7000`–`7999` |
| 📡 Network Protocols | `8000`–`8999` |
| 🔍 Digital Forensics | `9000`–`9999` |

(The scoreboard itself runs on `8080`, outside every category block —
it's platform infrastructure, not a challenge.)

Each category is building toward **10 challenges** (10 rungs per
ladder). Right now most categories have 3–5 built; the rest are listed
below as a visible backlog — ask, and the next one gets built.

---

## How to read this page

Challenges are grouped by **category**, and within each category,
**ordered easiest → hardest**. A category with more than one challenge
is a **ladder** — do them in order, since each one assumes the skill
from the one before it. ✅ rows are built and ready to run; ⬜ rows are
**planned** (not built yet) — they reserve their slot and port so the
numbering won't shift later, and they're exactly what "add more" means
next.

---

## 🌐 Web & Application Security (`5000`–`5999`)

| # | Port | Challenge | Difficulty | Skill |
|---|---|---|---|---|
| 1 | 5000 | ✅ [web-idor](services/web-idor/README.md) | Beginner | Broken Access Control (IDOR) |
| 2 | 5001 | ✅ [web-notes](services/web-notes/README.md) | Beginner | SQL Injection — auth bypass |
| 3 | 5002 | ✅ [web-sqli-union](services/web-sqli-union/README.md) | Beginner-Intermediate | SQL Injection — UNION data extraction |
| 4 | 5003 | ✅ [web-sqli-blind](services/web-sqli-blind/README.md) | Intermediate | SQL Injection — blind boolean, no errors shown |
| 5 | 5004 | ✅ [web-authbypass-jwt](services/web-authbypass-jwt/README.md) | Intermediate | Broken auth — JWT "alg: none" forgery |
| 6 | 5005 | ✅ [web-idor-tokens](services/web-idor-tokens/README.md) | Intermediate | Harder IDOR — share-link token is a bare hash of a public value (username), no secret |
| 7 | 5006 | ✅ [web-xss-stored](services/web-xss-stored/README.md) | Intermediate | Stored XSS — exfiltrate an admin's cookie, then use it |
| 8 | 5007 | ✅ [web-ssrf](services/web-ssrf/README.md) | Intermediate-Advanced | Server-Side Request Forgery reaching an internal-only endpoint |
| 9 | 5008 | ✅ [web-path-traversal](services/web-path-traversal/README.md) | Intermediate | Directory/path traversal to read `/flag.txt` directly |
| 10 | 5009 | ✅ [web-api-mass-assignment](services/web-api-mass-assignment/README.md) | Advanced | API accepts unexpected fields (e.g. `"role":"admin"`) on signup |

**SQLi ladder:** `web-notes` → `web-sqli-union` → `web-sqli-blind`. Each
step removes a crutch the last one gave you (visible error → generic
error → no signal but true/false at all). `web-idor` is a standalone
entry point into this category — do it first, it needs the least
setup. `web-authbypass-jwt` is a different bug family (broken
authentication/API security) rather than another SQLi rung.

**🌐 Web & Application Security is now complete (10/10).**

## 🔐 Cryptography (`6000`–`6999`)

| # | Port | Challenge | Difficulty | Skill |
|---|---|---|---|---|
| 1 | 6000 | ✅ [crypto-encoding](services/crypto-encoding/README.md) | Beginner | Recognizing & reversing stacked encodings (hex, Base64, reversal) |
| 2 | 6001 | ✅ [crypto-xor](services/crypto-xor/README.md) | Beginner-Intermediate | Breaking real crypto — XOR key reuse, chosen-plaintext attack |
| 3 | 6002 | ✅ [crypto-weak-rsa](services/crypto-weak-rsa/README.md) | Intermediate-Advanced | RSA shared-prime key recovery via `gcd` |
| 4 | 6003 | ⬜ `crypto-ecb-oracle` | Intermediate | AES-ECB mode pattern leakage / block manipulation |
| 5 | 6004 | ⬜ `crypto-padding-oracle` | Advanced | CBC padding oracle attack |
| 6 | 6005 | ⬜ `crypto-weak-hash` | Beginner-Intermediate | Cracking an unsalted, fast-hashed password via wordlist |
| 7 | 6006 | ⬜ `crypto-jwt-secret` | Intermediate | Brute-forcing a weak HMAC secret (distinct from `web-authbypass-jwt`'s `alg:none` bug) |
| 8 | 6007 | ⬜ `crypto-nonce-reuse` | Advanced | AES-GCM nonce reuse breaking authenticity/confidentiality |
| 9 | 6008 | ⬜ `crypto-rsa-small-e` | Advanced | Low public exponent + no padding — cube-root recovery |
| 10 | 6009 | ⬜ `crypto-timing` | Advanced | Timing side-channel on a naive string comparison |

**Ladder:** `crypto-encoding` has no key and nothing to break — it's
encoding literacy. `crypto-xor` is the first challenge where you
actually defeat a cryptographic weakness (a reused symmetric key).
`crypto-weak-rsa` is the first real public-key break (a key-generation
flaw, not symmetric reuse). Don't confuse "hard to read" (rung 1) with
"actually secure until it's broken" (rungs 2+) — rung 1's README
explains why.

## 🔢 Binary Exploitation & Reverse Engineering (`7000`–`7999`)

| # | Port | Challenge | Difficulty | Skill |
|---|---|---|---|---|
| 1 | 7000 | ✅ [re-crackme](services/re-crackme/README.md) | Beginner | Static analysis — `strings`, `objdump`, no exploitation |
| 2 | 7001 | ✅ [pwn-baby](services/pwn-baby/README.md) | Intermediate | Stack buffer overflow — ret2win |
| 3 | 7002 | ✅ [pwn-format](services/pwn-format/README.md) | Intermediate-Advanced | Format string — arbitrary memory write |
| 4 | 7003 | ⬜ `re-anti-debug` | Intermediate | Bypassing simple anti-debugging checks |
| 5 | 7004 | ⬜ `re-packed` | Intermediate | Unpacking a UPX-packed binary before analyzing it |
| 6 | 7005 | ⬜ `pwn-canary-bypass` | Advanced | Leaking and bypassing a stack canary |
| 7 | 7006 | ⬜ `pwn-heap` | Advanced | Basic heap overflow / use-after-free |
| 8 | 7007 | ⬜ `pwn-ret2libc` | Advanced | Return-to-libc with ASLR/PIE enabled |
| 9 | 7008 | ⬜ `pwn-rop-chain` | Advanced | Full ROP chain construction, no gift `win()` function |
| 10 | 7009 | ⬜ `re-mobile-apk` | Advanced | Basic Android APK reverse engineering |

**Ladder:** `re-crackme` teaches the tools (reading a binary's data and
disassembly) with zero risk of crashing anything. `pwn-baby` is the
first real memory-corruption exploit. `pwn-format` is the hardest
thing on the platform today — do it last of the three that exist.

## 📡 Network Protocols (`8000`–`8999`)

| # | Port | Challenge | Difficulty | Skill |
|---|---|---|---|---|
| 1 | 8000 | ✅ [net-auth](services/net-auth/README.md) | Beginner | Default/weak credentials left enabled |
| 2 | 8001 | ✅ [net-proto](services/net-proto/README.md) | Beginner-Intermediate | Command Injection via incomplete blacklist |
| 3 | 8002 | ✅ [net-replay](services/net-replay/README.md) | Intermediate | Replay attack — a static, leaked session token |
| 4 | 8003 | ✅ [net-rate-limit-bypass](services/net-rate-limit-bypass/README.md) | Intermediate | Rate limiter that resets on reconnect — brute force via scripted reconnects |
| 5 | 8004 | ⬜ `net-ssrf-pivot` | Intermediate-Advanced | Using one exposed service to reach an internal-only one |
| 6 | 8005 | ⬜ `net-dns-spoof-sim` | Advanced | Simulated DNS cache poisoning exercise |
| 7 | 8006 | ⬜ `net-tls-downgrade` | Advanced | Forcing a weak/no-encryption protocol fallback |
| 8 | 8007 | ⬜ `net-protocol-fuzzing` | Advanced | Crash/info-leak from malformed protocol input |
| 9 | 8008 | ⬜ `net-arp-spoof-sim` | Advanced | Simulated on-path (ARP spoofing) attacker exercise |
| 10 | 8009 | ⬜ `net-c2-beacon-analysis` | Advanced (blue-team) | Spotting malicious beacon traffic in a capture |

**Ladder:** `net-auth` is the simplest possible finding — a password
nobody disabled. `net-proto` needs understanding shell metacharacters.
`net-replay` requires noticing and reusing a leaked credential across
sessions. `net-rate-limit-bypass` is the first challenge here that
needs you to actually write and run a script, not just send one clever
input.

## 🔍 Digital Forensics (`9000`–`9999`)

| # | Port | Challenge | Difficulty | Skill |
|---|---|---|---|---|
| 1 | 9000 | ✅ [forensics-pcap-basic](services/forensics-pcap-basic/README.md) | Beginner | Plaintext capture — open it and read it |
| 2 | 9001 | ✅ [forensics-stego](services/forensics-stego/README.md) | Beginner-Intermediate | LSB steganography — hidden data in image pixels |
| 3 | 9002 | ✅ [forensics-pcap-ftp](services/forensics-pcap-ftp/README.md) | Intermediate | Multi-stream capture — following the *right* TCP stream |
| 4 | 9003 | ⬜ `forensics-memory-dump` | Intermediate | Basic memory forensics (string/process extraction from a memory image) |
| 5 | 9004 | ⬜ `forensics-disk-image` | Intermediate-Advanced | Autopsy-style disk image analysis, deleted file recovery |
| 6 | 9005 | ⬜ `forensics-log-analysis` | Intermediate | Finding an intrusion by sifting through log files |
| 7 | 9006 | ⬜ `forensics-metadata` | Beginner-Intermediate | Flag leaked in a file's EXIF/document metadata |
| 8 | 9007 | ⬜ `forensics-timeline` | Advanced | Reconstructing an attack timeline from multiple log sources |
| 9 | 9008 | ⬜ `forensics-malware-triage` | Advanced | Static analysis of a "malicious" sample (blue-team flavored) |
| 10 | 9009 | ⬜ `forensics-pcap-tls` | Advanced | Encrypted capture requiring key recovery or metadata analysis |

**Ladder:** `forensics-pcap-basic` is the flag sitting in plain text in
one packet. `forensics-stego` hides it at the bit level inside an
image. `forensics-pcap-ftp` hides it in *which conversation* you
choose to look at. Three different "where do I even look" skills, in
increasing order of how easy it is to miss.

---

## A suggested path through everything (optional)

If you're not sure where to start, a reasonable order that interleaves
categories (so you're not doing five SQLi challenges in a row) across
everything currently built:

1. `net-auth` — the single easiest challenge on the platform
2. `web-idor` — fastest possible browser-only win
3. `forensics-pcap-basic` — open a capture, read the flag
4. `web-notes` — classic SQLi, still browser only
5. `crypto-encoding` — no exploitation yet, just careful observation
6. `net-proto` — first time using `nc`, command injection
7. `re-crackme` — first binary challenge, still no exploitation
8. `web-sqli-union` — SQLi gets a level harder
9. `forensics-stego` — a different kind of "find the hidden thing"
10. `crypto-xor` — first real crypto break
11. `web-authbypass-jwt` — forge a token instead of guessing a password
12. `web-sqli-blind` — SQLi with (almost) no signal at all
13. `forensics-pcap-ftp` — find the *right* stream, not just *a* stream
14. `net-replay` — capture and reuse a leaked credential
15. `pwn-baby` — first real memory-corruption exploit
16. `crypto-weak-rsa` — break real public-key crypto via a key-gen flaw
17. `pwn-format` — the hardest challenge on the platform today

This is a suggestion, not a requirement — the scoreboard tracks whoever
solves what, in whatever order your team actually goes.

---

## What's next (the road to 10-per-category)

Every ⬜ row above is a reserved slot, not just an idea — its name and
port are already fixed so adding it later is a small diff, not a
renumbering. Ask for any of them by name (or just "the next rung in
[category]") and it gets built, tested end-to-end, and wired in the
same way every ✅ row already was.

A few of these intentionally lean toward **blue-team / defensive**
skills rather than pure attacker exploitation (`net-c2-beacon-analysis`,
`forensics-malware-triage`, `forensics-log-analysis`,
`forensics-timeline`) — a real attack-defense competition rewards
spotting and understanding an attack as much as executing one, so the
backlog isn't 100% "break this."

This list will keep growing past 10-per-category too, once the first
10 are filled in and the team's skill level calls for a rung 11.
