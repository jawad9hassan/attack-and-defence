# Attack & Defence — a self-hosted A/D-CTF training range

A small, scalable attack-defense CTF simulation, built for a five-person
team training for a real A/D competition. One command brings up:

- **Vulnerable services** you attack and defend (currently eleven,
  covering web, binary, crypto, network-protocol, and digital-forensics
  bug classes — several as difficulty ladders within one category —
  designed to keep scaling: see `docs/ADDING_A_SERVICE.md`)
- **A checker** that runs real, round-based game operations: it verifies
  each service's normal functionality, rotates its flag every round, and
  expires old flags — the same mechanics a real attack-defense gameserver
  uses
- **A live scoreboard** (auto-refreshing) with defense (uptime) scores and
  an attacker leaderboard

**👉 [`main.md`](main.md) is the challenge index** — every challenge,
grouped by category, ordered easiest → hardest, with its port/command
and a link to its own walkthrough. Start there once the platform is up.

Read `docs/ARCHITECTURE.md` for how the pieces fit together, and the
commit history (`git log`) for how — and why — each piece was built, in
order, with everything tested before it was committed.

## Quick start

```bash
cp .env.example .env    # optional — defaults work fine for local practice
docker compose up --build
```

Then:

- **Scoreboard:** `http://localhost:8080`
- **Challenge index (start here):** [`main.md`](main.md) — every
  service's port/command, grouped by category, easiest → hardest

Each service's own `README.md` (linked from `main.md`) explains its
vulnerability class and gives you a path to discover the exploit
yourself, without handing you the exact payload.

## Services

**See [`main.md`](main.md) for the full, up-to-date challenge index** —
all eleven services, grouped by category, ordered easiest → hardest,
each with a direct link to its own walkthrough. That file is the single
source of truth for "what challenges exist and in what order"; this
README won't duplicate the table and risk it going stale.

More than one service per category is intentional, organized as
**difficulty ladders** (e.g. three SQLi challenges of increasing
difficulty, three binary-exploitation challenges) rather than one-off
duplicates — a real competition rarely has just one of anything, and
the plan is to keep adding rungs and whole new categories over time.
See `main.md`'s "What's next" section for what's planned, and
`docs/ADDING_A_SERVICE.md` for how straightforward adding another one
is meant to be.

## How a training session works

1. Attackers exploit a service and steal its **current** flag (flags
   rotate every round — see `config/game.yml`'s `round_time_seconds` and
   `flag_lifetime_rounds` — so a stale flag stops being valid).
2. `POST` the captured flag to the scoreboard:
   ```bash
   curl -X POST http://localhost:8080/api/submit \
     -H "Content-Type: application/json" \
     -d '{"flag": "FLAG{...}", "submitter": "your_name"}'
   ```
3. Defenders read the vulnerable source, patch it, and redeploy
   (`docker compose up --build <service-name>`) — the checker's SLA check
   will immediately tell you if the patch broke normal functionality
   instead of just the bug.
4. Watch the live scoreboard for both sides of the score.

Full operational guidance (session timing, rotating attacker/defender
roles, what to do afterward) is in `docs/RULES.md`.

## Repository layout

```
attack-and-defence/
├── main.md                   ← START HERE: challenge index, easiest → hardest
├── docker-compose.yml        ← brings up everything together
├── config/game.yml           ← round timing, flag lifetime, service registry
├── services/
│   ├── web-notes/             (SQL Injection, ladder rung 1/3)
│   ├── web-sqli-union/        (SQL Injection, ladder rung 2/3)
│   ├── web-sqli-blind/        (SQL Injection, ladder rung 3/3)
│   ├── web-idor/               (Broken Access Control / IDOR)
│   ├── re-crackme/             (Reverse Engineering, ladder rung 1/3)
│   ├── pwn-baby/               (Stack Overflow / ret2win, ladder rung 2/3)
│   ├── pwn-format/             (Format String, ladder rung 3/3)
│   ├── crypto-encoding/        (Layered encoding, ladder rung 1/2)
│   ├── crypto-xor/             (XOR key-reuse / chosen-plaintext, ladder rung 2/2)
│   ├── net-proto/              (Command Injection)
│   ├── forensics-stego/        (LSB Steganography)
│   └── _template/              (copy this to add a new service)
├── platform/
│   ├── common/flagd.py         (shared flag-rotation sidecar)
│   ├── checker/                (round engine + per-service checker modules)
│   └── scoreboard/             (Flask + SQLite, live scoreboard page)
└── docs/
    ├── ARCHITECTURE.md
    ├── ADDING_A_SERVICE.md
    └── RULES.md
```

## Changelog

- ✅ `web-notes` — SQL Injection service
- ✅ `pwn-baby` — Stack Overflow (ret2win) service
- ✅ flagd — live, per-round flag rotation without rebuilding services
- ✅ Round-based checker (SLA + flag planting)
- ✅ Live scoreboard (defense uptime + attacker leaderboard)
- ✅ Unified `docker-compose.yml` + scalability docs + service template
- ✅ `web-idor` — Broken Access Control (IDOR) service
- ✅ `crypto-xor` — XOR key-reuse / chosen-plaintext crypto service
- ✅ `net-proto` — Command Injection (incomplete blacklist) service
- ✅ `pwn-format` — Format String (arbitrary write) service
- ✅ `web-sqli-union` — UNION-based SQLi (SQLi ladder, rung 2 of 3)
- ✅ `web-sqli-blind` — Blind boolean-based SQLi (SQLi ladder, rung 3 of 3)
- ✅ `crypto-encoding` — layered encoding puzzle (crypto ladder, rung 1 of 2)
- ✅ `re-crackme` — intro reverse engineering (binary ladder, rung 1 of 3)
- ✅ `forensics-stego` — LSB steganography (new category: digital forensics)
- ✅ `main.md` — challenge index, grouped by category, easiest → hardest
- ⬜ A second Broken Access Control challenge (harder than `web-idor`)
- ⬜ A second Command Injection / network-protocol challenge
- ⬜ A PCAP/network-traffic-analysis challenge (digital forensics ladder)
- ⬜ A heap-based binary exploitation challenge (binary ladder, rung 4)
- ⬜ A harder crypto challenge, e.g. weak RSA parameters (crypto ladder, rung 3)
- ⬜ Real multi-team isolation (see `docs/ARCHITECTURE.md`'s scaling section)

This list keeps growing — the architecture (checker module contract +
service template) is deliberately built so each new addition is a small,
self-contained diff, not a rewrite.

## A note on how this was built

Every piece in this repo was written, tested, and verified working before
being committed — including a real bug found and fixed along the way (a
checker module that occasionally misread a service's response; see the
commit that fixes it for what happened and why). `git log` is a genuine,
readable build history, not a single dump.
