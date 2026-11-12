# Attack & Defence — a self-hosted A/D-CTF training range

A small, scalable attack-defense CTF simulation, built for a five-person
team training for a real A/D competition. One command brings up:

- **Vulnerable services** you attack and defend (currently seventeen,
  covering web, binary, crypto, network-protocol, and digital-forensics
  bug classes — each category is its own difficulty ladder, building
  toward 10 rungs per category — designed to keep scaling: see
  `docs/ADDING_A_SERVICE.md`)
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

After the first setup, the team can pull new challenges and restart
with one command instead of the `git pull` + `docker compose down` +
`docker compose up --build` sequence by hand:

```bash
./setup.sh              # pull latest, stop old containers, rebuild, run
./setup.sh --detached    # same, but keep running in the background
./setup.sh --reset       # also wipes the scoreboard's saved data —
                         # use this right before the real competition
                         # run, not during practice
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
all seventeen built services plus the full 10-per-category roadmap
(built and planned), grouped by category, ordered easiest → hardest,
each with a direct link to its own walkthrough. That file is the
single source of truth for "what challenges exist, what's planned next,
and in what order"; this README won't duplicate the table and risk it
going stale.

More than one service per category is intentional, organized as
**difficulty ladders** (e.g. five web challenges, three crypto
challenges, three network challenges, each of increasing difficulty)
rather than one-off duplicates — a real competition rarely has just one
of anything. Every category is explicitly building toward 10 rungs;
`main.md` lists the still-unbuilt slots by name and port so the plan is
visible even before each one exists. See `docs/ADDING_A_SERVICE.md` for
how straightforward adding another one is meant to be.

Also new this round: a dedicated **port scheme** — each category owns
a 1000-port block (`5000`s = Web, `6000`s = Crypto, `7000`s =
Binary/RE, `8000`s = Network, `9000`s = Forensics), so you can tell a
challenge's category from its port alone. See `main.md`'s "Port
scheme" section.

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
│   ├── web-idor/               (Broken Access Control / IDOR, 5000)
│   ├── web-notes/              (SQL Injection, 5001, ladder rung 1/5)
│   ├── web-sqli-union/         (SQL Injection, 5002, ladder rung 2/5)
│   ├── web-sqli-blind/         (SQL Injection, 5003, ladder rung 3/5)
│   ├── web-authbypass-jwt/     (Broken Auth / JWT forgery, 5004)
│   ├── crypto-encoding/        (Layered encoding, 6000, ladder rung 1/3)
│   ├── crypto-xor/             (XOR key-reuse, 6001, ladder rung 2/3)
│   ├── crypto-weak-rsa/        (RSA shared-prime break, 6002, ladder rung 3/3)
│   ├── re-crackme/             (Reverse Engineering, 7000, ladder rung 1/3)
│   ├── pwn-baby/               (Stack Overflow / ret2win, 7001, ladder rung 2/3)
│   ├── pwn-format/             (Format String, 7002, ladder rung 3/3)
│   ├── net-auth/               (Default credentials, 8000, ladder rung 1/3)
│   ├── net-proto/              (Command Injection, 8001, ladder rung 2/3)
│   ├── net-replay/             (Replay attack, 8002, ladder rung 3/3)
│   ├── forensics-pcap-basic/   (Plaintext capture, 9000, ladder rung 1/3)
│   ├── forensics-stego/        (LSB Steganography, 9001, ladder rung 2/3)
│   ├── forensics-pcap-ftp/     (Multi-stream capture, 9002, ladder rung 3/3)
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
- ✅ Category-based port scheme (`5000`s Web, `6000`s Crypto, `7000`s
  Binary/RE, `8000`s Network, `9000`s Forensics)
- ✅ `web-authbypass-jwt` — broken auth, forging a JWT via `alg: none`
- ✅ `crypto-weak-rsa` — RSA shared-prime key recovery (crypto ladder, rung 3)
- ✅ `net-auth` — default/weak credentials (network ladder, rung 1)
- ✅ `net-replay` — leaked static session token / replay attack (network ladder, rung 3)
- ✅ `forensics-pcap-basic` — plaintext capture (forensics ladder, rung 1)
- ✅ `forensics-pcap-ftp` — multi-stream capture analysis (forensics ladder, rung 3)
- ✅ `platform/common/pcap_writer.py` — dependency-free pcap-file builder shared by both PCAP challenges
- ✅ `web-idor-tokens` — predictable share-link tokens (hash of a public
  value, no secret) (Web ladder, rung 6)
- ⬜ Every category is building toward 10 rungs — see `main.md` for the
  full named, ported backlog (⬜ rows) for Web, Crypto, Binary/RE,
  Network, and Forensics
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
