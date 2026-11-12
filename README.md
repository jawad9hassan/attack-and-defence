# Attack & Defence — a self-hosted A/D-CTF training range

A small, scalable attack-defense CTF simulation, built for a five-person
team training for a real A/D competition. One command brings up:

- **Vulnerable services** you attack and defend (currently six, covering
  web, binary, crypto, and network-protocol bug classes, designed to keep
  scaling — see `docs/ADDING_A_SERVICE.md`)
- **A checker** that runs real, round-based game operations: it verifies
  each service's normal functionality, rotates its flag every round, and
  expires old flags — the same mechanics a real attack-defense gameserver
  uses
- **A live scoreboard** (auto-refreshing) with defense (uptime) scores and
  an attacker leaderboard

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
- **web-notes** (service 1): `http://localhost:5000`
- **pwn-baby** (service 2): `nc localhost 9999`
- **web-idor** (service 3): `http://localhost:5001`
- **crypto-xor** (service 4): `nc localhost 9000`
- **net-proto** (service 5): `nc localhost 9200`
- **pwn-format** (service 6): `nc localhost 9998`

Each service's own `README.md` explains its vulnerability class and gives
you a path to discover the exploit yourself, without handing you the exact
payload.

## Services

| Folder | Category | Difficulty | What you're doing |
|---|---|---|---|
| `services/web-notes` | Web / SQL Injection | Beginner | Bypass a login form's SQL query |
| `services/pwn-baby`  | Binary / Stack Overflow | Intermediate | Hijack control flow with a ret2win |
| `services/web-idor`  | Web / Broken Access Control (IDOR) | Beginner | Read another user's data by changing an ID |
| `services/crypto-xor` | Crypto / Key Reuse | Beginner-Intermediate | Break a reused XOR key with a chosen-plaintext attack |
| `services/net-proto`  | Network / Command Injection | Beginner-Intermediate | Bypass an incomplete blacklist to inject shell commands |
| `services/pwn-format`  | Binary / Format String | Intermediate-Advanced | Arbitrary memory write via `printf()`'s own directives |

More than one service of the same general category exists on purpose
(e.g. two web bugs, two binary bugs) — a real competition rarely has
just one of anything, and the plan is to keep adding more of each kind
over time, not stop at one. See the changelog below for what's next,
and `docs/ADDING_A_SERVICE.md` for how straightforward adding another
one is meant to be.

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
├── docker-compose.yml        ← brings up everything together
├── config/game.yml           ← round timing, flag lifetime, service registry
├── services/
│   ├── web-notes/             (SQL Injection)
│   ├── pwn-baby/               (Stack Overflow / ret2win)
│   ├── web-idor/               (Broken Access Control / IDOR)
│   ├── crypto-xor/             (XOR key-reuse / chosen-plaintext)
│   ├── net-proto/              (Command Injection)
│   ├── pwn-format/             (Format String)
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
- ⬜ A second web service with a logic-based auth bypass (not SQLi, not IDOR)
- ⬜ A heap-based binary exploitation service (use-after-free / heap overflow)
- ⬜ A second, harder crypto service (e.g. weak RSA parameters)
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
