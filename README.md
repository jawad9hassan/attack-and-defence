# Attack & Defence — a self-hosted A/D-CTF training range

A small, scalable attack-defense CTF simulation, built for a five-person
team training for a real A/D competition. One command brings up:

- **Vulnerable services** you attack and defend (currently two, designed
  to scale — see `docs/ADDING_A_SERVICE.md`)
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

Each service's own `README.md` explains its vulnerability class and gives
you a path to discover the exploit yourself, without handing you the exact
payload.

## Services

| Folder | Category | Difficulty | What you're doing |
|---|---|---|---|
| `services/web-notes` | Web / SQL Injection | Beginner | Bypass a login form's SQL query |
| `services/pwn-baby`  | Binary / Stack Overflow | Intermediate | Hijack control flow with a ret2win |

More services are planned (see the changelog below) and the platform is
built to make adding one straightforward — see `docs/ADDING_A_SERVICE.md`.

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
- ⬜ A web service with a logic-based auth bypass (not SQLi)
- ⬜ A custom network-protocol service (`nc`-style)
- ⬜ Real multi-team isolation (see `docs/ARCHITECTURE.md`'s scaling section)

## A note on how this was built

Every piece in this repo was written, tested, and verified working before
being committed — including a real bug found and fixed along the way (a
checker module that occasionally misread a service's response; see the
commit that fixes it for what happened and why). `git log` is a genuine,
readable build history, not a single dump.
