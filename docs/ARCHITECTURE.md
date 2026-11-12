# Architecture

## Overview

```
                         ┌─────────────────────────┐
                         │        checker          │
                         │   (round loop, every     │
                         │    round_time_seconds)   │
                         └───────────┬─────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
        ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐
        │   web-notes     │  │   pwn-baby      │  │   scoreboard     │
        │  (public:5001)  │  │  (public:7001)  │  │  (public:8080)   │
        │  flagd:10000    │  │  flagd:10000    │  │                  │
        │  (internal only)│  │  (internal only)│  │  flags, rounds,  │
        └────────────────┘  └────────────────┘  │  leaderboard DB  │
                 ▲                   ▲           └─────────────────┘
                 │                   │                     ▲
                 └─────────┬─────────┘                     │
                           │                                │
                      players / attackers ───── POST /api/submit
```

Every round, the checker:

1. Calls each service's `sla_check()` — the service's *normal*, non-exploit
   behavior (e.g. logging in as a seeded guest user). This is what catches
   a bad defense patch: if a team "fixes" a vulnerability by breaking the
   service outright, this fails and they lose defense points, exactly like
   a real attack-defense competition.
2. Generates a fresh flag and pushes it into the service via **flagd**, a
   tiny internal-only admin daemon baked into every service's image. flagd
   is never published on a host port — only containers on the same Docker
   network (i.e. the checker) can reach it. This is what lets flags rotate
   every round without rebuilding or restarting anything.
3. Registers the new flag with the scoreboard, tagged with the round it was
   planted in and the round it expires in (`flag_lifetime_rounds` later).

Players attack a service through its real, public port — using the actual
vulnerability, not some shortcut — steal the current flag, and `POST` it to
the scoreboard's `/api/submit`. The scoreboard checks the flag exists, has
not expired, and has not already been captured, then awards points.

## Why this design

- **Realistic enough to matter, simple enough to actually finish.** A full
  gameserver (team registration, VPN routing, per-team vulnbox clones,
  tick-based infrastructure) is what competitions like FAUST CTF or GCC
  run — but building and debugging one is itself a multi-week project.
  This repo keeps the *mechanics* that actually teach the skill (rotating
  flags, a live SLA/attack scoreboard, a checker you can break by patching
  wrong) while staying buildable and debuggable by a small team in days,
  not weeks.
- **One shared instance, individual competition.** Rather than modeling
  multiple isolated teams (which needs per-team networking you don't have
  reason to set up for five training partners), everyone attacks the same
  running services and competes by submitter name on one leaderboard. The
  attack/defense *mechanics* — rotating flags, expiry, SLA scoring — are
  identical to the multi-team case; only the team-isolation layer is
  skipped. See "Scaling to real multi-team play" below for how to add it
  back.
- **flagd instead of rebuilding images.** Early versions of this kind of
  training setup often just bake the flag into the image at build time —
  but then "a new round" means rebuilding and restarting every service,
  which is slow and doesn't match how real checkers work. flagd is the
  smallest thing that could plausibly work: one TCP port, one shared
  secret, two commands (`SET` / `GET`).

## Flag format and lifecycle

Flags look like `FLAG{<32 hex characters>}`, generated with
`secrets.token_hex(16)` (cryptographically random, not guessable).

A flag placed in round `N` expires at round `N + flag_lifetime_rounds`
(configured in `config/game.yml`). Submitting it after that round returns
`410 flag expired`. This mirrors real attack-defense games, where sitting
on a captured flag instead of submitting it immediately is a losing
strategy.

## Scoring

- **Defense:** `defense_points_per_round` (default 1) per service per round
  it passes its SLA check. Tracked on the leaderboard under a
  `defense:<service>` pseudo-submitter, so you can see at a glance how much
  of the total score came from keeping services up versus stealing flags.
- **Attack:** `attack_points_per_flag` (default 10) to whoever submits a
  valid, unexpired, not-yet-captured flag first.

## Scaling to real multi-team play

The current config (`config/game.yml`) has one implicit "team": the shared
instance everyone attacks. To grow this into genuine team-vs-team play
later:

1. Run one copy of each service **per team** (e.g. `web-notes-team1`,
   `web-notes-team2`, ...), each on its own Docker network or VLAN so teams
   can't directly inspect each other's containers.
2. Extend `config/game.yml`'s `services` list with a `teams` dimension (or
   loop the compose file through a template), so the checker plants a
   different flag per `(service, team)` pair each round.
3. Extend the scoreboard's `flags` table with a `team` column, and
   `/api/submit` to require the submitting team's own identity, so a team
   can only earn points by capturing flags from *other* teams' instances
   (not their own).
4. Add network isolation so attackers can only reach other teams' public
   service ports, not the checker's internal flagd channel.

None of this changes `platform/checker`'s or `platform/scoreboard`'s core
logic — it's additive scope, not a rewrite.
