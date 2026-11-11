# Running a training session

This is the operational side: how to actually run a session with your
team, not just the code.

## Before the session

1. `cp .env.example .env` and pick real secrets (anything — this is a
   private training environment, not a public competition).
2. `docker compose up --build -d` from the repo root.
3. Open the scoreboard at `http://localhost:8080` and confirm rounds are
   ticking (the round number in the top-left should increase roughly every
   `round_time_seconds`, from `config/game.yml`).
4. Everyone picks a `submitter` name (just something typed into the
   `/api/submit` request — see each service's README for exact exploit +
   submission steps) and sticks with it, so the leaderboard tracks
   individuals consistently across the session.

## Suggested round/session timing

- **Short practice session (1-2 hours):** `round_time_seconds: 60-90`,
  `flag_lifetime_rounds: 5` — flags live for 5-7 minutes, long enough to
  find and exploit a new vulnerability, short enough that sitting on a
  captured flag instead of submitting costs you.
- **Longer session mimicking a real competition day:** `round_time_seconds:
  120`, `flag_lifetime_rounds: 3` — closer to how FAUST CTF / GCC-style
  games are actually paced.

Change these in `config/game.yml` and restart the `checker` container
(`docker compose restart checker`) to apply.

## Roles during a session

Assign roles explicitly rather than letting everyone attack everything at
once — it mirrors how real team roles work and avoids five people staring
at the same service:

- **Attacker(s):** find and exploit vulnerabilities, submit flags.
- **Defender(s):** read the vulnerable source, write and deploy patches
  (`docker compose up --build <service>` after editing), and watch the
  scoreboard's SLA column to confirm the patch didn't break anything.
- **Rotate roles** every 30-45 minutes so everyone practices both sides —
  this is exactly what the real competition requires simultaneously.

## What "winning" looks like here

The leaderboard combines:

- `defense:<service>` pseudo-submitters — points for keeping each service
  up and passing its SLA check.
- Real submitter names — points for captured flags.

There's no single "team score" by design (see `docs/ARCHITECTURE.md`'s
section on scaling to multi-team play for how to add one back). For now,
the honest framing is: the group's **combined** score across both columns
is what to compare session-over-session as you improve.

## After the session

- Write up what you found in `docs/writeups/` (create it — it's gitignored
  for `*.db` but `.md` writeups should be committed).
- If you patched a service, commit the patch — future sessions should
  start from the fixed version, with a *new* intentional bug if you want
  to practice the same service again.
- Check `docker compose logs checker` if any SLA checks failed
  unexpectedly — it's often a real bug in the checker module itself (see
  the commit history for an example of exactly that happening and getting
  fixed).
