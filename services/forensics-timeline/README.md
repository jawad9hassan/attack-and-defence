# Challenge 8: forensics-timeline (Correlating Multiple Log Sources)

An incident-response bundle with three *independent* log files from
the same day: a firewall log, a web server access log, and an
account-management (auth) log. Each one only records what its own
system saw. None of them says "this event is part of the same
incident as that one in a different file" — that correlation is
entirely on you.

## Running it

Standalone:

```bash
cd services/forensics-timeline
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-timeline
```

Then open `http://localhost:9007/` and download `logs.zip`.

## Background

Real security incidents almost never show up complete in one log
file. A firewall sees connection attempts. A web server sees HTTP
requests. An identity system sees accounts being created or changed.
Analysts have to stitch these views together by hand (or with a
SIEM) using the only things all three logs share: **source IP** and
**time**. This challenge is a small, manageable version of exactly
that correlation work.

## What you need to work out

1. **Several IPs look "suspicious" across the three files** — a port
   scan here, a weird URL there, an account change somewhere else.
   Most of them are red herrings: an IP that scanned but never showed
   up again, a strange request with no scan before it, an account
   change with no web or firewall activity anywhere near it in time.
2. **Only one IP ties all three logs together**, in a sensible order:
   a port scan against the web host, then (shortly after) a request
   against the web application from that same IP, then (shortly
   after that) an account-management event that followed directly
   from it. Look for that specific chain, in that order, close
   together in time.
3. **The flag is inside the auth.log line at the end of that chain.**
   You'll know you found the right one because the timestamps and the
   source IP tie cleanly back through the web log and the firewall
   log before it.

## Tools you'll need

| Tool | Why |
|---|---|
| `grep` / `less` | Pull all lines for a given IP out of each file to compare |
| A spreadsheet, or a few lines of Python | Sort events from all three files by timestamp to see the true chronological order across sources |

**Don't ask which IP is the real one.** Grep each file for every IP
that appears more than once anywhere, then check which one shows up
in *all three* files within a tight time window, in the right order.
If you're stuck for more than 20 minutes, come back with the
candidate IPs you've found and which files each one appears in.

## Defender role

This is a forensics/analysis exercise — the "vulnerability" here is
a web endpoint that let an unauthenticated request create an admin
account, not a flaw in how this bundle is served. The relevant
defensive takeaways:

- **Centralize logging with a shared, correlatable identifier** (a
  request ID, a session ID) so an incident doesn't require manually
  cross-referencing timestamps across unrelated systems.
- **Require authentication for privileged account-management
  endpoints.** The account-creation request that appears in
  `web_access.log` here should never have succeeded without an
  authenticated, authorized session.
- **Alert on the pattern, end to end.** A detection rule that
  correlates "port scan, then access to a sensitive endpoint, then a
  privileged account change, all from the same source within
  minutes" would have caught this chain automatically instead of
  needing a human to notice it after the fact.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a freshly generated `logs.zip` (with the
current flag embedded in the real attack chain's `auth.log` line) is
produced on every download — the correlation technique stays exactly
the same; only the flag text rotates. Submit whatever you currently
extract; stale ones expire.

## Where this sits in the Digital Forensics ladder

`forensics-metadata` (rung 7) → **`forensics-timeline` (rung 8)** →
`forensics-malware-triage` (rung 9). See `main.md` for the full
ladder.
