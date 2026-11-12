# Challenge 6: forensics-log-analysis (Finding an Intrusion in Logs)

A fabricated SSH authentication log — the same plain-text format a
real `/var/log/auth.log` uses — from a production server's day.
Nothing is encrypted, obfuscated, or hidden in any special way. The
exercise is the most fundamental blue-team skill there is: scrolling
through logs and noticing the handful of lines that don't belong among
dozens that look completely normal.

## Running it

Standalone:

```bash
cd services/forensics-log-analysis
docker compose up --build
```

Or as part of the full platform:

```bash
# from the repo root
docker compose up --build forensics-log-analysis
```

Then open `http://localhost:9005/` and download `auth.log`.

## What's in the file

A day's worth of SSH login lines in standard syslog format:

```
Jun 14 08:23:41 prod-web-03 sshd[8003]: Accepted password for jsmith from 10.1.2.14 port 51234 ssh2
```

Most of the file is exactly this: a handful of employees logging in
successfully from their usual IPs, scattered through business hours.

## What you need to work out

1. **Look for `Failed password` lines.** A couple of these from a
   real user mistyping their password now and then would be normal.
   What does it look like when there are dozens of them, for the same
   account, from the same IP, seconds apart?

2. **Follow that IP's activity forward in the log.** A brute-force
   attempt that never succeeds is noise. One that eventually does is
   an intrusion — look for an `Accepted password` line for the same
   account, from the same IP, right after the burst of failures ends.

3. **See what happens immediately after.** The very next log line
   after a successful login is often the most important one in the
   whole file — it's what the attacker actually *did* once inside.

## Tools you'll need

| Tool | Why |
|---|---|
| `grep` / `less` / a text editor | Scroll through the log, search for `Failed password` and `Accepted password` |
| A spreadsheet or a few lines of Python (optional) | Count failures per IP if you want to confirm the burst quantitatively rather than just by eye |

**Don't ask which IP is the attacker.** Counting `Failed password`
lines per source IP (`grep "Failed password" auth.log | awk '{print
$11}' | sort | uniq -c`, or just reading closely) finds it directly.
If you're stuck for more than 15 minutes, come back with what you've
found so far (e.g. "I see failures from IP X, but I'm not sure what
happened after").

## Defender role

This is a forensics/analysis exercise — there's no server-side bug to
patch (the "vulnerability" is a weak admin password that let a brute
force eventually succeed, not a flaw in how this page serves the
log). The relevant defensive takeaways:

- **Rate-limit or lock out authentication after repeated failures.**
  A real server would have blocked this IP (or at least massively
  slowed it down) long before 40 attempts succeeded — this is exactly
  the same class of problem `net-rate-limit-bypass` explores from the
  attacker's side.
- **Alert on the pattern, not just the outcome.** A SOC watching for
  "many failed logins for one account in a short window" would catch
  this attack *before* it succeeded, not after reading about it in a
  log days later.
- **Use something stronger than a brute-forceable password** for
  privileged accounts in the first place — SSH keys, or at minimum a
  password long and random enough that 40 attempts isn't anywhere
  close to enough.

## Flag rotation

As part of the full platform, the flag inside `/flag.txt` changes
every round via `flagd`, and a freshly generated log (with the flag
embedded in the post-compromise command line) is produced on every
download — the analysis technique stays exactly the same; only the
flag text rotates. Submit whatever you currently extract; stale ones
expire.

## Where this sits in the Digital Forensics ladder

`forensics-disk-image` (rung 5) → **`forensics-log-analysis`
(rung 6)** → `forensics-metadata` (rung 7). See `main.md` for the full
ladder.
