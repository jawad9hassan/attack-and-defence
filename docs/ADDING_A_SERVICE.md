# Adding a new service

This is the actual contract the platform needs from every service. Follow
it and the checker, scoreboard, and live scoreboard page all pick up the
new service automatically — no changes needed outside what's listed here.

A ready-to-copy skeleton for every file below lives in `services/_template/`.

## 1. Write the vulnerable service itself

Put it in `services/<name>/`. It needs:

- Some vulnerability a player can exploit over the network to read the
  current flag (that's the whole point).
- A way to read the "live" flag fresh on every request/connection, not
  once at startup — either from a file (what both existing services do)
  or any other mechanism flagd can update (see next step).
- Ideally, some **normal, non-exploit functionality** the checker can
  exercise for its SLA check (a legitimate login, a benign echo, a health
  endpoint — anything that proves the service works without using the bug).

## 2. Wire up flagd

Copy `platform/common/flagd.py` into the image (see any existing
Dockerfile for the `COPY` line) and run it alongside the main service via
an `entrypoint.sh`:

```bash
#!/bin/bash
set -e
python3 /opt/flagd.py &
exec <your service's real start command>
```

flagd needs `FLAGD_SECRET` (shared with the checker, never baked into the
image — passed via environment at deploy time) and writes to whatever file
`FLAG_PATH` points at (default `/flag.txt`). Your service must read the
**same file** to serve the current flag.

**Never publish flagd's port in docker-compose.** It must only be
reachable from the checker, on the internal Docker network.

## 3. Write a checker module

Create `platform/checker/checkers/<name>_checker.py` implementing exactly
two functions:

```python
def sla_check(host, port):
    """Exercise NORMAL functionality only. Return (ok: bool, detail: str)."""
    ...

def put_flag(host, flagd_port, flagd_secret, flag):
    """Push `flag` into the service via flagd. Return True on success."""
    ...
```

`put_flag` is almost always identical across services (just a flagd `SET`
— see `services/_template/checker_template.py` for the exact snippet to
copy). `sla_check` is the one piece that's genuinely specific to each
service.

**Important:** `sla_check` must never rely on the vulnerability. If a team
patches the bug correctly, their SLA check still has to pass — that's how
a correct patch is distinguished from a broken service.

## 4. Register the service in `config/game.yml`

```yaml
services:
  - name: my-service
    host: my-service          # must match the docker-compose service name
    port: 1234                # the service's public port
    flagd_port: 10000
    checker_module: my_service_checker
```

## 5. Add it to `docker-compose.yml`

```yaml
  my-service:
    build:
      context: .
      dockerfile: services/my-service/Dockerfile
    ports:
      - "1234:1234"
    environment:
      - FLAGD_SECRET=${FLAGD_SECRET:-change-me-flagd-secret}
    restart: unless-stopped
```

Add it to the `checker` service's `depends_on` list too.

## 6. Test it before committing

1. Run the service standalone (its own `docker-compose.yml`, or as a plain
   process like this repo's development history did — see `git log` on
   `services/pwn-baby` and `services/web-notes` for exactly how).
2. Confirm the real exploit works and returns the flag.
3. Confirm `sla_check()` passes against the *unexploited* service.
4. Confirm `put_flag()` actually rotates the flag and the exploit then
   returns the new value.
5. Only then wire it into the root `docker-compose.yml` and the checker.

## 7. Write the service's own README

Same style as `services/web-notes/README.md` and `services/pwn-baby/README.md`:
explain the vulnerability class, give an attacker a path to discover it
*without* handing over the exact payload, and describe what a correct
defensive patch looks like.
