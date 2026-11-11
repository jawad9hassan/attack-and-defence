#!/usr/bin/env python3
"""
Checker engine — the round loop.

Every ROUND_TIME_SECONDS, for each configured service:
  1. run its sla_check() (normal, non-exploit functionality)
  2. report the result to the scoreboard (feeds defense points)
  3. generate a fresh flag and push it in via flagd (put_flag)
  4. register the new flag with the scoreboard, with an expiry round
     (flag_lifetime_rounds later), so stale captures stop being valid —
     same as in a real attack-defense game.

This is intentionally a single, simple process: no distributed queue,
no multi-team fan-out yet. See docs/ARCHITECTURE.md for how this is
meant to grow.
"""
import importlib
import os
import secrets
import sys
import time

import requests
import yaml

CONFIG_PATH = os.environ.get("GAME_CONFIG", "/config/game.yml")
SCOREBOARD_URL = os.environ.get("SCOREBOARD_URL", "http://scoreboard:8080")
CHECKER_SECRET = os.environ.get("CHECKER_SECRET")
FLAGD_SECRET = os.environ.get("FLAGD_SECRET")

if not CHECKER_SECRET:
    print("engine: CHECKER_SECRET is required", file=sys.stderr)
    sys.exit(1)
if not FLAGD_SECRET:
    print("engine: FLAGD_SECRET is required", file=sys.stderr)
    sys.exit(1)

HEADERS = {"X-Checker-Secret": CHECKER_SECRET}


def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def load_checker_modules(services):
    modules = {}
    for svc in services:
        modules[svc["name"]] = importlib.import_module(f"checkers.{svc['checker_module']}")
    return modules


def start_round():
    resp = requests.post(f"{SCOREBOARD_URL}/internal/round/start", headers=HEADERS, timeout=10)
    resp.raise_for_status()
    return resp.json()["round_id"]


def report_sla(round_id, service, ok, detail):
    requests.post(
        f"{SCOREBOARD_URL}/internal/sla",
        headers=HEADERS,
        json={
            "round_id": round_id,
            "service": service,
            "status": "up" if ok else "down",
            "detail": detail,
        },
        timeout=10,
    )


def register_flag(round_id, service, value, expires_round):
    requests.post(
        f"{SCOREBOARD_URL}/internal/flag",
        headers=HEADERS,
        json={
            "round_id": round_id,
            "service": service,
            "value": value,
            "expires_round": expires_round,
        },
        timeout=10,
    )


def generate_flag():
    return f"FLAG{{{secrets.token_hex(16)}}}"


def run_round(round_id, config, modules):
    lifetime = config["flag_lifetime_rounds"]

    for svc in config["services"]:
        name = svc["name"]
        host = svc["host"]
        module = modules[name]

        ok, detail = module.sla_check(host, svc["port"])
        report_sla(round_id, name, ok, detail)
        print(f"[round {round_id}] {name}: SLA {'UP' if ok else 'DOWN'} ({detail})")

        flag = generate_flag()
        placed = module.put_flag(host, svc["flagd_port"], FLAGD_SECRET, flag)
        if placed:
            register_flag(round_id, name, flag, round_id + lifetime)
            print(f"[round {round_id}] {name}: planted flag {flag}")
        else:
            print(f"[round {round_id}] {name}: FAILED to plant flag (flagd unreachable?)")


def main():
    config = load_config()
    modules = load_checker_modules(config["services"])
    round_time = config["round_time_seconds"]

    print(f"engine: starting, round_time={round_time}s, "
          f"services={[s['name'] for s in config['services']]}")

    while True:
        round_id = start_round()
        run_round(round_id, config, modules)
        time.sleep(round_time)


if __name__ == "__main__":
    main()
