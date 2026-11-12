#!/bin/bash
set -e

# Seed an initial flag so the service has something valid to show before
# the checker's first round writes a fresh one.
: "${FLAG_PATH:=/flag.txt}"
: "${INITIAL_FLAG:=FLAG{waiting_for_first_round}}"
if [ ! -f "$FLAG_PATH" ]; then
    echo "$INITIAL_FLAG" > "$FLAG_PATH"
fi

# flagd is internal-only: it listens on FLAGD_PORT but that port is never
# published in docker-compose, so only containers on this service's
# Docker network (i.e. the checker) can reach it.
python3 /opt/flagd.py &

exec python3 app.py
