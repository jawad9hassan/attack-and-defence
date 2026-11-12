#!/bin/bash
set -e

: "${FLAG_PATH:=/flag.txt}"
: "${INITIAL_FLAG:=FLAG{waiting_for_first_round}}"
if [ ! -f "$FLAG_PATH" ]; then
    echo "$INITIAL_FLAG" > "$FLAG_PATH"
fi

python3 /opt/flagd.py &

exec python3 /service/bank.py
