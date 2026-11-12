#!/bin/bash
set -e

# Runs entirely as the unprivileged `player` user (set in Dockerfile).
# /flag.txt already exists and is owned by this user, so flagd can
# overwrite it each round without needing root.
#
# No socat here (see Dockerfile comment): ./server IS the TCP server --
# it binds, listens, accepts and fork()s internally on its own.

python3 /opt/flagd.py &

exec /service/server
