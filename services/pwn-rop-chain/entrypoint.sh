#!/bin/bash
set -e

# Runs entirely as the unprivileged `player` user (set in Dockerfile).
# /flag.txt already exists and is owned by this user, so flagd can
# overwrite it each round without needing root.

python3 /opt/flagd.py &

exec socat -T30 TCP-LISTEN:9989,reuseaddr,fork EXEC:/service/vuln,pty,stderr
