#!/bin/bash
set -e

# Runs entirely as the unprivileged `player` user (set in Dockerfile).
# /flag.txt already exists and is owned by this user, so flagd can
# overwrite it each round without needing root.

python3 /opt/flagd.py &

# Players connect to the PACKED stub, never the plain `inner` binary
# directly -- that's the whole point of the challenge.
exec socat -T30 TCP-LISTEN:9994,reuseaddr,fork EXEC:/service/vault_packed,pty,stderr
