#!/bin/bash
# setup.sh — one command for the team: pull the latest challenges from
# GitHub, stop whatever's currently running, and (re)build + start the
# whole platform.
#
# Usage:
#   ./setup.sh              pull latest, rebuild, run in the foreground
#   ./setup.sh --detached    same, but keep running in the background
#   ./setup.sh --reset       also wipe the scoreboard's saved data
#                            (flags/rounds/leaderboard) and start from
#                            round 0 -- use this right before the real
#                            competition-day run, not during practice
#   ./setup.sh --help        show this message

set -e
cd "$(dirname "$0")"

RESET=false
DETACHED=false
for arg in "$@"; do
    case "$arg" in
        --reset) RESET=true ;;
        --detached|-d) DETACHED=true ;;
        --help|-h)
            sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (try --help)"
            exit 1
            ;;
    esac
done

echo "==> Pulling the latest challenges from GitHub..."
git pull

echo "==> Stopping any currently running containers..."
if [ "$RESET" = true ]; then
    echo "    (--reset: also wiping the scoreboard's saved data)"
    docker compose down -v
else
    docker compose down
fi

echo "==> Building and starting everything (the first run after new"
echo "    challenges are added can take a few minutes)..."
if [ "$DETACHED" = true ]; then
    docker compose up --build -d
    echo ""
    echo "==> Done. Running in the background."
    echo "    Check status with: docker compose ps"
    echo "    Scoreboard:         http://localhost:8080"
    echo "    Challenge index:    main.md"
else
    docker compose up --build
fi
