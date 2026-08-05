#!/usr/bin/env bash
# One overwatch tick, as launchd runs it.
#
# Exits non-zero only when the TICK ITSELF failed — not when the subject is
# slipping. Those are different facts, and collapsing them makes `launchctl
# list` show a broken watcher when the watcher is working perfectly and the
# thing it watches is not.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1

mkdir -p logs state

STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if ! OUT="$(python3 overwatch.py tick 2>&1)"; then
    printf '%s tick FAILED\n%s\n' "$STAMP" "$OUT" >> logs/tick.log
    exit 1
fi

STATUS="$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' 2>/dev/null || echo unknown)"
printf '%s tick ok status=%s\n' "$STAMP" "$STATUS" >> logs/tick.log
exit 0
