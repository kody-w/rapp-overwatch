#!/usr/bin/env bash
# Install the overwatch launchd job for the current user.
#
#   bash install-launchd.sh          # install and start
#   bash install-launchd.sh --remove # unload and delete
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="com.rapp.overwatch"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

if [[ "${1:-}" == "--remove" ]]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "removed $LABEL"
    exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" "$DIR/logs"
sed -e "s|__DIR__|$DIR|g" -e "s|__HOME__|$HOME|g" \
    "$DIR/$LABEL.plist.template" > "$PLIST"
chmod +x "$DIR/run.sh"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo "loaded $LABEL (every 30 min)"
echo "  status: launchctl list | grep $LABEL"
echo "  logs:   $DIR/logs/tick.log"
