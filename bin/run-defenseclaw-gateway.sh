#!/opt/homebrew/bin/bash
# DefenseClaw gateway supervisor for launchd.
#
# `defenseclaw-gateway start` daemonizes (forks to background and exits 0),
# which is incompatible with launchd's KeepAlive — launchd would either
# loop-restart it or lose track of it entirely. So this wrapper:
#
#   1. Stops any stale instance (clean slate after reboot or crash)
#   2. Starts the gateway with the tinyproxy egress env
#   3. Locates the daemonized PID and waits on it
#   4. Exits non-zero when the gateway dies, so launchd restarts us
#   5. On SIGTERM/SIGINT (reboot, launchctl bootout), stops the gateway cleanly
#
# Loaded via /Library/LaunchDaemons/com.aetherclaude.dc-gateway.plist.

set -euo pipefail

export HOME="/Users/aetherclaude"
export PATH="/Users/aetherclaude/.local/bin:/opt/homebrew/bin:/usr/bin:/bin"
export HTTPS_PROXY="http://127.0.0.1:8888"
export HTTP_PROXY="http://127.0.0.1:8888"
export NO_PROXY="localhost,127.0.0.1"

GATEWAY="/Users/aetherclaude/.local/bin/defenseclaw-gateway"
LOG="$HOME/logs/dc-gateway.log"
mkdir -p "$(dirname "$LOG")"

ts() { date "+%Y-%m-%dT%H:%M:%S"; }
log() { echo "$(ts) $1" >> "$LOG"; }

cleanup() {
    log "supervisor received shutdown; stopping gateway"
    "$GATEWAY" stop >/dev/null 2>&1 || true
    exit 0
}
trap cleanup TERM INT

log "supervisor starting"

"$GATEWAY" stop >/dev/null 2>&1 || true
sleep 1
"$GATEWAY" start >> "$LOG" 2>&1 || {
    log "gateway start failed"
    exit 1
}
sleep 2

# Locate the daemonized gateway PID. -x matches the process name exactly,
# so this won't pick up our wrapper or any other shell command containing
# the string "defenseclaw-gateway".
PID=$(pgrep -u "$(id -u)" -x defenseclaw-gateway | head -1 || true)

if [ -z "$PID" ]; then
    log "gateway PID not found 2s after start; exiting for launchd restart"
    exit 1
fi

log "gateway running as PID $PID; supervising"

# Wait on the PID. kill -0 just checks existence (no signal sent).
while kill -0 "$PID" 2>/dev/null; do
    sleep 30
done

log "gateway PID $PID exited; signaling launchd restart"
exit 1
