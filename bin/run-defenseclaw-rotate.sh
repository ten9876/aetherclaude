#!/opt/homebrew/bin/bash
# Weekly rotation of DEFENSECLAW_GATEWAY_TOKEN (and the dashboard webhook
# bearer that DefenseClaw uses to authenticate to /defenseclaw-webhook).
#
# Why we don't use `defenseclaw setup rotate-token`: that command lives
# in the Python CLI which hasn't been published with 0.3.x release
# artifacts yet. So we do the equivalent manually: replace the token
# value in ~/.defenseclaw/.env (atomic 0o600 write) and restart the
# gateway sidecar, which is what the official command would do.
#
# Triggered by /Library/LaunchDaemons/com.aetherclaude.dc-rotate.plist
# weekly (Sunday 04:00). Manual invocation:
#   sudo -u aetherclaude /Users/Shared/aetherclaude/bin/run-defenseclaw-rotate.sh

set -euo pipefail

export PATH="/Users/aetherclaude/bin:/Users/aetherclaude/.local/bin:/opt/homebrew/bin:/usr/bin:/bin"
export HOME="/Users/aetherclaude"

ENV_FILE="$HOME/.defenseclaw/.env"
DASH_ENV_FILE="$HOME/.env"
LOG="$HOME/logs/orchestrator.log"

mkdir -p "$(dirname "$LOG")"
ts() { date "+%Y-%m-%dT%H:%M:%S"; }
log() { echo "$(ts) $1" >> "$LOG"; }

# 1. Generate new tokens
NEW_GATEWAY_TOKEN=$(openssl rand -hex 32)
NEW_DASH_BEARER=$(openssl rand -hex 16)

# 2. Update DefenseClaw's .env (gateway token + matching webhook bearer)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
    grep -vE '^DEFENSECLAW_GATEWAY_TOKEN=|^DEFENSECLAW_DASHBOARD_BEARER=' "$ENV_FILE" 2>/dev/null || true
    echo "DEFENSECLAW_GATEWAY_TOKEN=$NEW_GATEWAY_TOKEN"
    echo "DEFENSECLAW_DASHBOARD_BEARER=$NEW_DASH_BEARER"
} > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT

# 3. Update the dashboard's .env so /defenseclaw-webhook validates against
#    the new bearer too (otherwise auth fails until next dashboard reload).
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
    grep -vE '^DEFENSECLAW_DASHBOARD_BEARER=' "$DASH_ENV_FILE" 2>/dev/null || true
    echo "DEFENSECLAW_DASHBOARD_BEARER=$NEW_DASH_BEARER"
} > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$DASH_ENV_FILE"
trap - EXIT

# 4. Restart gateway via launchd so the new token takes effect.
# launchd runs the gateway in the foreground under com.aetherclaude.dc-gateway
# (KeepAlive); kickstart -k restarts it through launchd. Without a sudoers
# entry for that, stop the foreground gateway process (this user owns it) and
# KeepAlive respawns it, reading the new token from .env at startup. The match
# is the bare binary path, so `defenseclaw-gateway tui` sessions are left alone.
if ! /usr/bin/sudo -n /bin/launchctl kickstart -k system/com.aetherclaude.dc-gateway >/dev/null 2>&1; then
    /usr/bin/pkill -TERM -u "$(id -u)" -f '^/Users/aetherclaude/.local/bin/defenseclaw-gateway$' || true
    log "Token rotation: dc-gateway kickstart not permitted; stopped gateway for launchd restart"
fi
sleep 3

# 5. Reload dashboard so the new bearer is read from .env at startup.
# `launchctl kickstart -k system/...` requires root; a tight sudoers entry
# at /etc/sudoers.d/aetherclaude-dc-rotate grants the dashboard kickstart
# (and, where present, the dc-gateway one used in step 4).
/usr/bin/sudo -n /bin/launchctl kickstart -k system/com.aetherclaude.dashboard >/dev/null 2>&1 || true

# 6. Log a single line the dashboard tailer will catch
TOKEN_PREFIX="${NEW_GATEWAY_TOKEN:0:8}"
log "Token Rotated: gateway prefix=${TOKEN_PREFIX}…"
