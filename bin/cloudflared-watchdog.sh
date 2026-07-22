#!/opt/homebrew/bin/bash
# Watchdog for com.aetherclaude.cloudflared.
#
# Invoked every 5 minutes by com.aetherclaude.cloudflared-watchdog. Probes
# the public tunnel URL from outside the box, kickstarts cloudflared when
# it 530s twice in a row.
#
# Why probe from outside rather than just checking `pgrep cloudflared`:
# the failure mode we hit on 2026-07-22 was cloudflared apparently
# stuck — a process-liveness check would have said "fine" while the
# public URL was down for hours. Probing what Cloudflare's edge sees
# catches the real symptom.
#
# The two-consecutive gate rides through the ~15s Starlink drops noted
# in PR #39. Individual 5-min checks landing inside a 15s drop happen
# ~5% of the time; two independent 5-min-apart checks both hitting a
# drop is ~0.25% — noise floor for false positives, but a genuinely-
# dead daemon stays 530 across every check.

set -euo pipefail

URL="https://dashboard.aethersdr.com/"
LABEL="system/com.aetherclaude.cloudflared"
STATE_DIR="/Users/aetherclaude/logs"
STATE_FILE="${STATE_DIR}/.cloudflared-watchdog-consecutive-530"
LOG_FILE="${STATE_DIR}/cloudflared-watchdog.log"

mkdir -p "$STATE_DIR"

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '%s %s\n' "$(ts)" "$*" >> "$LOG_FILE"; }

# `|| echo 000` handles curl exit≠0 (DNS/network failure) — treat those
# the same as a 530 for gating purposes, since both mean "public URL is
# not returning OK."
code=$(curl -sS -o /dev/null -m 15 -w '%{http_code}' "$URL" 2>/dev/null || echo "000")

prev=$(cat "$STATE_FILE" 2>/dev/null || echo 0)

case "$code" in
    530|000)
        consec=$((prev + 1))
        printf '%s' "$consec" > "$STATE_FILE"
        log "public URL code=${code} (${consec} consecutive bad)"
        if [ "$consec" -ge 2 ]; then
            log "kickstarting ${LABEL}"
            launchctl kickstart -k "$LABEL"
            printf '0' > "$STATE_FILE"
        fi
        ;;
    *)
        if [ "$prev" -gt 0 ]; then
            log "public URL back (code=${code}); clearing counter"
            printf '0' > "$STATE_FILE"
        fi
        ;;
esac
