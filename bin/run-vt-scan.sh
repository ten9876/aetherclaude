#!/opt/homebrew/bin/bash
# Daily VirusTotal scan of the AetherClaude agent binaries.
#
# Hashes every file under SCAN_PATH and looks each hash up against
# VirusTotal's API. If any file is flagged, log a CRITICAL line that the
# dashboard tailer will surface as an alert.
#
# Triggered by /Library/LaunchDaemons/com.aetherclaude.vt-scan.plist
# (StartCalendarInterval, daily 06:00). Manual invocation:
#   sudo -u aetherclaude /Users/Shared/aetherclaude/bin/run-vt-scan.sh

set -euo pipefail

export PATH="/Users/aetherclaude/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export HOME="/Users/aetherclaude"

source /Users/aetherclaude/.env
export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8888}"
export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8888}"
# Disable the 10-file default cap so all binaries get checked. ~20 files
# per run × 1 daily run = 20 lookups/day — well under VT's 500/day free tier.
export MCP_SCANNER_VT_MAX_FILES=0

SCAN_PATH="/Users/Shared/aetherclaude/bin"
LOGDIR="/Users/aetherclaude/logs"
OUT="$LOGDIR/vt-scan-latest.json"
ERR="$LOGDIR/vt-scan-stderr.log"

mkdir -p "$LOGDIR"

# Run the VT subcommand. stderr captures the scanner's progress logs +
# any per-file warnings (rate-limit timeouts, API errors, etc.).
mcp-scanner virustotal "$SCAN_PATH" --format raw > "$OUT" 2> "$ERR" || true

ts=$(date "+%Y-%m-%dT%H:%M:%S")

if [ ! -s "$OUT" ]; then
    echo "$ts VT Scan: failed (no output produced; see $ERR)" >> "$LOGDIR/orchestrator.log"
    exit 1
fi

safe=$(jq '[.scan_results[]? | select(.is_safe==true)] | length' "$OUT" 2>/dev/null || echo 0)
unsafe=$(jq '[.scan_results[]? | select(.is_safe==false)] | length' "$OUT" 2>/dev/null || echo 0)

# Single-line summary picked up by the dashboard's tail_orchestrator_skills
# regex (a SKILL event per run, source=skill-dispatch, binary=skill:vt-scan).
echo "$ts VT Scan: $safe safe, $unsafe threats" >> "$LOGDIR/orchestrator.log"

if [ "$unsafe" -gt 0 ]; then
    echo "$ts CRITICAL: VT found $unsafe threats — see $OUT" >> "$LOGDIR/orchestrator.log"
fi
