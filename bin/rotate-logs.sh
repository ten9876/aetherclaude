#!/opt/homebrew/bin/bash
# Rotate the AetherClaude service logs.
#
# Why this exists: several plists claimed rotation was handled by macOS's
# newsyslog ("default config rotates large logs"). That was never true —
# newsyslog only touches files with an explicit /etc/newsyslog.d entry, and
# we never shipped one. Left unrotated since deploy, tinyproxy-access.log
# reached 2.0 GB and the logs tree 2.3 GB on a volume at 81% capacity.
#
# Why copy-truncate rather than rename-and-recreate:
#
#   1. Every big log is held open by a long-lived writer — launchd owns the
#      fd for any StandardOutPath/StandardErrorPath, tinyproxy owns its own
#      LogFile. Renaming the file leaves the writer appending to the
#      now-unlinked inode: the "rotated" file keeps growing invisibly and
#      the fresh file stays empty until the service restarts. Truncating in
#      place keeps the inode, so the writer never notices.
#
#   2. Ownership is heterogeneous and mostly not root — tinyproxy-access.log
#      is nobody:nobody, orchestrator.log is aetherclaude:staff,
#      pf-blocked.log is root:wheel. Recreating each file would mean
#      reproducing owner and mode per path; truncation preserves both for
#      free.
#
# The copy-truncate tradeoff is a small race: lines written between the cp
# and the truncate are lost. For append-only diagnostic logs that is a fair
# trade against unbounded growth, and it is what logrotate's copytruncate
# does for exactly these cases.
#
# Usage:
#   sudo /Users/Shared/aetherclaude/bin/rotate-logs.sh [--threshold MB] [--keep N] [--dry-run]

set -euo pipefail

LOG_DIRS=(
    /Users/aetherclaude/logs
    /Users/Shared/aetherclaude/logs
)

THRESHOLD_MB=50
KEEP=5
DRY_RUN=false

while [ $# -gt 0 ]; do
    case "$1" in
        --threshold) THRESHOLD_MB="$2"; shift 2 ;;
        --keep)      KEEP="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

THRESHOLD_BYTES=$((THRESHOLD_MB * 1024 * 1024))

log() { echo "[$(date "+%Y-%m-%dT%H:%M:%S")] $*"; }

# Never rotate our own output — we hold that fd ourselves and truncating it
# mid-run would confuse the very record of what we did.
SELF_LOG="/Users/Shared/aetherclaude/logs/logrotate.log"

reclaimed=0
rotated=0

for dir in "${LOG_DIRS[@]}"; do
    [ -d "$dir" ] || continue

    for f in "$dir"/*.log "$dir"/*.err; do
        # The globs above stay literal when a directory has no match.
        [ -f "$f" ] || continue
        [ -L "$f" ] && continue
        [ "$f" = "$SELF_LOG" ] && continue

        size=$(stat -f %z "$f" 2>/dev/null || echo 0)
        [ "$size" -ge "$THRESHOLD_BYTES" ] || continue

        human=$(echo "$size" | awk '{printf "%.1fM", $1/1048576}')
        if [ "$DRY_RUN" = true ]; then
            log "would rotate $f ($human)"
            rotated=$((rotated + 1))
            continue
        fi

        # Shift the existing generations down: .1.gz -> .2.gz, ...
        # Walk highest-first so we never overwrite a generation we still need.
        i="$KEEP"
        while [ "$i" -gt 1 ]; do
            prev=$((i - 1))
            [ -f "${f}.${prev}.gz" ] && mv -f "${f}.${prev}.gz" "${f}.${i}.gz"
            i="$prev"
        done

        # Copy, then truncate in place (see header for why not mv).
        cp "$f" "${f}.1"
        : > "$f"
        gzip -f "${f}.1"

        log "rotated $f ($human) -> $(basename "${f}").1.gz"
        reclaimed=$((reclaimed + size))
        rotated=$((rotated + 1))

        # Drop anything beyond the retention window.
        for old in "${f}".*.gz; do
            [ -f "$old" ] || continue
            gen=$(basename "$old" | sed -E 's/.*\.([0-9]+)\.gz$/\1/')
            [[ "$gen" =~ ^[0-9]+$ ]] || continue
            if [ "$gen" -gt "$KEEP" ]; then
                rm -f "$old"
                log "  pruned $(basename "$old")"
            fi
        done
    done
done

if [ "$DRY_RUN" = true ]; then
    log "dry run: $rotated file(s) would rotate (threshold ${THRESHOLD_MB}M)"
else
    log "rotated $rotated file(s), reclaimed $(echo "$reclaimed" | awk '{printf "%.2f GB", $1/1073741824}')"
fi
