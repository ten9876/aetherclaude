#!/opt/homebrew/bin/bash
# promote-operating-notes.sh — the human ratification gate for the
# Signals -> agent feedback loop.
#
# The dashboard distills warning/error Galileo Signals into a PROPOSED operating-
# notes file. Nothing reaches the live agent until a human promotes it here: this
# copies the proposed file to the ACTIVE file that run-agent.sh injects into every
# Claude run via --append-system-prompt. Keeps the "human is the final authority"
# posture — the loop surfaces and stages coaching; a person ratifies what the
# agent actually sees.
#
# Usage:
#   promote-operating-notes.sh              # show diff, prompt, then promote
#   promote-operating-notes.sh --yes        # promote without prompting
#   promote-operating-notes.sh --show       # print proposed vs active, do nothing
#   promote-operating-notes.sh --clear      # remove the active file (agent stops
#                                             seeing any notes)
set -euo pipefail

STATE_DIR="/Users/aetherclaude/state"
PROPOSED="$STATE_DIR/operating-notes.proposed.md"
ACTIVE="$STATE_DIR/operating-notes.md"

show() {
    echo "=== PROPOSED ($PROPOSED) ==="
    [ -s "$PROPOSED" ] && cat "$PROPOSED" || echo "(none staged)"
    echo
    echo "=== ACTIVE ($ACTIVE — injected into the agent) ==="
    [ -s "$ACTIVE" ] && cat "$ACTIVE" || echo "(none active — loop is inert)"
}

case "${1:-}" in
    --show)
        show; exit 0 ;;
    --clear)
        rm -f "$ACTIVE"
        echo "Cleared active operating notes — the agent will inject none on its next run."
        exit 0 ;;
esac

if [ ! -s "$PROPOSED" ]; then
    echo "No proposed operating notes staged ($PROPOSED is empty/absent)."
    echo "The dashboard writes it from Galileo Signals; nothing to promote yet."
    exit 0
fi

if [ -f "$ACTIVE" ] && diff -q "$PROPOSED" "$ACTIVE" >/dev/null 2>&1; then
    echo "Active notes already match the proposal — nothing to do."
    exit 0
fi

echo "--- diff: ACTIVE (current) -> PROPOSED (new) ---"
diff "${ACTIVE:-/dev/null}" "$PROPOSED" 2>/dev/null || true
echo "-----------------------------------------------"

if [ "${1:-}" != "--yes" ]; then
    read -r -p "Promote these notes into the live agent? [y/N] " ans
    case "$ans" in y|Y|yes|YES) ;; *) echo "Aborted — active notes unchanged."; exit 0 ;; esac
fi

tmp="$ACTIVE.tmp.$$"
cp "$PROPOSED" "$tmp"
mv "$tmp" "$ACTIVE"
echo "Promoted. run-agent.sh will inject $(grep -c '^- ' "$ACTIVE" 2>/dev/null || echo 0) note(s) into the agent on its next run."
