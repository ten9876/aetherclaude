#!/opt/homebrew/bin/bash
# AetherClaude deploy script — run on the Mac Mini as the jeremy user (with sudo)
#
# Pulls the latest changes, syncs scripts into /Users/aetherclaude/bin via symlinks,
# and restarts affected launchd services.
#
# Usage: ./scripts/deploy.sh [--no-restart]

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_TARGET="/Users/aetherclaude/bin"
SKILLS_TARGET="/Users/aetherclaude/skills"
RESTART=true

for arg in "$@"; do
    case "$arg" in
        --no-restart) RESTART=false ;;
    esac
done

echo "==> Pulling latest from origin/main"
git -C "$REPO_DIR" pull --ff-only

echo "==> Syncing scripts into $BIN_TARGET (via symlinks)"
for f in "$REPO_DIR"/bin/*; do
    name=$(basename "$f")
    target="$BIN_TARGET/$name"
    if [ -L "$target" ] || [ ! -e "$target" ] || ! diff -q "$f" "$target" >/dev/null 2>&1; then
        sudo -u aetherclaude ln -sfn "$f" "$target"
        echo "   linked $name"
    fi
done

echo "==> Syncing skills into $SKILLS_TARGET"
for f in "$REPO_DIR"/skills/*.md; do
    name=$(basename "$f")
    sudo -u aetherclaude ln -sfn "$f" "$SKILLS_TARGET/$name"
done

echo "==> Syncing pf anchor"
if ! sudo diff -q "$REPO_DIR/config/pf/com.aetherclaude" /etc/pf.anchors/com.aetherclaude >/dev/null 2>&1; then
    sudo cp "$REPO_DIR/config/pf/com.aetherclaude" /etc/pf.anchors/com.aetherclaude
    sudo pfctl -a com.aetherclaude -f /etc/pf.anchors/com.aetherclaude 2>&1 | grep -v "could result\|No ALTQ\|ALTQ related" || true
    echo "   pf reloaded"
fi

echo "==> Syncing cloudflared config"
if ! sudo diff -q "$REPO_DIR/config/cloudflared/config.yml" /Users/aetherclaude/.cloudflared/config.yml >/dev/null 2>&1; then
    sudo cp "$REPO_DIR/config/cloudflared/config.yml" /Users/aetherclaude/.cloudflared/config.yml
    sudo chown aetherclaude:staff /Users/aetherclaude/.cloudflared/config.yml
    [ "$RESTART" = true ] && sudo launchctl kickstart -k system/com.aetherclaude.cloudflared
fi

echo "==> Syncing launchd plists"
for f in "$REPO_DIR"/config/launchd/*.plist; do
    name=$(basename "$f")
    target="/Library/LaunchDaemons/$name"
    if ! sudo diff -q "$f" "$target" >/dev/null 2>&1; then
        sudo cp "$f" "$target"
        sudo chown root:wheel "$target"
        sudo chmod 644 "$target"
        if [ "$RESTART" = true ]; then
            label="${name%.plist}"
            sudo launchctl bootout "system/$label" 2>/dev/null || true
            sudo launchctl bootstrap system "$target"
            echo "   reloaded $label"
        fi
    fi
done

if [ "$RESTART" = true ]; then
    echo "==> Kicking dashboard + agent to pick up script changes"
    sudo launchctl kickstart -k system/com.aetherclaude.dashboard 2>/dev/null || true
    sudo launchctl kickstart -k system/com.aetherclaude.agent 2>/dev/null || true
fi

echo "==> Done"
