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
    current=$(readlink "$target" 2>/dev/null || true)
    if [ "$current" != "$f" ]; then
        sudo -u aetherclaude ln -sfn "$f" "$target"
        echo "   linked $name"
    fi
done

echo "==> Syncing skills into $SKILLS_TARGET (via symlinks)"
for f in "$REPO_DIR"/skills/*.md; do
    name=$(basename "$f")
    target="$SKILLS_TARGET/$name"
    current=$(readlink "$target" 2>/dev/null || true)
    if [ "$current" != "$f" ]; then
        sudo -u aetherclaude ln -sfn "$f" "$target"
        echo "   linked $name"
    fi
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

echo "==> Syncing tinyproxy config + allowlist"
tinyproxy_changed=false
if ! sudo diff -q "$REPO_DIR/config/tinyproxy/tinyproxy.conf" /opt/homebrew/etc/tinyproxy/tinyproxy.conf >/dev/null 2>&1; then
    sudo cp "$REPO_DIR/config/tinyproxy/tinyproxy.conf" /opt/homebrew/etc/tinyproxy/tinyproxy.conf
    tinyproxy_changed=true
fi
if ! sudo diff -q "$REPO_DIR/config/tinyproxy/allowlist" /opt/homebrew/etc/tinyproxy/allowlist >/dev/null 2>&1; then
    sudo cp "$REPO_DIR/config/tinyproxy/allowlist" /opt/homebrew/etc/tinyproxy/allowlist
    tinyproxy_changed=true
fi
if [ "$tinyproxy_changed" = true ] && [ "$RESTART" = true ]; then
    sudo launchctl kickstart -k system/com.aetherclaude.tinyproxy
    echo "   tinyproxy reloaded"
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
            # bootout returns before launchd finishes tearing the job
            # down; an immediate bootstrap of the same label races the
            # teardown and fails with "Bootstrap failed: 5: Input/output
            # error" — which under set -e killed the whole deploy and
            # left the service unloaded (2026-07-22 tunnel outage).
            # Wait for the label to disappear, then retry bootstrap.
            for _ in $(seq 1 20); do
                sudo launchctl print "system/$label" >/dev/null 2>&1 || break
                sleep 0.5
            done
            bootstrapped=false
            for _ in $(seq 1 5); do
                if sudo launchctl bootstrap system "$target"; then
                    bootstrapped=true
                    break
                fi
                sleep 2
            done
            if [ "$bootstrapped" != true ]; then
                echo "ERROR: bootstrap failed for $label after 5 attempts" >&2
                exit 1
            fi
            echo "   reloaded $label"
        fi
    fi
done

if [ "$RESTART" = true ]; then
    echo "==> Kicking dashboard to pick up script changes"
    sudo launchctl kickstart -k system/com.aetherclaude.dashboard 2>/dev/null || true
    # NOTE: Do NOT kickstart com.aetherclaude.agent here. That plist
    # runs the same /Users/aetherclaude/bin/run-agent.sh that the
    # dashboard's /webhook handler also spawns directly via
    # subprocess.Popen for every incoming GitHub event. `launchctl
    # kickstart -k` on macOS SIGTERMs every process matching the
    # plist's ProgramArguments — including the dashboard-spawned
    # in-flight orchestrators that are mid-PR-creation. Trace
    # 5a19c310 (#2486) died exactly this way: commit-signed.js had
    # just pushed the branch, the orch was 2 lines away from
    # creating the PR, deploy ran, SIGTERM landed, branch left
    # orphaned without a PR. The agent plist itself is a no-op
    # service (no calendar/interval trigger, exits on missing argv);
    # picking up script changes happens automatically on next webhook
    # because each invocation execs the script fresh from the symlink.
fi

echo "==> Done"
