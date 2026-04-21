#!/opt/homebrew/bin/bash
# AetherClaude Release Notes Compiler
# Generates draft release notes from merged PRs since last tag.
# Triggered manually: sudo systemctl start aetherclaude-release-notes

set -euo pipefail

export PATH="/Users/aetherclaude/bin:/Users/aetherclaude/.local/bin:/usr/bin"
export HOME="/Users/aetherclaude"
export HTTPS_PROXY=""
export HTTP_PROXY=""
export NO_PROXY="localhost,127.0.0.1"

source /Users/aetherclaude/.env

WORKSPACE="/Users/aetherclaude/workspace/AetherSDR"
LOGDIR="/Users/aetherclaude/logs"
REPO="ten9876/AetherSDR"

mkdir -p "$LOGDIR"

log() { echo "$(date "+%Y-%m-%dT%H:%M:%S") RELEASE: $1" >> "$LOGDIR/orchestrator.log"; }

get_app_token() { /Users/aetherclaude/bin/github-app-token.sh 2>/dev/null; }

log "=== Release notes compilation starting ==="

cd "$WORKSPACE"
git fetch upstream --quiet 2>/dev/null

# Find the latest tag
LAST_TAG=$(git describe --tags --abbrev=0 upstream/main 2>/dev/null)
if [ -z "$LAST_TAG" ]; then
    log "ERROR: No tags found"
    exit 1
fi
log "Last release: ${LAST_TAG}"

# Get the tag date
TAG_DATE=$(git log -1 --format=%aI "$LAST_TAG" 2>/dev/null)
TAG_DATE_SHORT=$(echo "$TAG_DATE" | cut -dT -f1)

# Fetch merged PRs since the tag
APP_TOKEN=$(get_app_token)
MERGED_PRS=$(curl -s \
    -H "Authorization: token ${APP_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    --proxy "${HTTPS_PROXY}" \
    "https://api.github.com/search/issues?q=$(echo "repo:${REPO} is:pr is:merged merged:>${TAG_DATE_SHORT}" | jq -sRr @uri)&per_page=50&sort=created&order=asc")

PR_COUNT=$(echo "$MERGED_PRS" | jq '.total_count')
log "Found ${PR_COUNT} merged PRs since ${LAST_TAG}"

if [ "$PR_COUNT" -eq 0 ]; then
    log "No merged PRs since last tag — nothing to compile"
    exit 0
fi

# Format PR list for the prompt
PR_LIST=$(echo "$MERGED_PRS" | jq -r '.items[] | "- PR #\(.number): \(.title) (by @\(.user.login), labels: \([.labels[].name] | join(", ")))"')

# Git log for additional context
GIT_LOG=$(git log --oneline "${LAST_TAG}..upstream/main" 2>/dev/null | head -50)

RELEASE_LOG="$LOGDIR/release-notes-$(date +%Y%m%d-%H%M%S).log"

PROMPT="You are AetherClaude. Compile release notes for AetherSDR.

Last release: ${LAST_TAG} (${TAG_DATE_SHORT})
Merged PRs since then:
${PR_LIST}

Git log since ${LAST_TAG}:
${GIT_LOG}

Write release notes in this format:

# AetherSDR vX.Y.Z Release Notes

## New Features
- [Feature description] (#PR)

## Enhancements
- [Enhancement description] (#PR)

## Bug Fixes
- [Fix description] (#PR)

## Contributors
Thank you to everyone who contributed to this release:
- @username — [what they did]

Rules:
- Group by: New Features, Enhancements, Bug Fixes, Internal/CI (if any)
- Every contributor gets credited by GitHub username
- Keep each item to 1-2 lines
- Link PR numbers as #NNN
- Do not include internal refactors unless they affect users
- If a PR was by AetherClaude, credit it as 'AetherClaude (automated agent)'
- Write for a ham radio audience — they care about RX/TX, DSP, frequency accuracy, not implementation details

Output the release notes as plain text. Do NOT use any MCP tools — just output the text."

cd "$WORKSPACE"
env \
    -u GH_TOKEN -u GITHUB_TOKEN -u GH_APP_TOKEN -u GITHUB_APP_ID \
    HOME="$HOME" PATH="$PATH" \
    HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTP_PROXY" NO_PROXY="$NO_PROXY" \
    claude -p "$PROMPT" \
        --setting-sources user \
        --strict-mcp-config \
        --permission-mode bypassPermissions \
        --allowedTools "Read,Glob,Grep,Bash(git log *),Bash(git show *),Bash(git tag *)" \
        --disallowedTools "Edit,Write,Bash(sudo *),Bash(curl *),Bash(rm *),WebFetch,WebSearch,Agent" \
        --mcp-config /Users/aetherclaude/.claude/mcp-servers.json \
    > "$RELEASE_LOG" 2>&1 || {
    log "ERROR: Release notes compilation failed"
    exit 1
}

log "Release notes written to ${RELEASE_LOG}"
log "=== Release notes compilation complete ==="

echo ""
echo "================================================"
echo "  Release notes saved to: ${RELEASE_LOG}"
echo "  Review with: sudo cat ${RELEASE_LOG}"
echo "================================================"
