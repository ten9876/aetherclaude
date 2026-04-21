#!/opt/homebrew/bin/bash
# AetherClaude Stale Issue Triage
# Weekly sweep of issues with no activity for 30+ days.
# Runs as a separate systemd timer (Sundays at 10:00 AM).

set -euo pipefail

export PATH="/Users/aetherclaude/bin:/Users/aetherclaude/.local/bin:/usr/bin"
export HOME="/Users/aetherclaude"
export HTTPS_PROXY=""
export HTTP_PROXY=""
export NO_PROXY="localhost,127.0.0.1"

source /Users/aetherclaude/.env

WORKSPACE="/Users/aetherclaude/workspace/AetherSDR"
LOGDIR="/Users/aetherclaude/logs"
STATE_FILE="/Users/aetherclaude/state/last-poll.json"
REPO="ten9876/AetherSDR"
MAX_STALE_PER_RUN=20

mkdir -p "$LOGDIR"
[ -f "$STATE_FILE" ] || echo '{}' > "$STATE_FILE"

log() { echo "$(date "+%Y-%m-%dT%H:%M:%S") STALE: $1" >> "$LOGDIR/orchestrator.log"; }
get_state() { jq -r ".\"$1\" // \"\"" "$STATE_FILE"; }
set_state() {
    local tmp
    tmp=$(mktemp)
    jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

get_app_token() { /Users/aetherclaude/bin/github-app-token.sh 2>/dev/null; }

github_api() {
    local method="$1" endpoint="$2" token="$3"
    shift 3
    curl -s -X "$method" \
        -H "Authorization: token ${token}" \
        -H "Accept: application/vnd.github+json" \
        --proxy "${HTTPS_PROXY}" \
        "$@" \
        "https://api.github.com${endpoint}"
}

github_api_body() {
    local method="$1" endpoint="$2" token="$3" body="$4"
    local tmpfile
    tmpfile=$(mktemp)
    echo "$body" > "$tmpfile"
    curl -s -X "$method" \
        -H "Authorization: token ${token}" \
        -H "Accept: application/vnd.github+json" \
        --proxy "${HTTPS_PROXY}" \
        -d "@${tmpfile}" \
        "https://api.github.com${endpoint}"
    rm -f "$tmpfile"
}

sanitize_input() {
    local text="$1"
    text=$(echo "$text" | sed -E '
        s/[Ii]gnore (previous|all|above) instructions/[REDACTED]/g
        s/[Yy]ou are now a/[REDACTED]/g
        s/[Dd]isregard (your|all|previous)/[REDACTED]/g
        s/[Ff]orget your instructions/[REDACTED]/g
    ')
    text=$(echo "$text" | sed 's/<!--.*-->//g')
    echo "$text"
}

log "=== Stale issue triage starting ==="

APP_TOKEN=$(get_app_token)

# Find open issues not updated in 30+ days
STALE_DATE=$(date -d '30 days ago' +%Y-%m-%d 2>/dev/null || date -v-30d +%Y-%m-%d)
STALE_ISSUES=$(github_api GET "/search/issues?q=$(echo "repo:${REPO} is:issue is:open updated:<${STALE_DATE} -label:pinned -label:long-term -label:wontfix" | jq -sRr @uri)&per_page=${MAX_STALE_PER_RUN}" "$APP_TOKEN")

COUNT=$(echo "$STALE_ISSUES" | jq '.total_count')
log "Found $COUNT stale issues (processing up to $MAX_STALE_PER_RUN)"

echo "$STALE_ISSUES" | jq -c '.items[]' 2>/dev/null | while read -r item; do
    local number title author updated_at
    number=$(echo "$item" | jq -r '.number')
    title=$(echo "$item" | jq -r '.title')
    author=$(echo "$item" | jq -r '.user.login')
    updated_at=$(echo "$item" | jq -r '.updated_at')

    # Skip if assigned (someone is working on it)
    local assignee_count
    assignee_count=$(echo "$item" | jq '.assignees | length')
    [ "$assignee_count" -gt 0 ] && continue

    # Skip if we already pinged within 30 days
    local last_ping
    last_ping=$(get_state "stale_ping_${number}")
    if [ -n "$last_ping" ]; then
        log "Issue #${number} already pinged recently, skipping"
        continue
    fi

    # Skip if bot already commented recently
    local recent_bot_comment
    recent_bot_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=10" "$APP_TOKEN" | \
        jq '[.[] | select(.user.login == "aethersdr-agent[bot]")] | length')
    if [ "$recent_bot_comment" -gt 0 ]; then
        set_state "stale_ping_${number}" "$(date "+%Y-%m-%dT%H:%M:%S")"
        continue
    fi

    log "Triaging stale issue #${number}: ${title} (last updated: ${updated_at})"

    # Read issue body + comments for context
    local issue_body issue_comments
    issue_body=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}" "$APP_TOKEN" | jq -r '.body // "No body"')")
    issue_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}/comments" "$APP_TOKEN" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

    local stale_log="$LOGDIR/stale-${number}-$(date +%Y%m%d-%H%M%S).log"

    local prompt="You are AetherClaude. Issue #${number} has had no activity for 30+ days.

Issue #${number}: ${title}
Author: @${author}
Last updated: ${updated_at}

Issue body:
${issue_body}

Issue comments:
${issue_comments}

Check the codebase (git log, source files) to determine:

1. If recent commits may have fixed this issue, use comment_on_issue to say:
   'Hey @${author} — it looks like recent changes (specifically [commit/PR]) may have addressed this. Could you check if this is still an issue on the latest version? — AetherClaude (automated agent for AetherSDR)'

2. If the issue is missing info needed to fix it, ask specifically for what is needed.

3. If the issue is still relevant and unfixed, use comment_on_issue to say:
   'Hey @${author} — just checking in on this. Is this still an issue for you? Any additional details that might help us track it down? — AetherClaude (automated agent for AetherSDR)'

Rules:
- Do NOT close the issue. Only comment.
- Do NOT use the word 'stale' — it sounds bureaucratic.
- Be brief and genuine. One question, not a form letter.
- If you cannot determine anything useful, do NOT comment."

    cd "$WORKSPACE"
    env \
        -u GH_TOKEN -u GITHUB_TOKEN -u GH_APP_TOKEN -u GITHUB_APP_ID \
        HOME="$HOME" PATH="$PATH" \
        HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTP_PROXY" NO_PROXY="$NO_PROXY" \
        claude -p "$prompt" \
            --setting-sources user \
            --strict-mcp-config \
            --permission-mode bypassPermissions \
            --allowedTools "Read,Glob,Grep,Bash(git log *),Bash(git show *),Bash(git diff *),mcp__aetherclaude-github__comment_on_issue,mcp__aetherclaude-github__read_issue,mcp__aetherclaude-github__list_issue_comments" \
            --disallowedTools "Edit,Write,Bash(sudo *),Bash(curl *),Bash(rm *),WebFetch,WebSearch,Agent" \
            --mcp-config /Users/aetherclaude/.claude/mcp-servers.json \
        > "$stale_log" 2>&1 || {
        log "ERROR: Stale triage failed for #${number}"
        continue
    }

    set_state "stale_ping_${number}" "$(date "+%Y-%m-%dT%H:%M:%S")"
    log "Triaged stale issue #${number}"
done

log "=== Stale issue triage complete ==="
