#!/opt/homebrew/bin/bash
# One-off: triage every open AetherSDR issue that has no state-tracking label.
#
# Idempotent + resumable: when re-run, skips any issue that now has a
# state-tracking label (because a previous batch-triage pass tagged it).
# Stops cleanly when the Anthropic token gets close to expiring.
#
# Usage:
#   sudo -u aetherclaude /Users/aetherclaude/bin/batch-triage.sh [--dry-run] [--limit N]

set -euo pipefail

DRY_RUN=false
LIMIT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --limit) LIMIT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

source /Users/aetherclaude/.env
HOME=/Users/aetherclaude
# Match launchd's PATH so python3 resolves to homebrew (which has cryptography)
# rather than system /usr/bin/python3 — github-app-token.sh signs JWTs.
PATH=/Users/aetherclaude/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export HOME PATH

REPO=ten9876/AetherSDR
WORKSPACE=/Users/aetherclaude/workspace/AetherSDR
LOGDIR=/Users/aetherclaude/logs/batch-triage
mkdir -p "$LOGDIR"
ACTIONS_DB=/Users/aetherclaude/data/issue-actions.db
SKILLS_DIR=/Users/aetherclaude/skills
CLAUDE_TIMEOUT=600
CLAUDE_MIN_TOKEN_SECS=600

# State-tracking labels — issue is skipped if it has any of these
STATE_LABELS=(
    "awaiting-response" "awaiting-confirmation" "claude-active"
    "maintainer-review" "insufficient-info" "aetherclaude-eligible" "no-claude"
)

log() { echo "[$(date "+%H:%M:%S")] $*"; }

#  ─── Helpers (mirrors of the ones in run-agent.sh, kept local here) ────────

get_app_token() { /Users/aetherclaude/bin/github-app-token.sh 2>/dev/null; }

github_api() {
    local method="$1" endpoint="$2" token="$3"
    echo "$token" | python3 /Users/aetherclaude/bin/gh-request.py "$method" "$endpoint"
}

github_api_body() {
    local method="$1" endpoint="$2" token="$3" body="$4"
    local tmpfile; tmpfile=$(mktemp)
    printf "%s" "$body" > "$tmpfile"
    echo "$token" | python3 /Users/aetherclaude/bin/gh-request.py "$method" "$endpoint" "$tmpfile"
    rm -f "$tmpfile"
}

add_label() {
    local issue="$1" label="$2" token="$3"
    github_api_body POST "/repos/${REPO}/issues/${issue}/labels" "$token" \
        "{\"labels\":[\"${label}\"]}" > /dev/null 2>&1 || true
}

record_action() {
    local issue="$1" action="$2" state="$3" outcome="$4" detail="${5:-}"
    sqlite3 "$ACTIONS_DB" \
        "INSERT INTO issue_actions(issue_number,action,state,outcome,detail,run_id) VALUES(${issue}, '${action}', '${state}', '${outcome}', \"${detail//\"/\"\"}\", 'batch-triage');" 2>/dev/null || true
}

sanitize_input() {
    # Drop control chars except tab/newline; truncate to 32K to keep prompts reasonable
    printf "%s" "$1" | tr -d '\000-\010\013\014\016-\037\177' | head -c 32768
}

load_skill() {
    local name="$1"
    awk '/^---$/{c++; next} c >= 2' "${SKILLS_DIR}/${name}.md"
}

render_skill() {
    local template="$1"; shift
    local rendered="$template"
    while [ $# -ge 2 ]; do
        local k="$1" v="$2"; shift 2
        rendered="${rendered//\$\{$k\}/$v}"
    done
    printf "%s" "$rendered"
}

check_token_time() {
    python3 -c "
import json, time
try:
    creds = json.load(open('$HOME/.claude/.credentials.json'))
    expires_ms = creds.get('claudeAiOauth', {}).get('expiresAt', 0)
    print(int((expires_ms / 1000) - time.time()))
except Exception:
    print(-1)
" 2>/dev/null || echo -1
}

run_claude() {
    local prompt="$1" logfile="$2"
    local token_secs; token_secs=$(check_token_time)
    if [ "$token_secs" -ge 0 ] && [ "$token_secs" -lt "$CLAUDE_MIN_TOKEN_SECS" ]; then
        log "STOP: Anthropic token expires in ${token_secs}s, refresh and re-run"
        exit 2
    fi
    local pid
    env -u GH_TOKEN -u GITHUB_TOKEN -u GH_APP_TOKEN -u GITHUB_APP_ID \
        HOME="$HOME" PATH="$PATH" \
        claude -p "$prompt" \
            --model opus \
            --setting-sources user \
            --strict-mcp-config \
            --permission-mode bypassPermissions \
            --allowedTools "Read,Glob,Grep,Bash(ls *),Bash(head *),Bash(tail *),mcp__aetherclaude-github__*" \
            --disallowedTools "Bash(sudo *),Bash(curl *),Bash(wget *),Bash(rm -rf *),Bash(ssh *),Bash(scp *),Bash(nc *),Bash(ncat *),Bash(dd *),Bash(mount *),Bash(chmod *),Bash(chown *),Bash(chsh *),Bash(passwd *),Bash(brew *),Bash(npm *),Bash(pip *),Bash(nft *),Bash(systemctl *),Bash(git push *),Bash(git commit *),Bash(cat /Users/aetherclaude/.env),Bash(cat /Users/aetherclaude/.git-credentials),Bash(cat /Users/aetherclaude/.github-app-key.pem),Bash(echo \$*),Bash(env),Bash(printenv),Bash(set),WebFetch,WebSearch,Agent" \
            --mcp-config /Users/aetherclaude/.claude/mcp-servers.json \
        < /dev/null > "$logfile" 2>&1 &
    pid=$!
    ( sleep "$CLAUDE_TIMEOUT"; kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null ) &
    local watchdog=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill -9 "$watchdog" 2>/dev/null || true
    return "$rc"
}

# ─── Auto-close zero-effort detection (mirrors the orchestrator's logic) ──

is_zero_effort() {
    local title="$1" body="$2"
    local body_len=${#body}
    local has_radio=0 has_os=0 has_version=0 has_steps=0
    echo "$body" | grep -qiE 'radio.*model|firmware|flex-|FLEX-|M-[0-9]' && has_radio=1
    echo "$body" | grep -qiE '\bos\b|macos|linux|windows|arch|ubuntu|debian|fedora|tumbleweed' && has_os=1
    echo "$body" | grep -qiE 'version|v0\.|aethersdr.*[0-9]' && has_version=1
    echo "$body" | grep -qiE 'steps|reproduce|1\.|2\.|3\.' && has_steps=1
    local total=$((has_radio + has_os + has_version + has_steps))
    local has_image=0 has_code=0
    echo "$body" | grep -qE '!\[|<img' && has_image=1
    echo "$body" | grep -qE '\`\`\`' && has_code=1
    if [ "$total" -eq 0 ] && [ "$body_len" -lt 200 ] && [ "$has_image" -eq 0 ] && [ "$has_code" -eq 0 ]; then
        return 0
    fi
    return 1
}

# ─── Main ──────────────────────────────────────────────────────────────────

log "=== Batch triage starting (dry_run=$DRY_RUN, limit=$LIMIT) ==="
log "Workspace: $WORKSPACE"
log "Logs: $LOGDIR"

APP_TOKEN=$(get_app_token)
[ -n "$APP_TOKEN" ] || { log "FATAL: failed to get app token"; exit 1; }

cd "$WORKSPACE"
git fetch origin --quiet 2>/dev/null || true
git checkout main --quiet 2>/dev/null || true

# Build issue list — paginate
log "Fetching open issues..."
issues_json=""
for page in 1 2 3 4 5 6 7 8 9 10; do
    page_data=$(github_api GET "/repos/${REPO}/issues?state=open&per_page=100&page=${page}" "$APP_TOKEN" || echo "[]")
    count=$(echo "$page_data" | jq 'length')
    [ "$count" = "0" ] && break
    issues_json+=$(echo "$page_data" | jq -c '.[] | select(.pull_request == null)')$'\n'
done

# Filter: keep issues that have NO state-tracking label
state_label_json=$(printf '%s\n' "${STATE_LABELS[@]}" | jq -R . | jq -s .)
candidates=$(echo "$issues_json" | jq --argjson s "$state_label_json" -c '
    select(. != null and (.labels | type == "array")) |
    select(([.labels[].name] - $s) == [.labels[].name])
')

total=$(echo "$candidates" | grep -c '^{' || echo 0)
log "$total candidates to triage"

if [ "$DRY_RUN" = "true" ]; then
    echo "$candidates" | jq -r '"#\(.number) — \(.title)"' | head -20
    log "(dry-run: showing first 20)"
    exit 0
fi

processed=0
while IFS= read -r issue; do
    [ -z "$issue" ] && continue
    [ "$LIMIT" -gt 0 ] && [ "$processed" -ge "$LIMIT" ] && { log "Hit limit $LIMIT, stopping"; break; }

    number=$(echo "$issue" | jq -r '.number')
    title=$(echo "$issue" | jq -r '.title')
    body=$(echo "$issue" | jq -r '.body // ""')

    log "─── #${number} (${title:0:70}) ───"

    # Re-fetch (might have been labeled by something else since we started)
    fresh=$(github_api GET "/repos/${REPO}/issues/${number}" "$APP_TOKEN")
    has_state=$(echo "$fresh" | jq --argjson s "$state_label_json" '[.labels[].name] | any(. as $l | $s | index($l) != null)')
    if [ "$has_state" = "true" ]; then
        log "  skipped — state label was added since enumeration"
        continue
    fi

    # Zero-effort? Auto-close (cheaper than Claude call)
    if is_zero_effort "$title" "$body"; then
        log "  zero-effort — auto-closing"
        github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$APP_TOKEN" \
            "{\"body\":\"Thanks for reaching out, but I don't have enough information here to investigate.\\n\\n**Fastest path to a fix:** open AetherSDR and go to **Help → Support → File an Issue**. This uses the AI-assisted bug report tool that auto-collects your OS, AetherSDR version, radio model and firmware, and a log bundle, then opens a pre-filled issue template. Just describe what happened and what you expected, and submit.\\n\\nI'm closing this issue — please file a new one (or reopen this one) with those details and I'll take another look.\\n\\n— AetherClaude (automated agent for AetherSDR)\"}" \
            > /dev/null 2>&1 || true
        github_api_body PATCH "/repos/${REPO}/issues/${number}" "$APP_TOKEN" \
            '{"state":"closed","state_reason":"not_planned"}' > /dev/null 2>&1 || true
        add_label "$number" "insufficient-info" "$APP_TOKEN"
        record_action "$number" "auto_close_zero_effort" "closed" "success" "batch-triage zero-effort"
        processed=$((processed + 1))
        continue
    fi

    # Real triage via Claude
    issue_body=$(sanitize_input "$body")
    issue_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}/comments" "$APP_TOKEN" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

    triage_log="$LOGDIR/${number}-$(date +%Y%m%d-%H%M%S).log"
    skill_template=$(load_skill "triage-issue")
    prompt=$(render_skill "$skill_template" \
        "ISSUE_NUMBER" "$number" \
        "ISSUE_TITLE" "$title" \
        "ISSUE_BODY" "$issue_body" \
        "ISSUE_COMMENTS" "$issue_comments" \
        "WORKSPACE" "$WORKSPACE" \
        "RETRY_CONTEXT" "")

    log "  invoking Claude (log: $triage_log)"
    if run_claude "$prompt" "$triage_log"; then
        log "  ✓ triaged"
        record_action "$number" "batch_triage" "triage" "success" "batch run"
    else
        rc=$?
        log "  ✗ Claude exited with code $rc"
        record_action "$number" "batch_triage" "triage" "failure" "rc=$rc"
    fi

    # Scrub tokens from this issue's triage log immediately. Claude can
    # Read() any file (allowed tool), so if a session pulls in something
    # containing a token, it lands in the log. Same patterns as the
    # orchestrator's end-of-run sweep.
    sed -i "" \
        -e 's/ghs_[A-Za-z0-9]\{30,\}/ghs_***/g' \
        -e 's/ghp_[A-Za-z0-9]\{30,\}/ghp_***/g' \
        -e 's/github_pat_[A-Za-z0-9_]\{20,\}/github_pat_***/g' \
        -e 's/sk-ant-[A-Za-z0-9-]\{20,\}/sk-ant-***/g' \
        -e "s/${WEBHOOK_SECRET:-NEVERMATCH}/WEBHOOK_SECRET_***/g" \
        "$triage_log" 2>/dev/null || true

    processed=$((processed + 1))
done <<< "$candidates"

# End-of-run scrubber: same as run-agent.sh's. Hits all Claude session
# transcripts on the box, all token formats. Defense in depth — even if
# Claude reads ~/.env or anything else with a secret, it won't persist.
log "Scrubbing token patterns from Claude session logs..."
find "$HOME/.claude/projects" -name "*.jsonl" 2>/dev/null | while read -r f; do
    sed -i "" \
        -e 's/ghs_[A-Za-z0-9]\{30,\}/ghs_***/g' \
        -e 's/ghp_[A-Za-z0-9]\{30,\}/ghp_***/g' \
        -e 's/github_pat_[A-Za-z0-9_]\{20,\}/github_pat_***/g' \
        -e 's/sk-ant-[A-Za-z0-9-]\{20,\}/sk-ant-***/g' \
        -e "s/${WEBHOOK_SECRET:-NEVERMATCH}/WEBHOOK_SECRET_***/g" \
        "$f" 2>/dev/null
done

log "=== Batch triage complete (processed=$processed) ==="
