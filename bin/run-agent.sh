#!/opt/homebrew/bin/bash
# AetherClaude Agent Orchestrator v2 (Multi-Skill)
# Processes issues, reviews PRs, triages stale issues, welcomes contributors,
# answers discussions, explains CI failures, detects duplicates.

set -euo pipefail

export PATH="/Users/aetherclaude/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export HOME="/Users/aetherclaude"

source /Users/aetherclaude/.env

# Lock key — passed as argv[1] by the dashboard's /webhook handler. The
# webhook computes "issue-N" / "pr-N" / "disc-N" / "global" from the
# payload and uses it to scope every per-orch resource (lockfile, state
# files, active-trace marker). Webhooks for different keys spawn parallel
# orchestrators; webhooks for the same key serialize via the per-key
# lockfile.
LOCK_KEY="${1:-}"
if [ -z "$LOCK_KEY" ]; then
    echo "$(date "+%Y-%m-%dT%H:%M:%S") No lock_key argv — webhook-only policy, exiting" >> "/Users/aetherclaude/logs/orchestrator.log" 2>/dev/null
    exit 0
fi

# Per-key state files. The dashboard /webhook handler writes trace-id
# and trigger-event before spawning us; we read+delete them.
TRACE_FILE="/Users/aetherclaude/state/trace-id.${LOCK_KEY}"
if [ ! -f "$TRACE_FILE" ]; then
    echo "$(date "+%Y-%m-%dT%H:%M:%S") No trace-id state file for ${LOCK_KEY}, exiting" >> "/Users/aetherclaude/logs/orchestrator.log" 2>/dev/null
    exit 0
fi
AETHER_TRACE_ID="$(cat "$TRACE_FILE")"
rm -f "$TRACE_FILE"  # one-shot
export AETHER_TRACE_ID
# DefenseClaw's audit DB has a native trace_id column (v7 schema migration 4).
# Setting DEFENSECLAW_RUN_ID populates it automatically, so DC's audit_sink
# fan-out to /defenseclaw-webhook arrives already correlated.
export DEFENSECLAW_RUN_ID="$AETHER_TRACE_ID"

WORKSPACE="/Users/aetherclaude/workspace/AetherSDR"
LOGDIR="/Users/aetherclaude/logs"
PROMPTDIR="/Users/aetherclaude/prompts"
STATE_FILE="/Users/aetherclaude/state/last-poll.json"
LOCKFILE="/tmp/aetherclaude-${LOCK_KEY}.lock"
REPO="ten9876/AetherSDR"
MAX_ISSUES_PER_RUN=4
MAX_PRS_PER_RUN=2
MAX_DISCUSSIONS_PER_RUN=10

mkdir -p "$LOGDIR" "$PROMPTDIR" "$(dirname "$STATE_FILE")"

# --- Concurrency lock ---
if [ -f "$LOCKFILE" ]; then
    pid=$(cat "$LOCKFILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "$(date "+%Y-%m-%dT%H:%M:%S") Agent already running (PID $pid), exiting" >> "$LOGDIR/orchestrator.log"
        exit 0
    fi
fi
echo $$ > "$LOCKFILE"
# Publish the running orchestrator's trace_id alongside the lockfile so the
# dashboard's /webhook handler can fold burst-webhooks into this trace
# (otherwise each webhook of a burst would mint its own trace_id, but only
# the FIRST one's orchestrator instance actually runs — the others bounce
# off this lockfile, leaving their traces empty of orchestrator activity).
ACTIVE_TRACE_FILE="/Users/aetherclaude/state/active-trace-id.${LOCK_KEY}"
echo "$AETHER_TRACE_ID" > "$ACTIVE_TRACE_FILE"

# Per-lock-key git worktree. Two webhooks with different lock_keys can launch
# parallel orchestrators (see dashboard /webhook handler); without isolated
# checkouts they'd race on the shared WORKSPACE tree. The worktree shares
# .git/ with WORKSPACE but has its own working directory, so claude edits in
# one orch run cannot collide with edits in another. Detached HEAD off
# origin/main — claude itself creates the work branch (aetherclaude/issue-N).
WORKTREE_DIR="${WORKSPACE}/.claude/worktrees/${LOCK_KEY}"

cleanup_worktree() {
    [ -d "$WORKTREE_DIR" ] || return 0
    cd "$WORKSPACE" 2>/dev/null || return 0
    git worktree remove --force "$WORKTREE_DIR" 2>/dev/null
    git worktree prune --quiet 2>/dev/null
}

ensure_worktree() {
    cd "$WORKSPACE" 2>/dev/null || return 1
    [ -d "$WORKTREE_DIR" ] && return 0
    git worktree prune --quiet 2>/dev/null
    if ! git worktree add --quiet --detach "$WORKTREE_DIR" origin/main 2>/dev/null; then
        # Stale dir/registration from a previous crashed run — clean and retry.
        git worktree remove --force "$WORKTREE_DIR" 2>/dev/null
        rm -rf "$WORKTREE_DIR" 2>/dev/null
        git worktree prune --quiet 2>/dev/null
        git worktree add --quiet --detach "$WORKTREE_DIR" origin/main 2>/dev/null || {
            echo "$(date "+%Y-%m-%dT%H:%M:%S") ERROR: failed to create worktree at $WORKTREE_DIR" >> "$LOGDIR/orchestrator.log"
            return 1
        }
    fi
}

trap 'rm -f "$LOCKFILE" "$ACTIVE_TRACE_FILE"; cleanup_worktree' EXIT

log() { echo "$(date "+%Y-%m-%dT%H:%M:%S") [${AETHER_TRACE_ID:0:8}] $1" >> "$LOGDIR/orchestrator.log"; }

# --- State management ---
[ -f "$STATE_FILE" ] || echo '{}' > "$STATE_FILE"

get_state() { jq -r ".\"$1\" // \"\"" "$STATE_FILE"; }

set_state() {
    local tmp
    tmp=$(mktemp)
    # Guard against empty/corrupt state file
    [ ! -s "$STATE_FILE" ] && echo '{}' > "$STATE_FILE"
    jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

# --- Issue Actions DB ---
ACTIONS_DB="/Users/aetherclaude/data/issue-actions.db"
RUN_ID="$(date "+%Y-%m-%dT%H:%M:%S")"

init_actions_db() {
    python3 - <<'PYEOF'
import sqlite3, os
db = os.environ.get('ACTIONS_DB', '/Users/aetherclaude/data/issue-actions.db')
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
conn.executescript("""
CREATE TABLE IF NOT EXISTS issue_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_number INTEGER NOT NULL,
    action       TEXT NOT NULL,
    state        TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    detail       TEXT,
    run_id       TEXT,
    created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
);
CREATE INDEX IF NOT EXISTS idx_ia_issue   ON issue_actions(issue_number);
CREATE INDEX IF NOT EXISTS idx_ia_action  ON issue_actions(action);
CREATE INDEX IF NOT EXISTS idx_ia_state   ON issue_actions(state);
CREATE INDEX IF NOT EXISTS idx_ia_created ON issue_actions(created_at);
""")
conn.commit()
conn.close()
PYEOF
}

record_action() {
    # record_action ISSUE_NUMBER ACTION STATE OUTCOME [DETAIL]
    local issue_number="$1" action="$2" state="$3" outcome="$4" detail="${5:-}"
    ACTIONS_DB="$ACTIONS_DB" python3 - "$issue_number" "$action" "$state" "$outcome" "$detail" "$RUN_ID" <<'PYEOF'
import sqlite3, sys, os
issue_number, action, state, outcome, detail, run_id = sys.argv[1:]
db = os.environ.get('ACTIONS_DB', '/Users/aetherclaude/data/issue-actions.db')
try:
    conn = sqlite3.connect(db)
    conn.execute(
        'INSERT INTO issue_actions (issue_number,action,state,outcome,detail,run_id) VALUES (?,?,?,?,?,?)',
        (int(issue_number), action, state, outcome, detail, run_id)
    )
    conn.commit()
    conn.close()
except Exception as e:
    print(f"record_action error: {e}", file=__import__('sys').stderr)
PYEOF
}

db_get_state() {
    local issue_number="$1"
    ACTIONS_DB="$ACTIONS_DB" python3 - "$issue_number" <<'PYEOF'
import sqlite3, sys, os
issue_number = int(sys.argv[1])
db = os.environ.get('ACTIONS_DB', '/Users/aetherclaude/data/issue-actions.db')
try:
    conn = sqlite3.connect(db)
    row = conn.execute(
        'SELECT state FROM issue_actions WHERE issue_number=? AND state != "N/A" ORDER BY id DESC LIMIT 1',
        (issue_number,)
    ).fetchone()
    conn.close()
    print(row[0] if row else 'new')
except:
    print('new')
PYEOF
}

# --- GitHub App token ---
get_app_token() { /Users/aetherclaude/bin/github-app-token.sh 2>/dev/null; }

# Get AetherClaude fork token with PR permissions (for cross-fork PR creation)
get_fork_pr_token() {
    python3 -c "
import json, time, urllib.request, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

env = {}
for line in open('$HOME/.env'):
    if '=' in line and not line.startswith('#'):
        k, v = line.strip().split('=', 1)
        env[k] = v

app_id = env['GITHUB_APP_ID']
pk = open('$HOME/.github-app-key.pem').read()
now = int(time.time())
header = base64.urlsafe_b64encode(json.dumps({'alg':'RS256','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'iat':now-60,'exp':now+600,'iss':app_id}).encode()).rstrip(b'=').decode()
key = serialization.load_pem_private_key(pk.encode(), password=None)
sig = key.sign(f'{header}.{payload}'.encode(), padding.PKCS1v15(), hashes.SHA256())
jwt = f'{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b\"=\").decode()}'
opener = urllib.request.build_opener()

# Get AetherClaude installation (fork)
req = urllib.request.Request('https://api.github.com/app/installations',
    headers={'Authorization': f'Bearer {jwt}', 'Accept': 'application/vnd.github+json', 'User-Agent': 'AetherClaude'})
installs = json.loads(opener.open(req).read())
install_id = None
for inst in installs:
    if inst['account']['login'] == 'AetherClaude':
        install_id = inst['id']
        break
if not install_id: install_id = installs[0]['id']

# Request token with PR + contents permissions
body = json.dumps({'permissions': {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}}).encode()
req2 = urllib.request.Request(f'https://api.github.com/app/installations/{install_id}/access_tokens',
    data=body, method='POST',
    headers={'Authorization': f'Bearer {jwt}', 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'AetherClaude'})
print(json.loads(opener.open(req2).read())['token'])
" 2>/dev/null
}

github_api() {
    local method="$1" endpoint="$2" token="$3"
    echo "$token" | python3 /Users/aetherclaude/bin/gh-request.py "$method" "$endpoint"
}

github_api_body() {
    local method="$1" endpoint="$2" token="$3" body="$4"
    local tmpfile
    tmpfile=$(mktemp)
    echo "$body" > "$tmpfile"
    echo "$token" | python3 /Users/aetherclaude/bin/gh-request.py "$method" "$endpoint" "$tmpfile"
    rm -f "$tmpfile"
}

# --- Input sanitization ---
sanitize_input() {
    local text="$1"
    text=$(echo "$text" | sed -E '
        s/[Ii]gnore (previous|all|above) instructions/[REDACTED]/g
        s/[Yy]ou are now a/[REDACTED]/g
        s/[Dd]isregard (your|all|previous)/[REDACTED]/g
        s/[Ff]orget your instructions/[REDACTED]/g
        s/[Ss]ystem\s*:/[REDACTED]/g
        s/<\|[^|]*\|>/[REDACTED]/g
        s/\[INST\]/[REDACTED]/g
        s/\[\/INST\]/[REDACTED]/g
    ')
    text=$(echo "$text" | sed 's/<!--.*-->//g')
    echo "$text"
}

# --- Anthropic token expiry check ---
CLAUDE_MIN_TOKEN_SECS=${CLAUDE_MIN_TOKEN_SECS:-600}  # 10 minutes minimum

check_token_time() {
    local remaining
    remaining=$(python3 -c "
import json, time
try:
    creds = json.load(open('$HOME/.claude/.credentials.json'))
    oauth = creds.get('claudeAiOauth', {})
    expires_ms = oauth.get('expiresAt', 0)
    remaining = int((expires_ms / 1000) - time.time())
    print(remaining)
except:
    print(-1)
" 2>/dev/null)
    echo "${remaining:--1}"
}

# --- Run Claude Code (shared helper) ---
CLAUDE_TIMEOUT=${CLAUDE_TIMEOUT:-600}  # 10 minutes default

run_claude() {
    # Check token expiry before dispatching
    local token_secs
    token_secs=$(check_token_time)
    if [ "$token_secs" -ge 0 ] && [ "$token_secs" -lt "$CLAUDE_MIN_TOKEN_SECS" ]; then
        log "SKIPPED: Anthropic token expires in ${token_secs}s (< ${CLAUDE_MIN_TOKEN_SECS}s minimum)"
        return 2
    fi
    local prompt="$1" logfile="$2"
    local claude_pid

    ensure_worktree || { log "ERROR: worktree setup failed for ${LOCK_KEY}"; return 1; }

    ( cd "$WORKTREE_DIR" && exec env \
        -u GH_TOKEN -u GITHUB_TOKEN -u GH_APP_TOKEN -u GITHUB_APP_ID \
        HOME="$HOME" PATH="$PATH" \
        HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTP_PROXY" NO_PROXY="$NO_PROXY" \
        claude -p "$prompt" \
            --model opus \
            --setting-sources user \
            --strict-mcp-config \
            --permission-mode bypassPermissions \
            --allowedTools "Read,Glob,Grep,Edit,Write,Bash(git add *),Bash(git commit *),Bash(git push *),Bash(git diff *),Bash(git log *),Bash(git status),Bash(git checkout *),Bash(ls *),Bash(head *),Bash(tail *),mcp__aetherclaude-github__*" \
            --disallowedTools "Bash(sudo *),Bash(curl *),Bash(wget *),Bash(rm -rf *),Bash(ssh *),Bash(scp *),Bash(nc *),Bash(ncat *),Bash(dd *),Bash(mount *),Bash(chmod *),Bash(chown *),Bash(chsh *),Bash(passwd *),Bash(brew *),Bash(npm *),Bash(pip *),Bash(nft *),Bash(systemctl *),Bash(cat /Users/aetherclaude/.env),Bash(cat /Users/aetherclaude/.git-credentials),Bash(cat /Users/aetherclaude/.github-app-key.pem),Bash(echo \$*),Bash(env),Bash(printenv),Bash(set),WebFetch,WebSearch,Agent" \
            --mcp-config /Users/aetherclaude/.claude/mcp-servers.json \
        > "$logfile" 2>&1 ) &
    claude_pid=$!

    # Watchdog: kill Claude if it exceeds timeout
    (
        sleep "$CLAUDE_TIMEOUT"
        if kill -0 "$claude_pid" 2>/dev/null; then
            log "TIMEOUT: Claude Code stuck for ${CLAUDE_TIMEOUT}s (PID $claude_pid), killing"
            kill -TERM "$claude_pid" 2>/dev/null
            sleep 5
            kill -9 "$claude_pid" 2>/dev/null
        fi
    ) &
    local watchdog_pid=$!

    wait "$claude_pid"
    local exit_code=$?

    # Clean up watchdog
    kill "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null

    if [ $exit_code -eq 143 ] || [ $exit_code -eq 137 ]; then
        log "ERROR: Claude Code was killed by stuck timer (exit $exit_code)"
        return 1
    fi
    return $exit_code
}

# --- Skill loader: reads prompt template from skills directory ---
load_skill() {
    local skill_name="$1"
    local skill_file="/Users/aetherclaude/skills/${skill_name}.md"
    if [ -f "$skill_file" ]; then
        # Strip YAML frontmatter (lines between --- markers)
        sed '1{/^---$/!q;};1,/^---$/d' "$skill_file"
    else
        echo "ERROR: Skill file not found: $skill_file" >&2
        return 1
    fi
}

# Substitute variables in a skill template
render_skill() {
    local template="$1"
    shift
    # Replace ${VAR_NAME} patterns with provided values
    while [ $# -ge 2 ]; do
        local var="$1" val="$2"
        template="${template//\$\{${var}\}/${val}}"
        shift 2
    done
    echo "$template"
}

# --- Label management helpers ---
add_label() {
    local issue_number="$1" label="$2" token="$3"
    github_api_body POST "/repos/${REPO}/issues/${issue_number}/labels" "$token" \
        "{\"labels\":[\"${label}\"]}" > /dev/null 2>&1
}

remove_label() {
    local issue_number="$1" label="$2" token="$3"
    local encoded_label
    encoded_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))")
    github_api DELETE "/repos/${REPO}/issues/${issue_number}/labels/${encoded_label}" "$token" > /dev/null 2>&1
}

# =====================================================================
# SKILL: First-Time Contributor Welcome (no Claude Code — template only)
# =====================================================================
skill_welcome_first_timers() {
    log "--- Skill: First-Time Contributor Welcome ---"
    local token="$1"

    # Check recent issues and PRs for first-timers
    local items
    items=$(github_api GET "/repos/${REPO}/issues?state=open&sort=created&direction=desc&per_page=10" "$token")

    echo "$items" | jq -c '.[]' | while read -r item; do
        local number author association is_pr has_bot_comment
        number=$(echo "$item" | jq -r '.number')
        author=$(echo "$item" | jq -r '.user.login')
        association=$(echo "$item" | jq -r '.author_association')
        is_pr=$(echo "$item" | jq -r '.pull_request // empty')

        # Only first-timers
        if [ "$association" != "FIRST_TIME_CONTRIBUTOR" ] && [ "$association" != "FIRST_TIMER" ]; then
            continue
        fi

        # Check if we already welcomed them
        has_bot_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=30" "$token" | \
            jq '[.[] | select(.user.login == "aethersdr-agent[bot]") | select(.body | test("Welcome to AetherSDR"))] | length')
        if [ "$has_bot_comment" -gt 0 ]; then
            continue
        fi

        log "Welcoming first-time contributor @${author} on #${number}"

        local body
        if [ -n "$is_pr" ]; then
            body="Welcome to AetherSDR, @${author}! Thanks for your first pull request.\n\nA few things that might help:\n- Our [CONTRIBUTING.md](https://github.com/${REPO}/blob/main/CONTRIBUTING.md) covers coding conventions and the PR process\n- CI will run automatically — if it fails, I'll post a comment explaining what went wrong\n- Jeremy (KK7GWY) reviews all PRs before merge\n\nIf you have questions, feel free to ask here or in [Discussions](https://github.com/${REPO}/discussions).\n\n— AetherClaude (automated agent for AetherSDR)"
        else
            body="Welcome to AetherSDR, @${author}! Thanks for taking the time to open this issue.\n\nJeremy (KK7GWY) and I will take a look. If we need any additional details, we'll ask here.\n\nIf you have questions about the project, our [Discussions](https://github.com/${REPO}/discussions) page is a good place to start.\n\n— AetherClaude (automated agent for AetherSDR)"
        fi

        github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" "{\"body\":\"${body}\"}" > /dev/null 2>&1
    done
}

# =====================================================================
# SKILL: Bug Report Quality (check for missing info — template based)
# =====================================================================
skill_check_bug_reports() {
    log "--- Skill: Bug Report Quality ---"
    local token="$1"

    local issues
    issues=$(github_api GET "/repos/${REPO}/issues?state=open&sort=created&direction=desc&per_page=10&labels=bug" "$token")

    echo "$issues" | jq -c '.[]' | while read -r item; do
        local number body author has_bot_comment
        number=$(echo "$item" | jq -r '.number')
        body=$(echo "$item" | jq -r '.body // ""')
        author=$(echo "$item" | jq -r '.user.login')

        # Skip if already commented
        has_bot_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=30" "$token" | \
            jq '[.[] | select(.user.login == "aethersdr-agent[bot]")] | length')
        if [ "$has_bot_comment" -gt 0 ]; then
            continue
        fi

        # Check for missing fields
        local missing=()
        echo "$body" | grep -qi "radio.*model\|firmware\|flex-\|FLEX-" || missing+=("Radio model and firmware version")
        echo "$body" | grep -qi "os\|macos\|linux\|windows\|arch\|ubuntu\|debian" || missing+=("Operating system")
        echo "$body" | grep -qi "version\|v0\.\|aethersdr.*[0-9]" || missing+=("AetherSDR version")
        echo "$body" | grep -qi "steps\|reproduce\|1\.\|2\.\|3\." || missing+=("Steps to reproduce")

        # Only comment if 2+ fields missing
        if [ "${#missing[@]}" -lt 2 ]; then
            continue
        fi

        log "Requesting info on #${number} (missing ${#missing[@]} fields)"

        local missing_list=""
        for m in "${missing[@]}"; do
            missing_list="${missing_list}\n- ${m}"
        done

        local comment="Thanks for reporting this, @${author}. To help us track it down, could you share a few more details?\n${missing_list}\n\nIf you can attach logs (Help → Support → File an Issue), that would be especially helpful.\n\n— AetherClaude (automated agent for AetherSDR)"

        github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" "{\"body\":\"${comment}\"}" > /dev/null 2>&1

        # Mark as waiting so skill_process_issues doesn't triage/implement while we await user reply
        add_label "$number" "awaiting-response" "$token"
        record_action "$number" "needs_info" "waiting" "success" "Missing ${#missing[@]} required fields"
        set_state "issue_${number}_state" "waiting"
    done
}

# =====================================================================
# SKILL: PR Review (Claude Code — convention check)
# =====================================================================
skill_review_prs() {
    log "--- Skill: PR Review ---"
    local token="$1"
    local count=0

    local prs
    prs=$(github_api GET "/repos/${REPO}/pulls?state=open&sort=created&direction=desc&per_page=10" "$token")

    echo "$prs" | jq -c '.[]' | while read -r pr; do
        [ "$count" -ge "$MAX_PRS_PER_RUN" ] && break

        local pr_number pr_author pr_draft pr_title head_sha
        pr_number=$(echo "$pr" | jq -r '.number')
        pr_author=$(echo "$pr" | jq -r '.user.login')
        pr_draft=$(echo "$pr" | jq -r '.draft')
        pr_title=$(echo "$pr" | jq -r '.title')
        head_sha=$(echo "$pr" | jq -r '.head.sha')

        # Skip: self, maintainer, drafts
        [ "$pr_author" = "AetherClaude" ] && continue
        [ "$pr_author" = "ten9876" ] && continue
        [ "$pr_draft" = "true" ] && continue

        # Skip if already reviewed
        local has_review
        has_review=$(github_api GET "/repos/${REPO}/pulls/${pr_number}/reviews" "$token" | \
            jq '[.[] | select(.user.login == "aethersdr-agent[bot]")] | length')
        [ "$has_review" -gt 0 ] && continue

        # Skip if CI hasn't completed — review after CI so CI explainer can run on failures
        local ci_runs ci_status
        ci_runs=$(github_api GET "/repos/${REPO}/commits/${head_sha}/check-runs" "$token")
        ci_status=$(echo "$ci_runs" | jq -r '
            if .total_count == 0 then "none"
            elif [.check_runs[].status] | all(. == "completed") | not then "pending"
            elif [.check_runs[].conclusion] | any(. == "failure") then "failed"
            else "passed" end')
        if [ "$ci_status" != "passed" ]; then
            log "PR #${pr_number} — CI status: ${ci_status}, deferring review"
            continue
        fi

        log "Reviewing PR #${pr_number}: ${pr_title} by @${pr_author}"

        local pr_diff
        pr_diff=$(echo "$token" | python3 /Users/aetherclaude/bin/gh-request.py GET "/repos/${REPO}/pulls/${pr_number}" | head -500)

        local pr_files
        pr_files=$(github_api GET "/repos/${REPO}/pulls/${pr_number}/files?per_page=50" "$token" | \
            jq -r '.[].filename' | head -30)

        local sanitized_diff
        sanitized_diff=$(sanitize_input "$pr_diff")

        # Fetch Copilot and other reviewer comments for context
        local copilot_comments=""
        copilot_comments=$(github_api GET "/repos/${REPO}/pulls/${pr_number}/comments?per_page=50" "$token" | \
            jq -r '.[] | "[\(.user.login)] \(.path // ""):\(.line // "") — \(.body)"' 2>/dev/null | head -30 || echo "")

        local review_log="$LOGDIR/pr-review-${pr_number}-$(date +%Y%m%d-%H%M%S).log"

        local skill_template
        skill_template=$(load_skill "review-pr")
        local prompt
        prompt=$(render_skill "$skill_template" "PR_NUMBER" "$pr_number" "PR_TITLE" "$pr_title" "PR_AUTHOR" "$pr_author" "PR_FILES" "$pr_files" "PR_DIFF" "$sanitized_diff" "COPILOT_COMMENTS" "$copilot_comments")

        cd "$WORKSPACE"
        run_claude "$prompt" "$review_log" || {
            log "ERROR: PR review failed for #${pr_number}"
            continue
        }
        log "Reviewed PR #${pr_number}"
        count=$((count + 1))
    done
}

# =====================================================================
# SKILL: CI Failure Explainer
# =====================================================================
skill_explain_ci_failures() {
    log "--- Skill: CI Failure Explainer ---"
    local token="$1"

    local prs
    prs=$(github_api GET "/repos/${REPO}/pulls?state=open&sort=updated&direction=desc&per_page=10" "$token")

    echo "$prs" | jq -c '.[]' | while read -r pr; do
        local pr_number pr_author head_sha
        pr_number=$(echo "$pr" | jq -r '.number')
        pr_author=$(echo "$pr" | jq -r '.user.login')
        head_sha=$(echo "$pr" | jq -r '.head.sha')

        # Skip self and maintainer
        [ "$pr_author" = "AetherClaude" ] && continue
        [ "$pr_author" = "ten9876" ] && continue

        # Check for failed checks
        local failed_checks
        failed_checks=$(github_api GET "/repos/${REPO}/commits/${head_sha}/check-runs" "$token" | \
            jq '[.check_runs[] | select(.conclusion == "failure")] | length')

        [ "$failed_checks" -eq 0 ] && continue

        # Skip if we already explained this CI failure (DB-backed — not "any bot comment")
        local already_explained
        already_explained=$(ACTIONS_DB="$ACTIONS_DB" python3 -c "
import sqlite3, os
db=os.environ.get('ACTIONS_DB','/Users/aetherclaude/data/issue-actions.db')
conn=sqlite3.connect(db)
row=conn.execute('SELECT id FROM issue_actions WHERE issue_number=? AND action=?',(int('$pr_number'),'ci_explain')).fetchone()
conn.close()
print('yes' if row else '')
" 2>/dev/null)
        [ -n "$already_explained" ] && continue

        log "Explaining CI failure on PR #${pr_number}"

        # Get the run ID from check runs
        local run_id
        run_id=$(github_api GET "/repos/${REPO}/commits/${head_sha}/check-runs" "$token" | \
            jq -r '[.check_runs[] | select(.conclusion == "failure")][0].details_url // ""' | \
            grep -oP 'runs/\K\d+' || echo "")

        local ci_context="CI check failed on commit ${head_sha}."
        if [ -n "$run_id" ]; then
            # Try to get job logs
            local jobs_info
            jobs_info=$(github_api GET "/repos/${REPO}/actions/runs/${run_id}/jobs" "$token" | \
                jq '[.jobs[] | select(.conclusion == "failure") | {name: .name, steps: [.steps[] | select(.conclusion == "failure") | .name]}]')
            ci_context="CI check failed on commit ${head_sha}.\nRun ID: ${run_id}\nFailed jobs: ${jobs_info}"
        fi

        # Fetch Copilot and other reviewer comments for context
        local copilot_comments=""
        copilot_comments=$(github_api GET "/repos/${REPO}/pulls/${pr_number}/comments?per_page=50" "$token" | \
            jq -r '.[] | "[\(.user.login)] \(.path // ""):\(.line // "") — \(.body)"' 2>/dev/null | head -30 || echo "")

        local ci_log="$LOGDIR/ci-explain-${pr_number}-$(date +%Y%m%d-%H%M%S).log"

        local skill_template
        skill_template=$(load_skill "explain-ci")
        local prompt
        prompt=$(render_skill "$skill_template" "PR_NUMBER" "$pr_number" "PR_AUTHOR" "$pr_author" "CI_CONTEXT" "$ci_context" "HEAD_SHA" "$head_sha" "COPILOT_COMMENTS" "$copilot_comments")

        cd "$WORKSPACE"
        run_claude "$prompt" "$ci_log" || {
            log "ERROR: CI explanation failed for PR #${pr_number}"
            continue
        }
        record_action "$pr_number" "ci_explain" "N/A" "success" "Explained CI failure"
        log "Explained CI failure on PR #${pr_number}"
    done
}

# =====================================================================
# SKILL: Duplicate Issue Detection (Claude Code — similarity analysis)
# =====================================================================
skill_detect_duplicates() {
    log "--- Skill: Duplicate Detection ---"
    local token="$1"

    local recent_issues
    recent_issues=$(github_api GET "/repos/${REPO}/issues?state=open&sort=created&direction=desc&per_page=5" "$token")

    echo "$recent_issues" | jq -c '.[] | select(.pull_request == null)' | while read -r item; do
        local number title body word_count
        number=$(echo "$item" | jq -r '.number')
        title=$(echo "$item" | jq -r '.title')
        body=$(echo "$item" | jq -r '.body // ""')
        word_count=$(echo "$body" | wc -w)

        [ "$word_count" -lt 20 ] && continue

        # Skip if we already checked (DB-backed)
        local already_checked
        already_checked=$(ACTIONS_DB="$ACTIONS_DB" python3 -c "
import sqlite3, os
db=os.environ.get('ACTIONS_DB','/Users/aetherclaude/data/issue-actions.db')
conn=sqlite3.connect(db)
row=conn.execute('SELECT id FROM issue_actions WHERE issue_number=? AND action=?',(int('$number'),'dup_check')).fetchone()
conn.close()
print('yes' if row else '')
" 2>/dev/null)
        [ -n "$already_checked" ] && continue

        # Extract key terms from title
        local search_terms
        search_terms=$(echo "$title" | tr -cs '[:alnum:]' ' ' | tr '[:upper:]' '[:lower:]' | \
            tr ' ' '\n' | grep -vE '^(the|a|an|is|in|on|of|to|and|or|for|not|with|bug|fix|add|issue|when|from|after|this|that)$' | \
            head -3 | tr '\n' ' ')

        [ -z "$search_terms" ] && continue

        log "Checking #${number} for duplicates (terms: ${search_terms})"

        local search_results
        search_results=$(github_api GET "/search/issues?q=$(echo "repo:${REPO} is:issue ${search_terms}" | jq -sRr @uri)&per_page=5" "$token" | \
            jq "[.items[] | select(.number != ${number}) | {number: .number, title: .title, state: .state}]")

        local candidate_count
        candidate_count=$(echo "$search_results" | jq '. | length')

        record_action "$number" "dup_check" "N/A" "success" "Checked ${candidate_count} candidates"

        [ "$candidate_count" -eq 0 ] && continue

        # Use Claude Code to assess similarity
        local dup_log="$LOGDIR/dup-check-${number}-$(date +%Y%m%d-%H%M%S).log"
        local sanitized_body
        sanitized_body=$(sanitize_input "$body")

        local skill_template
        skill_template=$(load_skill "detect-duplicate")
        local prompt
        prompt=$(render_skill "$skill_template" "ISSUE_NUMBER" "$number" "ISSUE_TITLE" "$title" "ISSUE_BODY" "$sanitized_body" "SEARCH_RESULTS" "$search_results")

        cd "$WORKSPACE"
        run_claude "$prompt" "$dup_log" || log "ERROR: Duplicate check failed for #${number}"
    done
}

# =====================================================================
# SKILL: Discussion Responder (Claude Code — answer questions)
# =====================================================================
skill_respond_discussions() {
    log "--- Skill: Discussion Responder (DISABLED — app tokens can't write to discussions) ---"
    return 0
    local token="$1"
    local count=0

    # Get recent discussions via GraphQL (through MCP would require claude invocation,
    # so we use the API directly here for the poll, then invoke claude for responses)
    local discussions
    discussions=$(echo "$token" | python3 -c "
import urllib.request, json, os, sys
token = sys.stdin.readline().strip()
opener = urllib.request.build_opener()
body = json.dumps({'query': 'query { repository(owner: \"ten9876\", name: \"AetherSDR\") { discussions(first: 10, orderBy: {field: CREATED_AT, direction: DESC}) { nodes { id number title author { login } category { name } comments { totalCount } locked createdAt } } } }'}).encode()
req = urllib.request.Request('https://api.github.com/graphql', data=body, headers={'Authorization': f'bearer {token}', 'Content-Type': 'application/json', 'User-Agent': 'AetherClaude'}, method='POST')
print(json.dumps(json.loads(opener.open(req, timeout=10).read()).get('data',{}).get('repository',{}).get('discussions',{}).get('nodes',[])))
" 2>/dev/null)

    echo "$discussions" | jq -c '.[]' | while read -r disc; do
        [ "$count" -ge "$MAX_DISCUSSIONS_PER_RUN" ] && break

        local disc_number disc_title disc_author disc_category comment_count locked
        disc_number=$(echo "$disc" | jq -r '.number')
        disc_title=$(echo "$disc" | jq -r '.title')
        disc_author=$(echo "$disc" | jq -r '.author.login // "unknown"')
        disc_category=$(echo "$disc" | jq -r '.category.name // ""')
        comment_count=$(echo "$disc" | jq -r '.comments.totalCount')
        locked=$(echo "$disc" | jq -r '.locked')

        # Skip: locked, announcements, already has replies
        [ "$locked" = "true" ] && continue
        [ "$disc_category" = "Announcements" ] && continue
        [ "$comment_count" -gt 0 ] && continue

        # Skip if already processed
        local already_processed
        already_processed=$(get_state "disc_${disc_number}")
        [ -n "$already_processed" ] && continue

        log "Responding to discussion #${disc_number}: ${disc_title}"
        set_state "disc_${disc_number}" "$(date "+%Y-%m-%dT%H:%M:%S")"

        local disc_log="$LOGDIR/discussion-${disc_number}-$(date +%Y%m%d-%H%M%S).log"

        local skill_template
        skill_template=$(load_skill "respond-discussion")
        local prompt
        prompt=$(render_skill "$skill_template" "DISC_NUMBER" "$disc_number" "DISC_TITLE" "$disc_title" "DISC_AUTHOR" "$disc_author" "DISC_CATEGORY" "$disc_category")

        cd "$WORKSPACE"
        run_claude "$prompt" "$disc_log" || log "ERROR: Discussion response failed for #${disc_number}"
        count=$((count + 1))
    done
}

# =====================================================================
# SKILL: Process Eligible Issues (existing — code fix + PR)
# =====================================================================
skill_process_issues() {
    log "--- Skill: Issue Pipeline ---"
    local token="$1"

    # =====================================================================
    # PHASE 1: Fetch candidate issues
    # All open issues created in the last 24 hours, EXCLUDING:
    #   - labeled maintainer-review
    #   - labeled security, breaking-change, protocol
    #   - pull requests (GitHub API returns PRs in /issues too)
    # PLUS: any issues explicitly labeled aetherclaude-eligible or assigned
    # =====================================================================

    local cutoff_date
    cutoff_date=$(date -d '24 hours ago' -Iseconds 2>/dev/null || date -v-24H -Iseconds)

    # Fetch recent issues (< 24hr)
    local recent_issues
    recent_issues=$(github_api GET "/repos/${REPO}/issues?state=open&sort=created&direction=desc&per_page=20&since=${cutoff_date}" "$token")

    # Also fetch explicitly tagged/assigned (these bypass the 24hr window)
    local labeled assigned
    labeled=$(github_api GET "/repos/${REPO}/issues?labels=aetherclaude-eligible&state=open&per_page=10" "$token")
    assigned=$(github_api GET "/repos/${REPO}/issues?assignee=AetherClaude&state=open&per_page=10" "$token")

    # Merge all, deduplicate, filter
    #
    # Single rule: skip issues currently in maintainer-review UNLESS the
    # maintainer has authorized implementation by adding aetherclaude-eligible.
    # No other label-based excludes — the maintainer's `aetherclaude-eligible`
    # is the only authoritative go/no-go signal.
    local all_issues
    all_issues=$(echo "$recent_issues $labeled $assigned" | jq -s '
        add
        | unique_by(.number)
        | [.[] | select(.pull_request == null)]
        | [.[] | select(
            ([.labels[].name] | any(. == "maintainer-review") | not)
            or ([.labels[].name] | any(. == "aetherclaude-eligible"))
        )]
        | sort_by(.created_at)
    ')

    local total
    total=$(echo "$all_issues" | jq '. | length')
    log "Found $total candidate issues"

    [ "$total" -eq 0 ] && return

    # =====================================================================
    # PHASE 2: Process ONE issue per cycle (state machine)
    # States tracked in last-poll.json:
    #   issue_NNN_state = "triage" | "waiting" | "implement" | "done" | "failed"
    #   issue_NNN_last_action = ISO timestamp
    # =====================================================================

    local processed=0
    local token
    token=$(get_app_token)

    while read -r issue; do
        # Only 1 action per cycle
        [ "$processed" -ge 4 ] && break

        local number title
        number=$(echo "$issue" | jq -r '.number')
        title=$(echo "$issue" | jq -r '.title')

        # GUARD 1: Check if ANY PR exists for this issue branch — if so, skip entirely
        local branch="aetherclaude/issue-${number}"
        local any_pr
        any_pr=$(github_api GET "/repos/${REPO}/pulls?head=ten9876:${branch}&state=all" "$token" | jq '. | length' 2>/dev/null || echo 0)
        local any_pr_v2
        any_pr_v2=$(github_api GET "/repos/${REPO}/pulls?head=ten9876:${branch}-v2&state=all" "$token" | jq '. | length' 2>/dev/null || echo 0)
        local total_prs=$((any_pr + any_pr_v2))
        if [ "$total_prs" -gt 0 ]; then
            log "Issue #${number} — ${total_prs} PR(s) already exist, skipping"
            continue
        fi

        # GUARD 2: Read state from DB (authoritative — no comment parsing)
        local issue_state
        issue_state=$(db_get_state "$number")

        log "Issue #${number} — detected state: ${issue_state}"

        if [ "$issue_state" = "done" ]; then
            log "Issue #${number} — already handled, skipping"
            continue
        fi

        # Skip if already declined (read from DB — no comment parsing)
        if [ "$issue_state" = "declined" ]; then
            log "Issue #${number} — already declined, skipping"
            continue
        fi

        # Check if issue is outside agent scope
        local issue_data
        issue_data=$(github_api GET "/repos/${REPO}/issues/${number}" "$token")
        local issue_labels_str
        issue_labels_str=$(echo "$issue_data" | jq -r '[.labels[].name] | join(" ")')

        # State override: if a maintainer-review issue gets the
        # 'aetherclaude-eligible' label added, transition to implement.
        # That label is the maintainer's authorization to write the fix.
        if [ "$issue_state" = "maintainer-review" ] && \
           echo "$issue_data" | jq -e '[.labels[].name] | any(. == "aetherclaude-eligible")' >/dev/null; then
            log "Issue #${number} — maintainer added aetherclaude-eligible, transitioning to implement"
            record_action "$number" "maintainer-review" "implement" "success" "aetherclaude-eligible label added"
            issue_state="implement"
            set_state "issue_${number}_state" "implement"
        fi

        local out_of_scope=false
        for label in github_actions ci cd release build docker workflow; do
            echo "$issue_labels_str" | grep -qi "$label" && out_of_scope=true
        done
        local issue_body_raw
        issue_body_raw=$(echo "$issue_data" | jq -r '.body // ""')
        echo "$issue_body_raw" | grep -qiE '\.github/workflows|Dockerfile|\.yml.*action|CI.*build|github.actions' && out_of_scope=true

        if [ "$out_of_scope" = true ]; then
            log "Issue #${number} is CI/workflow scope — declining"
            github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" \
                "{\"body\":\"Thanks for filing this. This issue involves CI/CD workflows, build infrastructure, or release packaging — that is outside what I can help with, as I am restricted to source code changes in \`src/\` and \`docs/\`.\n\nJeremy will need to handle this one directly.\n\n— AetherClaude (automated agent for AetherSDR)\"}" \
                > /dev/null 2>&1
            record_action "$number" "declined" "declined" "success" "CI/workflow scope"
            set_state "issue_${number}_state" "declined"
            processed=$((processed + 1))
            continue
        fi

        # =====================================================================
        # STATE MACHINE
        # =====================================================================

        # State machine loop — fall through phases without waiting for next cycle
        while true; do

        log "Issue #${number} (${title}) — state: ${issue_state:-new}"
        local prev_state="${issue_state:-new}"

        case "${issue_state:-new}" in

        new|"")
            # ---------------------------------------------------------
            # STATE: NEW — First encounter. Triage and post analysis.
            # ---------------------------------------------------------

            # ── Pre-triage: auto-close zero-effort submissions ──
            # Fires BEFORE Claude triage to save tokens on garbage reports.
            local raw_body body_len
            raw_body=$(echo "$issue_data" | jq -r '.body // ""')
            body_len=${#raw_body}

            local has_radio=0 has_os=0 has_version=0 has_steps=0
            echo "$raw_body" | grep -qiE 'radio.*model|firmware|flex-|FLEX-|M-[0-9]' && has_radio=1
            echo "$raw_body" | grep -qiE '\bos\b|macos|linux|windows|arch|ubuntu|debian|fedora|tumbleweed' && has_os=1
            echo "$raw_body" | grep -qiE 'version|v0\.|aethersdr.*[0-9]' && has_version=1
            echo "$raw_body" | grep -qiE 'steps|reproduce|1\.|2\.|3\.' && has_steps=1
            local total_fields=$((has_radio + has_os + has_version + has_steps))

            # Effort markers — if present, don't auto-close even if keywords missing
            local has_image=0 has_code=0
            echo "$raw_body" | grep -qE '!\[|<img' && has_image=1
            echo "$raw_body" | grep -qE '\`\`\`' && has_code=1

            local close_reason=""
            if [ "$total_fields" -eq 0 ] && [ "$body_len" -lt 200 ] && [ "$has_image" -eq 0 ] && [ "$has_code" -eq 0 ]; then
                close_reason="No required fields, body=${body_len}ch, no images/code"
            fi

            if [ -n "$close_reason" ]; then
                log "AUTO_CLOSE: Issue #${number} — ${close_reason}"
                github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" \
                    "{\"body\":\"Thanks for reaching out, but I don't have enough information here to investigate.\\n\\n**Fastest path to a fix:** open AetherSDR and go to **Help → Support → File an Issue**. This uses the AI-assisted bug report tool that auto-collects your OS, AetherSDR version, radio model and firmware, and a log bundle, then opens a pre-filled issue template. Just describe what happened and what you expected, and submit.\\n\\nI'm closing this issue — please file a new one (or reopen this one) with those details and I'll take another look.\\n\\n— AetherClaude (automated agent for AetherSDR)\"}" \
                    > /dev/null 2>&1
                github_api_body PATCH "/repos/${REPO}/issues/${number}" "$token" \
                    '{"state":"closed","state_reason":"not_planned"}' \
                    > /dev/null 2>&1
                add_label "$number" "insufficient-info" "$token"
                record_action "$number" "auto_close_zero_effort" "closed" "success" "${close_reason}"
                set_state "issue_${number}_state" "closed"
                # Update local var too — `continue` would re-enter the case on
                # "new" and loop forever; `break` exits the per-issue state
                # machine cleanly so the outer loop reads the next issue.
                issue_state="closed"
                processed=$((processed + 1))
                break
            fi

            log "TRIAGE: Analyzing issue #${number}"
            add_label "$number" "claude-active" "$token"
            record_action "$number" "triage" "triage" "started"

            local issue_body issue_comments
            issue_body=$(sanitize_input "$(echo "$issue_data" | jq -r '.body // "No body"')")
            issue_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}/comments" "$token" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

            local triage_log="$LOGDIR/triage-${number}-$(date +%Y%m%d-%H%M%S).log"

            local skill_template
            skill_template=$(load_skill "triage-issue")
            local prompt
            prompt=$(render_skill "$skill_template"                 "ISSUE_NUMBER" "$number"                 "ISSUE_TITLE" "$title"                 "ISSUE_BODY" "$issue_body"                 "ISSUE_COMMENTS" "$issue_comments"                 "WORKSPACE" "$WORKSPACE")

            cd "$WORKSPACE"
            run_claude "$prompt" "$triage_log" || {
                log "ERROR: Triage failed for issue #${number}"
                record_action "$number" "triage" "failed" "failure" "Claude Code exited non-zero"
                set_state "issue_${number}_state" "failed"
                break
            }

            # Check if we asked questions (look for ? in our comment)
            local our_comment
            our_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=5" "$token" | \
                jq -r '[.[] | select(.user.login == "aethersdr-agent[bot]")] | last | .body // ""')

            if echo "$our_comment" | grep -q "?"; then
                record_action "$number" "triage" "waiting" "success" "Asked clarifying question"
                set_state "issue_${number}_state" "waiting"
                log "Issue #${number} — asked questions, moving to WAITING"
                remove_label "$number" "claude-active" "$token"
                add_label "$number" "awaiting-response" "$token"
            else
                record_action "$number" "triage" "implement" "success"
                set_state "issue_${number}_state" "implement"
                log "Issue #${number} — analysis complete, moving to IMPLEMENT"
            fi
            set_state "issue_${number}_last_action" "$(date "+%Y-%m-%dT%H:%M:%S")"
            processed=$((processed + 1))
            ;;

        waiting)
            # ---------------------------------------------------------
            # STATE: WAITING — Check for user replies
            # ---------------------------------------------------------
            local last_action
            last_action=$(get_state "issue_${number}_last_action")

            # Get comments after our last comment
            local our_last_comment_time
            our_last_comment_time=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=10" "$token" | \
                jq -r '[.[] | select(.user.login == "aethersdr-agent[bot]")] | last | .created_at // ""')

            local new_user_comments
            new_user_comments=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=10" "$token" | \
                jq "[.[] | select(.user.login != \"aethersdr-agent[bot]\") | select(.created_at > \"${our_last_comment_time}\")] | length")

            if [ "$new_user_comments" -gt 0 ]; then
                # User replied. Run continue-triage Claude pass: it either
                # asks ONE targeted follow-up question (stay in waiting) or
                # adds 'maintainer-review' label to hand off (state changes).
                # Implement only fires later, after the maintainer separately
                # authorizes by adding 'aetherclaude-eligible' (handled by
                # the label-based state override at top of skill_process_issues).
                log "Issue #${number} — user replied, running continue-triage"
                local issue_body issue_comments
                issue_body=$(sanitize_input "$(echo "$issue_data" | jq -r '.body // "No body"')")
                issue_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=50" "$token" | jq -r '.[] | "[\(.user.login) \(.created_at)] \(.body)"' 2>/dev/null || echo "No comments")")

                local triage_log="$LOGDIR/continue-triage-${number}-$(date +%Y%m%d-%H%M%S).log"
                local skill_template
                skill_template=$(load_skill "continue-triage")
                local prompt
                prompt=$(render_skill "$skill_template"                     "ISSUE_NUMBER" "$number"                     "ISSUE_TITLE" "$title"                     "ISSUE_BODY" "$issue_body"                     "ISSUE_COMMENTS" "$issue_comments")

                cd "$WORKSPACE"
                if ! run_claude "$prompt" "$triage_log"; then
                    log "ERROR: continue-triage failed for #${number}"
                    record_action "$number" "continue-triage" "waiting" "failure" "Claude exited non-zero"
                    processed=$((processed + 1))
                    break
                fi

                # Did Claude add the maintainer-review label? Re-fetch labels.
                local refreshed_labels
                refreshed_labels=$(github_api GET "/repos/${REPO}/issues/${number}" "$token" | jq -r '[.labels[].name]')
                if echo "$refreshed_labels" | jq -e 'any(. == "maintainer-review")' >/dev/null; then
                    log "Issue #${number} — Claude handed off to maintainer"
                    record_action "$number" "continue-triage" "maintainer-review" "success" "Claude has enough info, handed off"
                    remove_label "$number" "awaiting-response" "$token"
                    set_state "issue_${number}_state" "maintainer-review"
                    issue_state="maintainer-review"
                else
                    log "Issue #${number} — Claude posted follow-up, staying in waiting"
                    record_action "$number" "continue-triage" "waiting" "success" "Claude asked follow-up question"
                    # awaiting-response label stays; reset stale clock
                    set_state "issue_${number}_last_action" "$(date "+%Y-%m-%dT%H:%M:%S")"
                fi
                processed=$((processed + 1))
                break
            else
                # No user reply — check how long we've been waiting
                local days_waited=0
                if [ -n "$our_last_comment_time" ]; then
                    days_waited=$(python3 -c "
import datetime, sys
try:
    t = '${our_last_comment_time}'
    dt = datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
    now = datetime.datetime.now(datetime.timezone.utc)
    print(int((now - dt).total_seconds() / 86400))
except Exception:
    print(0)
" 2>/dev/null)
                fi
                days_waited="${days_waited:-0}"
                local stale_threshold="${STALE_CLOSE_DAYS:-7}"

                if [ "$days_waited" -ge "$stale_threshold" ]; then
                    log "Issue #${number} — ${days_waited} days without reply, closing as stale"
                    github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" \
                        "{\"body\":\"Thanks for the report. Without the details requested above, I'm unable to reproduce this issue. Closing for now — please feel free to reopen with the requested information (OS, AetherSDR version, radio model and firmware, steps to reproduce) and we'll take another look.\\n\\n— AetherClaude (automated agent for AetherSDR)\"}" \
                        > /dev/null 2>&1
                    github_api_body PATCH "/repos/${REPO}/issues/${number}" "$token" \
                        '{"state":"closed","state_reason":"not_planned"}' \
                        > /dev/null 2>&1
                    add_label "$number" "insufficient-info" "$token"
                    remove_label "$number" "awaiting-response" "$token"
                    record_action "$number" "close_stale" "closed" "success" "${days_waited} days without user reply"
                    set_state "issue_${number}_state" "closed"
                else
                    log "Issue #${number} — waiting for user reply (${days_waited}/${stale_threshold} days)"
                    # Stay in waiting state; don't count as a processed action
                fi
            fi
            # Waiting doesn't count as a processed action
            ;;

        implement)
            # ---------------------------------------------------------
            # STATE: IMPLEMENT — Create the fix and PR
            # Gated: requires the 'aetherclaude-eligible' label to be
            # present at the moment of implementation. Defensive — the
            # waiting->implement transition already checks for it, but
            # an issue could lose the label between cycles or be moved
            # into 'implement' state directly.
            # ---------------------------------------------------------
            local _impl_eligible
            _impl_eligible=$(echo "$issue_data" | jq '[.labels[].name] | any(. == "aetherclaude-eligible")')
            if [ "$_impl_eligible" != "true" ]; then
                log "Issue #${number} — implement requested but aetherclaude-eligible label missing; punting to maintainer"
                add_label "$number" "maintainer-review" "$token"
                remove_label "$number" "claude-active" "$token"
                record_action "$number" "implement" "maintainer-review" "skipped" "aetherclaude-eligible label missing"
                set_state "issue_${number}_state" "maintainer-review"
                issue_state="maintainer-review"
                processed=$((processed + 1))
                break
            fi

            log "IMPLEMENT: Fixing issue #${number}"
            add_label "$number" "claude-active" "$token"

            local issue_body issue_comments
            issue_body=$(sanitize_input "$(echo "$issue_data" | jq -r '.body // "No body"')")
            issue_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${number}/comments" "$token" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

            local issue_log="$LOGDIR/issue-${number}-$(date +%Y%m%d-%H%M%S).log"

            # Check for rejected PR (retry logic)
            local retry_context=""
            local closed_prs
            closed_prs=$(github_api GET "/repos/${REPO}/pulls?head=ten9876:${branch}&state=closed" "$token")
            local rejected_count
            rejected_count=$(echo "$closed_prs" | jq '[.[] | select(.merged_at == null)] | length')
            if [ "$rejected_count" -gt 0 ]; then
                local rejected_pr_number
                rejected_pr_number=$(echo "$closed_prs" | jq -r '[.[] | select(.merged_at == null)] | sort_by(.closed_at) | last | .number')
                local rejected_pr_review
                rejected_pr_review=$(github_api GET "/repos/${REPO}/pulls/${rejected_pr_number}/reviews" "$token" | \
                    jq -r '.[] | "[\(.user.login)] \(.body // "")"' 2>/dev/null || echo "")
                local rejected_pr_comments
                rejected_pr_comments=$(github_api GET "/repos/${REPO}/issues/${rejected_pr_number}/comments" "$token" | \
                    jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "")
                retry_context="
IMPORTANT: A previous PR was REJECTED. Address the feedback:
${rejected_pr_review:-No review comments}
${rejected_pr_comments:-No comments}"
                branch="aetherclaude/issue-${number}-v2"
            fi

            # Create ephemeral worktree for isolation
            local WORKTREE="/tmp/aetherclaude/issue-${number}"
            rm -rf "$WORKTREE" 2>/dev/null
            git -C "$WORKSPACE" worktree prune 2>/dev/null || true
            git -C "$WORKSPACE" branch -D "$branch" 2>/dev/null || true
            git -C "$WORKSPACE" worktree add "$WORKTREE" -b "$branch" main 2>/dev/null || {
                log "ERROR: Failed to create worktree for issue #${number}"
                record_action "$number" "implement" "failed" "failure" "git worktree add failed"
                set_state "issue_${number}_state" "failed"
                remove_label "$number" "claude-active" "$token"
                processed=$((processed + 1))
                break
            }
            log "Created worktree at ${WORKTREE}"

            local skill_template
            skill_template=$(load_skill "implement-fix")
            local prompt
            prompt=$(render_skill "$skill_template" "ISSUE_NUMBER" "$number" "ISSUE_TITLE" "$title" "ISSUE_BODY" "$issue_body" "ISSUE_COMMENTS" "$issue_comments" "RETRY_CONTEXT" "$retry_context" "BRANCH" "$branch" "WORKSPACE" "$WORKTREE")

            record_action "$number" "implement" "implement" "started"
            log "Running Claude Code for issue #${number}"
            cd "$WORKTREE"
            run_claude "$prompt" "$issue_log" || {
                log "ERROR: Claude Code failed for issue #${number} (see ${issue_log})"
                record_action "$number" "implement" "failed" "failure" "Claude Code exited non-zero"
                set_state "issue_${number}_state" "failed"
                cd "$WORKSPACE"
                git worktree remove "$WORKTREE" --force 2>/dev/null
                git branch -D "$branch" 2>/dev/null
                processed=$((processed + 1))
                break
            }

            # Check if Claude actually made commits
            local commit_count
            commit_count=$(git -C "$WORKTREE" log main..HEAD --oneline 2>/dev/null | wc -l)
            if [ "$commit_count" -eq 0 ]; then
                log "WARNING: Issue #${number} — Claude Code ran but made no commits"
                record_action "$number" "implement" "failed" "failure" "Claude Code made no commits"
                set_state "issue_${number}_state" "failed"
                remove_label "$number" "claude-active" "$token"
                cd "$WORKSPACE"
                git worktree remove "$WORKTREE" --force 2>/dev/null
                git branch -D "$branch" 2>/dev/null
                processed=$((processed + 1))
                break
            fi
            log "Issue #${number} — ${commit_count} commit(s) from Claude Code"

            # Validation gate (run against worktree)
            log "Running validation gate for issue #${number}"
            if ! ${HOME}/bin/validate-diff.sh "$WORKTREE" 2>&1; then
                log "VALIDATION FAILED for issue #${number}"
                record_action "$number" "validation_failed" "failed" "failure" "validate-diff.sh rejected changes"
                set_state "issue_${number}_state" "failed"
                # Only post a comment if our last comment was not already a validation failure
                local last_bot_comment
                last_bot_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=50" "$token" | \
                    jq -r '[.[] | select(.user.login == "aethersdr-agent[bot]")] | last | .body // ""' | tr '[:upper:]' '[:lower:]')
                if ! echo "$last_bot_comment" | grep -q "failed automated validation"; then
                    github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" \
                        "{\"body\":\"Claude here \u2014 I attempted a fix for #${number} but it failed the automated validation gate (changes required files outside my allowed paths or modified protected files).\\n\\nI won't retry until you reply. If you'd like me to try a different approach, let me know.\\n\\n73, Jeremy KK7GWY \\u0026 Claude (AI dev partner)\"}" \
                        > /dev/null 2>&1 || true
                fi
                cd "$WORKSPACE"
                git worktree remove "$WORKTREE" --force 2>/dev/null
                git branch -D "$branch" 2>/dev/null
                processed=$((processed + 1))
                break
            fi

            # ORCHESTRATOR: Push to remote as a SIGNED commit
            # Use createCommitOnBranch GraphQL — commits made via the GitHub
            # API on behalf of a GitHub App are auto-signed with GitHub's key,
            # so the resulting commit shows verified status. Replaces the
            # plain `git push` (which would push unsigned local commits).
            local commit_msg
            commit_msg=$(git -C "$WORKTREE" log -1 --format=%B 2>/dev/null || echo "Fix issue #${number}")
            log "Pushing branch ${branch} as signed commit via API"
            local commit_result
            commit_result=$(/opt/homebrew/bin/node /Users/aetherclaude/bin/commit-signed.js \
                "$branch" "$commit_msg" "$WORKTREE" 2>&1)
            if echo "$commit_result" | jq -e '.error' >/dev/null 2>&1; then
                local err
                err=$(echo "$commit_result" | jq -r '.error')
                log "ERROR: signed commit failed for issue #${number}: ${err}"
                record_action "$number" "push_failed" "failed" "failure" "commit-signed.js: ${err}"
                set_state "issue_${number}_state" "failed"
                remove_label "$number" "claude-active" "$token"
                cd "$WORKSPACE"
                git worktree remove "$WORKTREE" --force 2>/dev/null
                git branch -D "$branch" 2>/dev/null
                processed=$((processed + 1))
                break
            fi
            local signed_sha
            signed_sha=$(echo "$commit_result" | jq -r '.sha')
            log "Signed commit ${signed_sha:0:7} pushed to ${branch}"

            # ORCHESTRATOR: Create PR
            log "Creating PR for issue #${number}"
            local pr_title commit_subject changed_files diff_stat pr_body_file
            pr_title=$(git -C "$WORKTREE" log -1 --format=%s 2>/dev/null || true)
            commit_subject="$pr_title"
            changed_files=$(git -C "$WORKTREE" diff --name-only main 2>/dev/null | head -30 || true)
            diff_stat=$(git -C "$WORKTREE" diff --stat main 2>/dev/null | tail -5 || true)
            pr_body_file="/tmp/pr-body-${number}.txt"
            ISSUE_NUMBER="$number" COMMIT_SUBJECT="$commit_subject"             CHANGED_FILES="$changed_files" DIFF_STAT="$diff_stat"             python3 - > "$pr_body_file" <<'PYEOF'
import os
issue = os.environ["ISSUE_NUMBER"]
subject = os.environ.get("COMMIT_SUBJECT", "See commit history")
files_raw = os.environ.get("CHANGED_FILES", "")
stat = os.environ.get("DIFF_STAT", "")
file_lines = "\n".join(f"- `{f}`" for f in files_raw.strip().split("\n") if f.strip())
print(f"""## Summary

Fixes #{issue}

### What was changed

{subject}

### Files modified

{file_lines}

```
{stat}
```

---
Generated by AetherClaude (automated agent for AetherSDR)""", end="")
PYEOF
            local pr_result
            pr_result=$(/opt/homebrew/bin/node /Users/aetherclaude/bin/create-pr.js "$pr_title" "$branch" "$number" "$pr_body_file" 2>/dev/null)
            # Legacy inline PR creation (replaced by create-pr.js):
            if false; then
            pr_result=$(echo "unused" | python3 -c "
import sys, json, os, urllib.request
token = sys.stdin.readline().strip()
opener = urllib.request.build_opener()
data = json.dumps({'title': sys.argv[1], 'body': '## Summary\n\nFixes #${number}\n\n---\nGenerated by AetherClaude (automated agent for AetherSDR)', 'head': 'AetherClaude:${branch}', 'base': 'main', 'draft': True}).encode()
req = urllib.request.Request('https://api.github.com/repos/${REPO}/pulls', data=data, method='POST',
    headers={'Authorization': 'token ' + token, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'AetherClaude'})
try:
    resp = json.loads(opener.open(req, timeout=15).read())
    print(json.dumps({'number': resp['number'], 'url': resp['html_url']}))
except urllib.error.HTTPError as e:
    body = e.read().decode()[:500]
    print(json.dumps({'error': f'{e.code}: {body}'}))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" "$pr_title" 2>/dev/null)
            fi

            local pr_number
            pr_number=$(echo "$pr_result" | jq -r '.number // empty')
            local pr_error
            pr_error=$(echo "$pr_result" | jq -r '.error // empty')

            if [ -n "$pr_number" ]; then
                log "PR #${pr_number} created for issue #${number}"
                record_action "$number" "pr_created" "done" "success" "https://github.com/${REPO}/pull/${pr_number}"
                local comment_json
                comment_json=$(REPO="${REPO}" PR_NUMBER="${pr_number}" \
                    COMMIT_SUBJECT="${commit_subject}" CHANGED_FILES="${changed_files}" \
                    python3 - <<'PYEOF'
import os, json
repo = os.environ['REPO']
pr_num = os.environ['PR_NUMBER']
subject = os.environ.get('COMMIT_SUBJECT', '(see commits)')
files_raw = os.environ.get('CHANGED_FILES', '')
file_lines = ''.join(
    f'- `{f}`\n' for f in files_raw.strip().split('\n') if f.strip()
)
body = (
    f'Claude here \u2014 fix applied in PR #{pr_num}: '
    f'https://github.com/{repo}/pull/{pr_num}\n\n'
    f'**What was changed:** {subject}\n\n'
    f'**Files touched:**\n{file_lines}\n'
    f'\u2014 AetherClaude (automated agent for AetherSDR)'
)
print(json.dumps({'body': body}))
PYEOF
                )
                github_api_body POST "/repos/${REPO}/issues/${number}/comments" "$token" \
                    "$comment_json" \
                    > /dev/null 2>&1 || true
                remove_label "$number" "claude-active" "$token"
                set_state "issue_${number}_state" "done"
                log "Completed issue #${number} — PR #${pr_number} verified"
            else
                log "ERROR: PR creation failed for issue #${number}: ${pr_error}"
                record_action "$number" "pr_created" "failed" "failure" "${pr_error}"
                set_state "issue_${number}_state" "failed"
                remove_label "$number" "claude-active" "$token"
            fi

            # Destroy worktree — clean slate
            cd "$WORKSPACE"
            git worktree remove "$WORKTREE" --force 2>/dev/null
            git branch -D "$branch" 2>/dev/null
            processed=$((processed + 1))
            ;;

        esac

        # If state changed, loop immediately to process next phase
        issue_state=$(db_get_state "$number")
        [ "${issue_state:-new}" = "$prev_state" ] && break
        log "Issue #${number} — state changed to ${issue_state}, continuing immediately"

        done  # end state machine while loop

    done < <(echo "$all_issues" | jq -c '.[]')
}



# =====================================================================
# MAIN DISPATCHER
# =====================================================================

init_actions_db
log "=== Agent run starting ==="

# Sync with upstream
cd "$WORKSPACE"
APP_TOKEN=$(get_app_token)
export HTTPS_PROXY="http://127.0.0.1:8888"
export HTTP_PROXY="http://127.0.0.1:8888"
export NO_PROXY="localhost,127.0.0.1"
export GIT_TERMINAL_PROMPT=0
git fetch origin --quiet 2>/dev/null || { log "ERROR: git fetch failed"; exit 1; }
git checkout main --quiet 2>/dev/null
git reset --hard origin/main --quiet 2>/dev/null || { log "ERROR: reset to origin/main failed"; exit 1; }

# --- Early exit if Claude is unavailable ---
_token_remaining=$(check_token_time)
if [ "${_token_remaining}" -ge 0 ] && [ "${_token_remaining}" -lt "$CLAUDE_MIN_TOKEN_SECS" ]; then
    log "Token expires in ${_token_remaining}s — nothing to do without Claude, exiting"
    exit 0
fi

# --- Trigger-event scope decision (drives both the pre-flight scanners
# and the skill dispatcher below) ---
# The dashboard /webhook handler stashed the trigger info in
# ~/state/trigger-event before kickstart. Format:
#   "<event_type>:<action>"            for most events
#   "<event_type>:<action>:<label>"    for issues:labeled
# Calendar-interval / manual kickstarts leave the file absent → full sweep.
TRIGGER_EVENT=""
TRIGGER_ACTION=""
TRIGGER_LABEL=""
TRIGGER_FILE="/Users/aetherclaude/state/trigger-event.${LOCK_KEY}"
if [ -f "$TRIGGER_FILE" ]; then
    raw=$(cat "$TRIGGER_FILE" 2>/dev/null)
    rm -f "$TRIGGER_FILE"
    IFS=':' read -r TRIGGER_EVENT TRIGGER_ACTION TRIGGER_LABEL <<< "$raw"
fi
log "Trigger: ${TRIGGER_EVENT:-interval/manual}${TRIGGER_ACTION:+ ($TRIGGER_ACTION)}${TRIGGER_LABEL:+ label=$TRIGGER_LABEL}"

# Compute the scope of skills (prompts) and MCP tools that the routed
# workflow will actually use. The pre-flight scanners narrow themselves
# to this scope so we get fresh per-event scan output without re-scanning
# everything. Empty = no skills relevant, scanners skip. "all" = sweep.
EVENT_SKILLS=""
EVENT_TOOLS=""
case "$TRIGGER_EVENT" in
    issues)
        if [ "$TRIGGER_ACTION" = "closed" ]; then
            : # observability only — no skills, no scan
        elif [ "$TRIGGER_ACTION" = "labeled" ] && [ "$TRIGGER_LABEL" = "aetherclaude-eligible" ]; then
            EVENT_SKILLS="implement-fix"
            EVENT_TOOLS="read_issue,list_issue_comments,comment_on_issue,add_labels"
        else
            EVENT_SKILLS="triage-issue,detect-duplicate"
            EVENT_TOOLS="read_issue,list_issue_comments,comment_on_issue,add_labels,search_issues"
        fi
        ;;
    issue_comment)
        EVENT_SKILLS="continue-triage"
        EVENT_TOOLS="read_issue,list_issue_comments,comment_on_issue,add_labels,remove_label"
        ;;
    pull_request)
        if [ "$TRIGGER_ACTION" = "closed" ]; then
            : # observability only
        else
            EVENT_SKILLS="review-pr"
            EVENT_TOOLS="read_issue,list_open_prs,list_pr_files,get_pr_diff,get_check_runs,create_pr_review"
        fi
        ;;
    pull_request_review)
        EVENT_SKILLS="continue-triage,implement-fix"
        EVENT_TOOLS="read_issue,list_issue_comments"
        ;;
    check_run|workflow_run)
        EVENT_SKILLS="explain-ci"
        EVENT_TOOLS="get_ci_run_log,get_check_runs"
        ;;
    discussion|discussion_comment)
        : # responder disabled — no scope
        ;;
    release)
        : # release-notes is a separate script — no skill/tool scan
        ;;
    "")
        EVENT_SKILLS="all"
        EVENT_TOOLS="all"
        ;;
    *)
        EVENT_SKILLS="all"
        EVENT_TOOLS="all"
        ;;
esac
log "Scope: skills=[${EVENT_SKILLS:-none}] tools=[${EVENT_TOOLS:-none}]"

# --- Cisco AI Defense: Pre-flight security scans ---

# MCP Scanner: scan MCP server tools for threats.
# Context-aware: scans only the subset of tools that the skills the trigger
# event routes to actually use (computed in EVENT_TOOLS below). Empty list
# = no skills, skip entirely. "all" = full manifest scan (interval/manual).
if command -v mcp-scanner &>/dev/null && [ -n "${EVENT_TOOLS:-}" ]; then
    MCP_MANIFEST="${HOME}/config/mcp-tools.json"
    MCP_LATEST="$LOGDIR/mcp-scan-latest.json"
    if [ -f "$MCP_MANIFEST" ]; then
        # Build the tools file we'll actually scan: the full manifest, or
        # a filtered subset based on EVENT_TOOLS.
        if [ "$EVENT_TOOLS" = "all" ]; then
            SCAN_MANIFEST="$MCP_MANIFEST"
            SCAN_TOOL_LABEL="all"
        else
            SCAN_MANIFEST=$(mktemp)
            jq --arg names "$EVENT_TOOLS" \
               '.tools |= map(select(.name as $n | $names | split(",") | index($n)))' \
               "$MCP_MANIFEST" > "$SCAN_MANIFEST"
            SCAN_TOOL_LABEL="$EVENT_TOOLS"
        fi
        MCP_SCAN=$(mcp-scanner --analyzers yara --format raw \
            static --tools "$SCAN_MANIFEST" 2>/dev/null)
        MCP_UNSAFE=$(echo "$MCP_SCAN" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Count HIGH findings but exclude known false positives (get_ci_run_log)
    high = sum(1 for r in d.get('scan_results', [])
        if not r.get('is_safe', True)
        and r.get('tool_name') != 'get_ci_run_log'
        for a, f in r.get('findings', {}).items()
        if f.get('severity') in ('HIGH', 'CRITICAL'))
    print(high)
except: print(0)
" 2>/dev/null)
        echo "$MCP_SCAN" > "$MCP_LATEST"
        # Clean up temp filtered manifest if we created one
        [ "$SCAN_MANIFEST" != "$MCP_MANIFEST" ] && rm -f "$SCAN_MANIFEST"
        if [ "${MCP_UNSAFE:-0}" -gt 0 ]; then
            log "CRITICAL: MCP Scanner found $MCP_UNSAFE threats — aborting"
            exit 1
        fi
        scanned_count=$(echo "$MCP_SCAN" | jq '.scan_results | length' 2>/dev/null || echo 0)
        log "MCP Scanner: ${scanned_count} tools scanned (scope=${SCAN_TOOL_LABEL}), clean"
    fi
fi

# Prompt Scanner: scan AetherClaude skill templates with YARA + prompt_defense.
# Context-aware: scans only the subset of skills the trigger event routes to
# (EVENT_SKILLS, set above). Empty list = no skills relevant, skip. "all" =
# full skill set (interval/manual sweep).
# Findings are logged but do NOT abort — the analyzer can produce false
# positives on legitimate phrasings, and we want surface-level visibility
# without breaking agent runs.
if command -v mcp-scanner &>/dev/null \
    && [ -x /Users/aetherclaude/bin/skills-to-prompts-json.py ] \
    && [ -n "${EVENT_SKILLS:-}" ]; then
    PROMPTS_JSON="$LOGDIR/skill-prompts-latest.json"
    if [ "$EVENT_SKILLS" = "all" ]; then
        /Users/aetherclaude/bin/skills-to-prompts-json.py > "$PROMPTS_JSON" 2>/dev/null
    else
        /Users/aetherclaude/bin/skills-to-prompts-json.py | \
            jq --arg names "$EVENT_SKILLS" \
               '.prompts |= map(select(.name as $n | $names | split(",") | index($n)))' \
               > "$PROMPTS_JSON" 2>/dev/null
    fi
    if [ -s "$PROMPTS_JSON" ]; then
        # Use the Python wrapper instead of `mcp-scanner static --prompts` —
        # the upstream CLI silently drops the prompt_defense analyzer from
        # the static analyzer-list builder. The wrapper bypasses that bug
        # by calling Scanner._analyze_prompt directly, so we get YARA threat
        # detection AND prompt_defense advisory hardening findings.
        PROMPT_SCAN=$(/Users/aetherclaude/bin/scan-prompts-pd.py "$PROMPTS_JSON" 2>/dev/null)
        echo "$PROMPT_SCAN" > "$LOGDIR/prompt-scan-latest.json"
        PROMPT_TOTAL=$(echo "$PROMPT_SCAN" | python3 -c "
import sys, json
try: print(len(json.load(sys.stdin).get('scan_results', [])))
except: print(0)
" 2>/dev/null)
        PROMPT_UNSAFE=$(echo "$PROMPT_SCAN" | python3 -c "
import sys, json
try: print(sum(1 for r in json.load(sys.stdin).get('scan_results', []) if not r.get('is_safe', True)))
except: print(0)
" 2>/dev/null)
        if [ "${PROMPT_UNSAFE:-0}" -gt 0 ]; then
            log "Prompt Scanner: ${PROMPT_TOTAL:-0} prompts scanned (scope=${EVENT_SKILLS}), ${PROMPT_UNSAFE} flagged"
        else
            log "Prompt Scanner: ${PROMPT_TOTAL:-0} prompts scanned (scope=${EVENT_SKILLS}), clean"
        fi
    fi
fi

# Skill Scanner: check for injected .claude/ commands
if command -v skill-scanner &>/dev/null; then
    if [ -d "$WORKSPACE/.claude" ]; then
        SKILL_SCAN=$(skill-scanner scan "$WORKSPACE/.claude" \
            --lenient --format json 2>/dev/null || echo "[]")
        SKILL_UNSAFE=$(echo "$SKILL_SCAN" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d if isinstance(d, list) else [d]
    print(sum(1 for r in items if r.get('max_severity') in ('HIGH','CRITICAL')))
except: print(0)
" 2>/dev/null)
        echo "$SKILL_SCAN" > "$LOGDIR/skill-scan-latest.json"
        if [ "${SKILL_UNSAFE:-0}" -gt 0 ]; then
            log "CRITICAL: Skill Scanner found injected malicious skills — aborting"
            rm -rf "$WORKSPACE/.claude"
            exit 1
        fi
        log "Skill Scanner: workspace clean"
    else
        echo "[]" > "$LOGDIR/skill-scan-latest.json"
        log "Skill Scanner: no .claude/ in workspace — clean"
    fi
fi

# --- @Mention handler (priority — runs before all other skills) ---
MENTION_FILE="/Users/aetherclaude/state/mention.${LOCK_KEY}"
if [ -f "$MENTION_FILE" ]; then
    MENTION_NUMBER=$(cat "$MENTION_FILE")
    rm -f "$MENTION_FILE"
    if [ -n "$MENTION_NUMBER" ]; then
        log "--- Skill: @Mention Response (Issue #${MENTION_NUMBER}) ---"

        # Fetch the issue/PR and latest comments
        mention_data=$(github_api GET "/repos/${REPO}/issues/${MENTION_NUMBER}" "$APP_TOKEN")
        mention_title=$(echo "$mention_data" | jq -r '.title // "Unknown"')
        mention_body=$(sanitize_input "$(echo "$mention_data" | jq -r '.body // "No body"')")
        mention_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${MENTION_NUMBER}/comments?per_page=20" "$APP_TOKEN" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

        mention_log="$LOGDIR/mention-${MENTION_NUMBER}-$(date +%Y%m%d-%H%M%S).log"

        cd "$WORKSPACE"
        run_claude "You are AetherClaude. You were @mentioned in issue/PR #${MENTION_NUMBER}: ${mention_title}

Someone has specifically asked for your attention. Read the full conversation below and respond to whatever they are asking. This overrides all rate limits and state guards.

Issue body:
${mention_body}

Comments:
${mention_comments}

Respond with ONE helpful comment on issue #${MENTION_NUMBER} addressing the user's request. Stay within AetherSDR project guardrails. If they ask you to fix something, analyze the code and propose a fix. If they ask a question, answer it. If it's outside your scope, explain why politely.

Working directory: ${WORKSPACE}" "$mention_log" || {
            log "ERROR: @Mention response failed for #${MENTION_NUMBER}"
        }
        log "--- @Mention Response complete for #${MENTION_NUMBER} ---"
    fi
fi

# --- Event-type routing ---
# TRIGGER_EVENT/ACTION/LABEL were already read at the top (before scanners).
# This case statement just translates the trigger into which skill functions
# to dispatch. Default: nothing runs. Interval/manual (TRIGGER_EVENT="")
# opts into everything via the catch-all branch.
run_first_timers=0
run_bug_reports=0
run_process_issues=0
run_explain_ci=0
run_review_prs=0
run_detect_duplicates=0

case "$TRIGGER_EVENT" in
    issues)
        if [ "$TRIGGER_ACTION" = "closed" ]; then
            # Issue closed — no skills needed. The next interval sweep will
            # update internal state. Recording the event for observability
            # is enough.
            :
        elif [ "$TRIGGER_ACTION" = "labeled" ] && [ "$TRIGGER_LABEL" = "aetherclaude-eligible" ]; then
            # Subcase: maintainer added the implement-authorize label.
            # Only the issue pipeline matters — it has the state-override
            # that transitions maintainer-review → implement. Welcome /
            # bug-report / dup-detection would be no-ops on a triaged issue.
            run_process_issues=1
        else
            # New / edited / reopened / other-label issue. The pipeline does
            # the work; the others handle first-timer welcome, bug-report
            # quality nudge, and duplicate detection on freshly-filed issues.
            run_first_timers=1
            run_bug_reports=1
            run_process_issues=1
            run_detect_duplicates=1
        fi
        ;;
    issue_comment)
        # User replied. Pipeline picks up continue-triage; first-timer welcome
        # may apply if it's their very first interaction.
        run_first_timers=1
        run_process_issues=1
        ;;
    pull_request)
        if [ "$TRIGGER_ACTION" = "closed" ]; then
            # PR closed — could be merge or rejection. The retry-context
            # path inside skill_process_issues will pick up rejected PRs
            # next time the issue runs through the pipeline; for merges,
            # the implement state already cleaned up. No skills needed
            # here — just record the event for observability.
            :
        else
            # New / sync / reopened PR. Welcome (in case it's their first
            # PR) + PR review.
            run_first_timers=1
            run_review_prs=1
        fi
        ;;
    pull_request_review)
        # A reviewer left feedback — may unblock implement-fix retry context.
        # All actions (submitted/edited/dismissed) routed the same — process
        # _issues self-filters via DB state on a per-issue basis.
        run_process_issues=1
        ;;
    discussion|discussion_comment)
        # Discussion responder is permanently disabled (app tokens can't
        # write to discussions). Nothing to do.
        :
        ;;
    check_run|workflow_run)
        # CI failure (the dashboard only forwards `completed` runs with
        # conclusion=failure). Run the explainer + give the issue pipeline
        # a chance to surface retry context for the affected PR's source
        # issue.
        run_explain_ci=1
        run_process_issues=1
        ;;
    release)
        # Release published — generate / refresh release notes. Done as a
        # detached one-shot so it doesn't hold the orchestrator's lock or
        # block other skills if it takes a while.
        log "Trigger: release published — kicking off release-notes generator"
        if [ -x /Users/aetherclaude/bin/run-release-notes.sh ]; then
            /Users/aetherclaude/bin/run-release-notes.sh > "$LOGDIR/release-notes-$(date +%Y%m%d-%H%M%S).log" 2>&1 &
        fi
        ;;
    "")
        # Interval / manual kickstart — full sweep.
        run_first_timers=1
        run_bug_reports=1
        run_process_issues=1
        run_explain_ci=1
        run_review_prs=1
        run_detect_duplicates=1
        ;;
    *)
        log "Unknown trigger event '$TRIGGER_EVENT' — running full sweep"
        run_first_timers=1
        run_bug_reports=1
        run_process_issues=1
        run_explain_ci=1
        run_review_prs=1
        run_detect_duplicates=1
        ;;
esac

# Quick skills (no Claude Code, template-based)
[ "$run_first_timers" = "1" ] && skill_welcome_first_timers "$APP_TOKEN"
[ "$run_bug_reports" = "1" ] && skill_check_bug_reports "$APP_TOKEN"

# Claude Code skills
[ "$run_process_issues" = "1" ]    && skill_process_issues    "$APP_TOKEN"
[ "$run_explain_ci" = "1" ]        && skill_explain_ci_failures "$APP_TOKEN"
[ "$run_review_prs" = "1" ]        && skill_review_prs        "$APP_TOKEN"
[ "$run_detect_duplicates" = "1" ] && skill_detect_duplicates "$APP_TOKEN"
# skill_respond_discussions is permanently disabled — the function definition
# remains for future use but is no longer dispatched.

# No GIT_ASKPASS cleanup needed — credential helper handles git auth

# Clean up workspace — prune orphaned worktrees, ensure main is clean
cd "$WORKSPACE"
git checkout main --quiet 2>/dev/null
git worktree prune 2>/dev/null
rm -rf /tmp/aetherclaude/issue-* 2>/dev/null
git branch | grep -v '^\*' | grep -v main | xargs git branch -D 2>/dev/null || true
git clean -fd 2>/dev/null

# Scrub tokens from Claude Code session logs (all files, all token types)
find "$HOME/.claude/projects" -name "*.jsonl" 2>/dev/null | while read f; do
    sed -i "" \
        -e "s/ghs_[A-Za-z0-9]\{30,\}/ghs_***/g" \
        -e "s/ghp_[A-Za-z0-9]\{30,\}/ghp_***/g" \
        -e "s/github_pat_[A-Za-z0-9_]\{20,\}/github_pat_***/g" \
        -e "s/sk-ant-[A-Za-z0-9-]\{20,\}/sk-ant-***/g" \
        "$f" 2>/dev/null
done

log "=== Agent run complete ==="
