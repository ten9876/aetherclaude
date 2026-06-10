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
REPO="aethersdr/AetherSDR"
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
trap '
    rc=$?
    # Forensic log if the script exits non-zero — set -e can kill us at
    # any bare command-substitution assignment if the substituted command
    # fails. Without this trap we get a SILENT death (lockfile cleaned
    # up, trace empty in the orchestrator log). Issue #2486 (5a19c310)
    # and issue #2500 (cc53455a, fe2b51d0) all died this way at the
    # commit_result=$(node commit-signed.js …) line — no log line, no
    # error, branch pushed but no PR created. With this trap, the
    # silent-death case leaves a "FATAL: exited rc=N" breadcrumb so we
    # can find the failure point on the next occurrence.
    if [ "$rc" -ne 0 ] && [ -n "${AETHER_TRACE_ID:-}" ]; then
        echo "$(date "+%Y-%m-%dT%H:%M:%S") [${AETHER_TRACE_ID:0:8}] FATAL: orchestrator exited rc=$rc (set -e?); last-touched LOCK_KEY=${LOCK_KEY:-?}" \
            >> "/Users/aetherclaude/logs/orchestrator.log" 2>/dev/null
    fi
    rm -f "$LOCKFILE" "$ACTIVE_TRACE_FILE"
' EXIT

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

# Post a bot-authored comment/review with the public cost-band footer
# attached and a precise audit row written. Takes the same arg shape as
# `github_api_body POST` so callers swap one for the other in-place.
#
#   post_bot_comment <endpoint> <token> <payload_json> [<kind>]
#
# kind is one of: issue_comment (default), pr_review, pr_description,
# discussion_comment. The helper extracts .body from the JSON payload,
# appends the footer, re-injects it, posts, and backfills the resulting
# comment URL into the audit row. A failure in bot-cost.py never blocks
# the post — we fall back to the bare body.
post_bot_comment() {
    local endpoint="$1" token="$2" payload="$3" kind="${4:-issue_comment}"

    local body wrapped new_payload response url target session_arg
    body=$(printf '%s' "$payload" | jq -r '.body // empty' 2>/dev/null || echo "")
    # Pass the most-recent run_claude session ID through so bot-cost.py
    # attributes only THIS run's tokens, not whatever happens to have
    # been written across all session JSONLs since the last marker.
    # Empty when post_bot_comment is called without a preceding claude
    # call (e.g., bare welcome message) — bot-cost.py falls back to
    # legacy offset behavior in that case, but the result is zero tokens
    # since there was no LLM work.
    session_arg=()
    if [ -n "${LAST_CLAUDE_SESSION_ID:-}" ]; then
        session_arg=(--session-id "$LAST_CLAUDE_SESSION_ID")
    fi
    wrapped=$(printf '%s' "$body" | /Users/aetherclaude/bin/bot-cost.py wrap \
                --kind "$kind" --endpoint "$endpoint" \
                "${session_arg[@]}" --body - 2>/dev/null) \
        || wrapped="$body"
    new_payload=$(printf '%s' "$payload" | jq --arg b "$wrapped" '.body = $b' 2>/dev/null) \
        || new_payload="$payload"

    response=$(github_api_body POST "$endpoint" "$token" "$new_payload")
    url=$(printf '%s' "$response" | jq -r '.html_url // empty' 2>/dev/null || echo "")
    if [ -n "$url" ]; then
        target=$(printf '%s' "$endpoint" | sed -nE 's|.*/(issues\|pulls)/([0-9]+)/.*|\1:\2|p' \
                | sed 's/^issues:/issue:/; s/^pulls:/pr:/')
        if [ -n "$target" ]; then
            /Users/aetherclaude/bin/bot-cost.py backfill-url \
                --target "$target" --url "$url" 2>/dev/null || true
        fi
    fi

    printf '%s' "$response"
}

# Citation-resolution check (Foundry Principle I — Evidence Over Assertion,
# partial form). Parses path:line / path:line-line citations from the latest
# agent comment on an issue and verifies each against the workspace clone
# of AetherSDR at origin/main. Unresolved citations are footnoted onto the
# comment via PATCH; the run continues regardless of result (informational,
# non-blocking — per the operator decision in this session).
#
# Args: ISSUE_NUMBER TOKEN
# Side effect: logs a CITATION_CHECK: line; if any citation fails, also
#   PATCHes the comment body to append a <details> footnote table.
check_citations() {
    local number="$1" token="$2"
    local workspace_main="/Users/aetherclaude/workspace/AetherSDR"
    [ -d "$workspace_main" ] || return 0

    local comments comment_data comment_id comment_body
    comments=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=100" "$token")
    comment_data=$(echo "$comments" | jq -c '[.[] | select(.user.login == "aethersdr-agent[bot]")] | last // empty' 2>/dev/null)
    [ -z "$comment_data" ] && return 0
    comment_id=$(echo "$comment_data" | jq -r '.id')
    comment_body=$(echo "$comment_data" | jq -r '.body')
    [ -z "$comment_body" ] && return 0

    # Refresh the workspace clone so citations check against current main.
    git -C "$workspace_main" fetch --quiet origin main 2>/dev/null || true
    git -C "$workspace_main" reset --hard --quiet origin/main 2>/dev/null || true

    # Extract every `path:line` and `path:line-line` token. Limited to
    # source-file extensions we actually have, anchored to project-shaped
    # paths (src/, third_party/, tests/, docs/, CMakeLists, plus loose
    # filename:line). Avoids matching code-block line annotations like
    # `at line 42` or URLs.
    local citations
    citations=$(echo "$comment_body" | grep -oE '\b[A-Za-z0-9_./-]+\.(cpp|cc|cxx|c|h|hpp|hh|py|js|ts|md|sh|yml|yaml|json|qrc|cmake|cs|txt):[0-9]+(-[0-9]+)?\b' | sort -u)
    [ -z "$citations" ] && return 0

    local resolved=0 unresolved=0 unresolved_block=""
    while IFS= read -r citation; do
        [ -z "$citation" ] && continue
        local path lines start_line end_line file_lines
        path="${citation%:*}"
        lines="${citation#*:}"
        start_line="${lines%%-*}"
        end_line="${lines##*-}"
        # FlexLib citations point at the upstream C# reference dir, not
        # the AetherSDR workspace — accept them as "external evidence".
        if [[ "$path" == FlexLib/* ]] || [[ "$path" == */FlexLib/* ]] || [[ "$path" == *.cs ]]; then
            resolved=$((resolved + 1))
            continue
        fi
        if [ -f "$workspace_main/$path" ]; then
            file_lines=$(wc -l < "$workspace_main/$path" 2>/dev/null | tr -d ' ')
            file_lines=${file_lines:-0}
            if [ "$start_line" -le "$file_lines" ] && [ "$end_line" -le "$file_lines" ]; then
                resolved=$((resolved + 1))
                continue
            fi
            unresolved=$((unresolved + 1))
            unresolved_block="${unresolved_block}| \`${citation}\` | line out of range (file has ${file_lines} lines) |"$'\n'
        else
            unresolved=$((unresolved + 1))
            unresolved_block="${unresolved_block}| \`${citation}\` | file not found in workspace |"$'\n'
        fi
    done <<< "$citations"

    log "CITATION_CHECK: #${number} — ${resolved} resolved, ${unresolved} unresolved"
    [ "$unresolved" -eq 0 ] && return 0

    # PATCH the comment to append an unresolved-citations footnote.
    # Non-blocking — failures here are logged but never fail the run.
    local footnote
    footnote=$(printf '\n\n---\n\n<sub>📍 Citation health check (Foundry Constitution Principle I): **%d resolved, %d unresolved** against `%s` at origin/main.</sub>\n\n<details><summary>Unresolved citations (%d)</summary>\n\n| Citation | Reason |\n|---|---|\n%s\n</details>' \
        "$resolved" "$unresolved" "$workspace_main" "$unresolved" "$unresolved_block")
    local new_body
    new_body=$(jq -n --arg b "${comment_body}${footnote}" '{body: $b}')
    if github_api_body PATCH "/repos/${REPO}/issues/comments/${comment_id}" "$token" "$new_body" > /dev/null 2>&1; then
        log "CITATION_CHECK: appended footnote to comment ${comment_id}"
    else
        log "CITATION_CHECK: failed to PATCH comment ${comment_id} (non-blocking, run continues)"
    fi
    return 0
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
# Heartbeat-based liveness limits — replaces the older fixed wall-clock
# CLAUDE_TIMEOUT. A Claude process is "alive" as long as the active
# session JSONL (where each tool_use / tool_result / text block is
# appended) has been written within the last CLAUDE_MAX_IDLE seconds.
# CLAUDE_HARD_CEILING is the absolute upper bound — productive runs
# still get bounded, runaway loops that produce output indefinitely
# are still stopped.
#
# Aligns with Foundry-security-spec Principle III ("Liveness By
# Heartbeat, Never By Clock"). The prior wall-clock kill at 600s/
# 1800s murdered productive runs whose work spilled past the timeout
# — see trace 50f9d8d0 on #2624, which was actively making tool calls
# at the 18-min mark when the old watchdog SIGTERM'd it. Heartbeat
# liveness lets that exact run keep going.
#
# CLAUDE_TIMEOUT is retained as a backward-compat alias for
# CLAUDE_HARD_CEILING so existing env overrides still take effect.
CLAUDE_MAX_IDLE="${CLAUDE_MAX_IDLE:-180}"           # 3 min of silence = stale
CLAUDE_HARD_CEILING="${CLAUDE_HARD_CEILING:-${CLAUDE_TIMEOUT:-3600}}"  # 60 min absolute

# Default tool surface — used by all skills that legitimately write code
# (triage, continue-triage, implement-fix, review-pr, explain-ci).
CLAUDE_ALLOWED_TOOLS_DEFAULT="Read,Glob,Grep,Edit,Write,Bash(git add *),Bash(git commit *),Bash(git push *),Bash(git diff *),Bash(git log *),Bash(git status),Bash(git checkout *),Bash(ls *),Bash(head *),Bash(tail *),mcp__aetherclaude-github__*,mcp__codegraph__*"

# @Mention tool surface — strictly conversational. No code mutation, no git
# write, no PR creation, no label management. Claude can read code and
# explain, propose fixes inline in a comment, and post that comment. Any
# actual implementation must come through the eligibility-label path,
# which routes to implement-fix with the full default tool surface.
# Lesson learned: trace 91e3b290 showed an @Mention going off-script
# to push a branch and 422 itself trying to open a PR.
CLAUDE_ALLOWED_TOOLS_MENTION="Read,Glob,Grep,Bash(git log *),Bash(git status),Bash(git diff *),Bash(git branch *),Bash(ls *),Bash(head *),Bash(tail *),mcp__aetherclaude-github__read_issue,mcp__aetherclaude-github__list_issue_comments,mcp__aetherclaude-github__comment_on_issue,mcp__aetherclaude-github__search_issues"

run_claude() {
    local prompt="$1" logfile="$2"
    # Optional 3rd arg overrides the allowedTools list. Defaults to the
    # full code-writing surface for backward compat with all existing
    # callers; the @Mention path passes CLAUDE_ALLOWED_TOOLS_MENTION.
    local allowed_tools="${3:-$CLAUDE_ALLOWED_TOOLS_DEFAULT}"
    local claude_pid watchdog_pid
    local exit_code=0

    # Mint a deterministic session ID and pass it to `claude --session-id`
    # so the resulting JSONL lands at a path WE know in advance:
    #   $session_dir/$claude_session_id.jsonl
    # Two payoffs:
    #   1. Heartbeat watchdog (below) targets the exact file instead of
    #      `ls -t | head -1`, which mis-picks an unrelated session's JSONL
    #      when concurrent runs share a cwd.
    #   2. `bot-cost.py wrap` reads usage scoped to THIS session only
    #      (main JSONL + its subagents/), so a post can't be charged for
    #      tokens burned by a sibling agent's in-flight work. Exported
    #      to LAST_CLAUDE_SESSION_ID so post_bot_comment can forward it.
    local claude_session_id
    claude_session_id=$(uuidgen | tr 'A-Z' 'a-z')
    export LAST_CLAUDE_SESSION_ID="$claude_session_id"
    # Up to 3 attempts (1 initial + 2 retries) on transient Anthropic API
    # socket drops. Trace 42301770 (#2624) hit this: Claude was 7 min
    # into legitimate implement work when the API socket closed mid-
    # stream, leaving a 135-byte log with just
    # "API Error: The socket connection was closed unexpectedly".
    # Not a code/config issue, not a firewall block — just transient
    # network flakiness. Auto-retry instead of marking the issue
    # 'failed' on the first hiccup. Other errors (auth, validation,
    # timeout) still fail immediately on the first attempt.
    local max_attempts=3
    local attempt=1

    while [ "$attempt" -le "$max_attempts" ]; do
        if [ "$attempt" -gt 1 ]; then
            local backoff=$((attempt * 5))
            log "Retrying Claude (attempt $attempt/$max_attempts) after ${backoff}s — previous attempt hit a socket-close error"
            sleep "$backoff"
        fi
        # Marker delimits per-attempt log content for the retry-trigger
        # grep below; without it, finding "socket connection was closed"
        # in attempt 2's log could be a stale match from attempt 1.
        echo "--- ATTEMPT $attempt of $max_attempts at $(date "+%Y-%m-%dT%H:%M:%S") ---" >> "$logfile"

        # Run claude in the caller's cwd. The orch chooses the right
        # working directory per case: $WORKSPACE for triage/welcome,
        # /tmp/aetherclaude/issue-N for IMPLEMENT. We do not force a cd.
        env \
            -u GH_TOKEN -u GITHUB_TOKEN -u GH_APP_TOKEN -u GITHUB_APP_ID \
            HOME="$HOME" PATH="$PATH" \
            HTTPS_PROXY="$HTTPS_PROXY" HTTP_PROXY="$HTTP_PROXY" NO_PROXY="$NO_PROXY" \
            claude -p "$prompt" \
                --model claude-fable-5 \
                --session-id "$claude_session_id" \
                --setting-sources user \
                --strict-mcp-config \
                --permission-mode bypassPermissions \
                --allowedTools "$allowed_tools" \
                --disallowedTools "Bash(sudo *),Bash(curl *),Bash(wget *),Bash(rm -rf *),Bash(ssh *),Bash(scp *),Bash(nc *),Bash(ncat *),Bash(dd *),Bash(mount *),Bash(chmod *),Bash(chown *),Bash(chsh *),Bash(passwd *),Bash(brew *),Bash(npm *),Bash(pip *),Bash(nft *),Bash(systemctl *),Bash(cat /Users/aetherclaude/.env),Bash(cat /Users/aetherclaude/.git-credentials),Bash(cat /Users/aetherclaude/.github-app-key.pem),Bash(echo \$*),Bash(env),Bash(printenv),Bash(set),WebFetch,WebSearch,Agent" \
                --mcp-config /Users/aetherclaude/.claude/mcp-servers.json \
            >> "$logfile" 2>&1 &
        claude_pid=$!

        # Heartbeat watchdog (Foundry Principle III). Polls the active
        # Claude session JSONL's mtime — Claude appends to it on every
        # tool_use/tool_result/text block, so an mtime within the last
        # CLAUDE_MAX_IDLE seconds is proof of life. Kill only when truly
        # stale. Hard ceiling at CLAUDE_HARD_CEILING catches runaway
        # loops that produce output indefinitely.
        #
        # JSONL path: claude encodes cwd-with-slashes-replaced-by-dashes
        # into ~/.claude/projects/. `pwd -P` resolves /tmp -> /private/tmp.
        local session_dir="/Users/aetherclaude/.claude/projects/$(pwd -P | sed 's|/|-|g')"
        local hb_start=$(date +%s)
        (
            while kill -0 "$claude_pid" 2>/dev/null; do
                sleep 10
                local hb_now=$(date +%s)
                local hb_elapsed=$((hb_now - hb_start))

                # Hard ceiling — bound the worst case regardless of liveness.
                if [ "$hb_elapsed" -gt "$CLAUDE_HARD_CEILING" ]; then
                    log "CEILING: Claude Code hit hard ceiling ${CLAUDE_HARD_CEILING}s (PID $claude_pid), killing"
                    kill -TERM "$claude_pid" 2>/dev/null
                    sleep 5
                    kill -9 "$claude_pid" 2>/dev/null
                    break
                fi

                # 60s startup grace — give Claude time to write its first
                # JSONL entry before we judge it stale.
                [ "$hb_elapsed" -lt 60 ] && continue

                # Target THIS run's JSONL by deterministic session ID
                # (passed to `claude --session-id` above). The old
                # `ls -t | head -1` heuristic picked the wrong file
                # whenever a concurrent run shared the same cwd —
                # could kill a healthy claude based on a sibling's
                # stalled heartbeat.
                local active_jsonl="$session_dir/$claude_session_id.jsonl"
                if [ ! -f "$active_jsonl" ]; then
                    # No JSONL yet despite 60s — keep waiting; claude
                    # may not have written its first entry. Don't kill
                    # on absence alone.
                    continue
                fi

                local last_mtime
                last_mtime=$(stat -f %m "$active_jsonl" 2>/dev/null || echo "$hb_now")
                local idle=$((hb_now - last_mtime))
                if [ "$idle" -gt "$CLAUDE_MAX_IDLE" ]; then
                    log "STALE: Claude Code no tool activity for ${idle}s (PID $claude_pid, elapsed ${hb_elapsed}s), killing"
                    kill -TERM "$claude_pid" 2>/dev/null
                    sleep 5
                    kill -9 "$claude_pid" 2>/dev/null
                    break
                fi
            done
        ) &
        watchdog_pid=$!

        wait "$claude_pid"
        exit_code=$?

        # Clean up watchdog. Both `|| true` guards are LOAD-BEARING: the
        # script runs under `set -euo pipefail`, and the watchdog subshell
        # often races us — if it noticed claude exit on its 10s heartbeat
        # tick BEFORE we get here, the subshell exited cleanly on its own
        # and our `kill` returns 1 (no such process), tripping set -e
        # and killing the orchestrator silently. (Verified the silent
        # kill empirically on macOS bash 5.x: a `kill PID 2>/dev/null` of
        # a dead PID exits the script with no log, no error, just trap-
        # EXIT cleanup of the lockfile.) Same for `wait` — if the
        # watchdog exited non-zero (e.g., killed by SIGTERM = 143, or
        # exited because its `kill -0` loop check returned 1), wait
        # surfaces that exit code and set -e kills us. Issue #2689's
        # two failed implements (traces 10cc8900 and 2a27e480) both hit
        # this — Claude completed, watchdog won the race, kill returned
        # 1, orchestrator died at the kill line WITHOUT logging the
        # commit_count check or the "no commits" warning.
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true

        # Success → done.
        if [ "$exit_code" -eq 0 ]; then
            return 0
        fi

        # Watchdog kill (SIGTERM / SIGKILL — heartbeat-stale or hard-
        # ceiling) → don't retry. The watchdog only fires on genuine
        # silence or absolute upper bound; retrying would hit the same
        # condition immediately. Caller sees the explicit STALE: /
        # CEILING: log line for the diagnosis.
        if [ "$exit_code" -eq 143 ] || [ "$exit_code" -eq 137 ]; then
            log "ERROR: Claude Code was killed by watchdog (exit $exit_code)"
            return 1
        fi

        # Retryable? Check only the log content from THIS attempt — awk
        # splits on the ATTEMPT marker, prints the last record. Patterns
        # cover Node's fetch errors plus Anthropic SDK's own wording.
        local last_attempt_log
        last_attempt_log=$(awk 'BEGIN{RS=""} /--- ATTEMPT [0-9]+ /{out=$0} END{print out}' "$logfile" 2>/dev/null)
        if echo "$last_attempt_log" | grep -qE "socket connection was closed|ECONNRESET|fetch failed|terminated.*ENOTFOUND|stream.*aborted"; then
            log "Claude Code attempt $attempt/$max_attempts failed with transient network error (exit $exit_code) — will retry"
            attempt=$((attempt + 1))
            continue
        fi

        # Non-retryable error (auth, MCP validation, real exception, etc.)
        return "$exit_code"
    done

    log "ERROR: Claude Code failed after $max_attempts attempts (last exit: $exit_code, transient network errors throughout)"
    return "$exit_code"
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

# Read the `goal:` field from a skill file's YAML frontmatter, if present.
# Returns empty string when absent. Used by render_skill_full to optionally
# wrap the rendered prompt with `/goal <condition>` so Claude iterates
# until the per-skill completion condition is met (Claude Code v2.1.139+).
# Frontmatter is a YAML block between the two `---` markers at the top
# of the file. We extract the line `goal: <value>` from it; quoted/
# multiline goals not supported (kept simple — single line is fine for
# our skills).
read_skill_goal() {
    local skill_name="$1"
    local skill_file="/Users/aetherclaude/skills/${skill_name}.md"
    [ -f "$skill_file" ] || { echo ""; return 0; }
    # Portable extraction (works on BSD sed / macOS — the orchestrator's
    # production env — as well as GNU sed). Prior implementation used
    # GNU-extended one-line range syntax `1{...};1,/.../{...}` which
    # BSD sed rejects with "extra characters at the end of p command",
    # silently returning empty so the /goal prefix was never emitted.
    # `goal:` only appears in the YAML frontmatter (skill bodies use
    # ${VAR} placeholders, not key:value lines), so a simple grep is
    # safe without an explicit frontmatter range.
    grep -m1 '^goal:[[:space:]]' "$skill_file" 2>/dev/null \
        | sed -E 's/^goal:[[:space:]]+//; s/^["'"'"']//; s/["'"'"']$//'
}

# Render a skill prompt with `/goal` framing when the skill defines one.
# Takes the skill NAME (not template content), looks up its `goal:`
# frontmatter, substitutes ${VAR_NAME} placeholders in both the goal
# string and the body, and emits:
#   /goal <substituted-goal>
#
#   <substituted-body>
# When no goal is defined, emits the body unchanged — call site can
# migrate from render_skill incrementally.
#
# Usage: prompt=$(render_skill_full "review-pr" "PR_NUMBER" "$pr_number" ...)
render_skill_full() {
    local skill_name="$1"; shift
    local body goal
    body=$(load_skill "$skill_name") || return 1
    goal=$(read_skill_goal "$skill_name")
    # Substitute ${VAR_NAME} placeholders in BOTH goal and body. Same
    # arg-pair format as render_skill — single pass over the pairs.
    local saved_args=("$@")
    while [ $# -ge 2 ]; do
        local var="$1" val="$2"
        body="${body//\$\{${var}\}/${val}}"
        goal="${goal//\$\{${var}\}/${val}}"
        shift 2
    done
    if [ -n "$goal" ]; then
        printf '/goal %s\n\n%s\n' "$goal" "$body"
    else
        printf '%s\n' "$body"
    fi
}

# --- Attachment download helper ---
# Pre-fetches every GitHub-hosted image / log / file referenced in
# the issue body or comments to a local dir under the working tree,
# so Claude (sandboxed; no WebFetch) can Read them via the
# filesystem. Returns a formatted prompt-section on stdout (empty
# string if no attachments). dest_dir defaults to ./attachments
# under cwd.
prepare_attachments() {
    local issue_number="$1" issue_body="$2" issue_comments="$3" dest_root="${4:-$WORKSPACE}"
    local dest="${dest_root}/attachments-${issue_number}"
    local mapping
    # Concatenate body + comments and pipe through the helper. The
    # helper writes <local_path>\t<url> per line on stdout; per-file
    # status on stderr (which we let through to the orchestrator log).
    mapping=$(printf '%s\n\n%s\n' "$issue_body" "$issue_comments" \
        | GH_TOKEN="$GH_TOKEN" GITHUB_TOKEN="$GITHUB_TOKEN" \
          /Users/Shared/aetherclaude/bin/download-issue-attachments.py "$dest" 2>>"$LOGDIR/orchestrator.log")
    if [ -z "$mapping" ]; then
        echo ""
        return 0
    fi
    # Build a markdown section the skill prompt can splice in.
    {
        echo "## Local attachments (downloaded for you)"
        echo ""
        echo "Each issue attachment was fetched to a local file you can"
        echo "Read. URLs in the issue body / comments map to:"
        echo ""
        while IFS=$'\t' read -r local_path url; do
            [ -z "$local_path" ] && continue
            echo "- \`${local_path}\` ← ${url}"
        done <<< "$mapping"
    }
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

        local welcome_kind="issue_comment"
        [ -n "$is_pr" ] && welcome_kind="pr_review"
        post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
            "{\"body\":\"${body}\"}" "$welcome_kind" > /dev/null 2>&1
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

        # ── Skip BRQ for "code-fix" bugs ────────────────────────────────
        # A bug report that already identifies the file:line, proposes a
        # fix in code, or cites a security/audit pass doesn't need radio
        # model / firmware / steps to reproduce — those are runtime-
        # context fields for behavioral bugs. Asking for them on a
        # well-scoped code-quality finding is noise and stalls the issue.
        # Three high-precision signals; ANY hit → skip:
        #   1. file:line reference (src/foo.cpp:123 or :123-456)
        #   2. proposed-fix section heading
        #   3. security/audit pass reference
        # See issue #2957 (atomic-rename TOCTOU on log symlink) — author
        # gave file:line + code-block mitigation + audit memo cite; BRQ
        # asked for radio model anyway.
        if echo "$body" | grep -qEi '\b[a-z0-9_/.-]+\.(cpp|cc|cxx|c|h|hpp|py|js|ts|sh|md|qrc|yml|yaml|json):[0-9]+(-[0-9]+)?\b' \
            || echo "$body" | grep -qEi '^##? *(mitigation|proposed fix|proposed solution|the fix|fix:)\b' \
            || echo "$body" | grep -qEi '\b(audit (finding|memo|pass)|security pass|security audit)\b'; then
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

        post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
            "{\"body\":\"${comment}\"}" issue_comment > /dev/null 2>&1

        # Mark as waiting so skill_process_issues doesn't triage/implement while we await user reply
        add_label "$number" "awaiting-response" "$token"
        record_action "$number" "needs_info" "waiting" "success" "Missing ${#missing[@]} required fields"
        set_state "issue_${number}_state" "waiting"
    done
}

# =====================================================================
# Review one PR: fetch diff/files/reviewer-context, render the review-pr
# skill, and run Claude to post the review. Shared by skill_review_prs
# (the CI-gated scan over open PRs) and the @mention path (an explicit
# "@AetherClaude review this PR" request). Gating (draft/CI/already-
# reviewed) is the caller's responsibility — this just performs the
# review. Returns non-zero if the Claude run fails.
# =====================================================================
review_single_pr() {
    local pr_number="$1" pr_title="$2" pr_author="$3" token="$4"

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

    # render_skill_full prepends `/goal <condition>` from the skill
    # file's frontmatter so Claude keeps iterating until the review
    # is actually posted (Claude Code 2.1.139+ feature). Per-skill
    # rollout — other skills still use render_skill until each one
    # is verified with /goal.
    local prompt
    prompt=$(render_skill_full "review-pr" "PR_NUMBER" "$pr_number" "PR_TITLE" "$pr_title" "PR_AUTHOR" "$pr_author" "PR_FILES" "$pr_files" "PR_DIFF" "$sanitized_diff" "COPILOT_COMMENTS" "$copilot_comments")

    cd "$WORKSPACE"
    run_claude "$prompt" "$review_log" || {
        log "ERROR: PR review failed for #${pr_number}"
        return 1
    }
    log "Reviewed PR #${pr_number}"
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

        # Skip: self bot PRs, drafts. Maintainer PRs ARE reviewed —
        # same flow as community PRs. Routine maintainer GitHub
        # activity is filtered at the webhook layer; once a PR is
        # accepted there, this skill runs uniformly.
        [ "$pr_author" = "AetherClaude" ] && continue
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

        review_single_pr "$pr_number" "$pr_title" "$pr_author" "$token" || continue
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

        # Skip self bot PRs; maintainer PRs get CI-failure explanations
        # too (same as community PRs).
        [ "$pr_author" = "AetherClaude" ] && continue

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
body = json.dumps({'query': 'query { repository(owner: \"aethersdr\", name: \"AetherSDR\") { discussions(first: 10, orderBy: {field: CREATED_AT, direction: DESC}) { nodes { id number title author { login } category { name } comments { totalCount } locked createdAt } } } }'}).encode()
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

    # Webhook-only mode: every orch is triggered by a webhook for a
    # specific issue/PR/disc, identified by LOCK_KEY. Scope the Issue
    # Pipeline to just that issue. If #N is in the Phase-1 candidate
    # list, narrow to it. If #N is NOT in the list (older than 24h,
    # missing aetherclaude-eligible, etc.), fetch it directly and
    # check whether the maintainer-review-without-eligible filter
    # would drop it; only then do we give up. Critically, we NEVER
    # fall back to processing OTHER issues — a webhook for #N must
    # not surprise the maintainer by implementing #M.
    if [[ "$LOCK_KEY" =~ ^issue-([0-9]+)$ ]]; then
        local trigger_num="${BASH_REMATCH[1]}"
        local scoped
        scoped=$(echo "$all_issues" | jq --argjson n "$trigger_num" '[.[] | select(.number == $n)]')
        local scoped_total
        scoped_total=$(echo "$scoped" | jq '. | length')
        if [ "$scoped_total" -eq 0 ]; then
            # Not in the union of (recent, labeled, assigned). Fetch it
            # directly so we can decide whether to process it or skip.
            local direct
            direct=$(github_api GET "/repos/${REPO}/issues/${trigger_num}" "$token")
            if echo "$direct" | jq -e '.number' >/dev/null 2>&1 \
               && [ "$(echo "$direct" | jq -r '.pull_request // empty')" = "" ]; then
                # Apply the same maintainer-review-without-eligible filter
                # as the Phase-1 jq pipeline.
                local passes_filter
                passes_filter=$(echo "$direct" | jq '
                    ([.labels[].name] | any(. == "maintainer-review") | not)
                    or ([.labels[].name] | any(. == "aetherclaude-eligible"))')
                if [ "$passes_filter" = "true" ]; then
                    scoped=$(echo "$direct" | jq '[.]')
                    scoped_total=1
                    log "Scoped Issue Pipeline to triggering issue #${trigger_num} (direct fetch)"
                fi
            fi
        else
            log "Scoped Issue Pipeline to triggering issue #${trigger_num}"
        fi
        # Replace all_issues with whatever scoping resolved to (may be
        # empty if #N is filtered out — that means we run no issues,
        # not that we pivot to other candidates).
        all_issues="$scoped"
        total="$scoped_total"
        if [ "$total" -eq 0 ]; then
            log "Issue Pipeline: triggering issue #${trigger_num} not eligible, skipping"
        fi
    fi

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
        any_pr=$(github_api GET "/repos/${REPO}/pulls?head=aethersdr:${branch}&state=all" "$token" | jq '. | length' 2>/dev/null || echo 0)
        local any_pr_v2
        any_pr_v2=$(github_api GET "/repos/${REPO}/pulls?head=aethersdr:${branch}-v2&state=all" "$token" | jq '. | length' 2>/dev/null || echo 0)
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

        # State override A: maintainer applied 'maintainer-review' to a
        # 'waiting' issue. The waiting branch only advances on a NEW user
        # comment, so an issue that has all the info we need but no user
        # reply (because the maintainer themselves answered, or because
        # the triage questions weren't blocking after all) would otherwise
        # be stuck in 'waiting' forever. Applying the maintainer-review
        # label is the maintainer's explicit "I have enough info, skip
        # waiting for user reply" signal. Advance to maintainer-review
        # so override B below can fire if aetherclaude-eligible is also
        # present.
        if [ "$issue_state" = "waiting" ] && \
           echo "$issue_data" | jq -e '[.labels[].name] | any(. == "maintainer-review")' >/dev/null; then
            log "Issue #${number} — maintainer applied 'maintainer-review' while waiting; advancing state"
            record_action "$number" "waiting" "maintainer-review" "success" "Maintainer applied maintainer-review label"
            issue_state="maintainer-review"
            set_state "issue_${number}_state" "maintainer-review"
        fi

        # State override B: maintainer-review issue gets the
        # 'aetherclaude-eligible' label — transition to implement.
        # That label is the maintainer's authorization to write the fix.
        if [ "$issue_state" = "maintainer-review" ] && \
           echo "$issue_data" | jq -e '[.labels[].name] | any(. == "aetherclaude-eligible")' >/dev/null; then
            log "Issue #${number} — maintainer added aetherclaude-eligible, transitioning to implement"
            record_action "$number" "maintainer-review" "implement" "success" "aetherclaude-eligible label added"
            issue_state="implement"
            set_state "issue_${number}_state" "implement"
        fi

        # State override C: failed issue gets 'aetherclaude-eligible' re-applied —
        # transition to implement. Treating the label re-apply as a tacit
        # "please retry" from the maintainer, distinct from any other webhook
        # (comment, push, …) on the same issue. The conditions ensure ONLY a
        # label-add webhook for THIS specific label fires the retry — a stray
        # comment on a failed issue, or another label being added/removed,
        # MUST NOT bypass the parked state.
        #
        # Typical use: a previous implement run died on a transient Anthropic
        # socket close or the like. Maintainer toggles aetherclaude-eligible
        # off-then-on; the re-add fires this override; the case below picks
        # up `implement` and runs a fresh attempt.
        if [ "$issue_state" = "failed" ] \
           && [ "$TRIGGER_EVENT" = "issues" ] \
           && [ "$TRIGGER_ACTION" = "labeled" ] \
           && [ "$TRIGGER_LABEL" = "aetherclaude-eligible" ] \
           && echo "$issue_data" | jq -e '[.labels[].name] | any(. == "aetherclaude-eligible")' >/dev/null; then
            log "Issue #${number} — maintainer re-applied aetherclaude-eligible after failure; retrying"
            record_action "$number" "retry_requested" "implement" "success" "Maintainer re-applied aetherclaude-eligible after failed run"
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
            post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
                "{\"body\":\"Thanks for filing this. This issue involves CI/CD workflows, build infrastructure, or release packaging — that is outside what I can help with, as I am restricted to source code changes in \`src/\` and \`docs/\`.\n\nJeremy will need to handle this one directly.\n\n— AetherClaude (automated agent for AetherSDR)\"}" \
                issue_comment > /dev/null 2>&1
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
                post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
                    "{\"body\":\"Thanks for reaching out, but I don't have enough information here to investigate.\\n\\n**Fastest path to a fix:** open AetherSDR and go to **Help → Support → File an Issue**. This uses the AI-assisted bug report tool that auto-collects your OS, AetherSDR version, radio model and firmware, and a log bundle, then opens a pre-filled issue template. Just describe what happened and what you expected, and submit.\\n\\nI'm closing this issue — please file a new one (or reopen this one) with those details and I'll take another look.\\n\\n— AetherClaude (automated agent for AetherSDR)\"}" \
                    issue_comment > /dev/null 2>&1
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

            # Pre-download any GitHub-hosted attachments so Claude can
            # Read them locally — its sandbox blocks WebFetch outbound.
            local attachments_section
            attachments_section=$(prepare_attachments "$number" "$issue_body" "$issue_comments" "$WORKSPACE")

            local triage_log="$LOGDIR/triage-${number}-$(date +%Y%m%d-%H%M%S).log"

            local skill_template
            skill_template=$(load_skill "triage-issue")
            local prompt
            prompt=$(render_skill "$skill_template"                 "ISSUE_NUMBER" "$number"                 "ISSUE_TITLE" "$title"                 "ISSUE_BODY" "$issue_body"                 "ISSUE_COMMENTS" "$issue_comments"                 "ATTACHMENTS" "$attachments_section"                 "WORKSPACE" "$WORKSPACE")

            cd "$WORKSPACE"
            run_claude "$prompt" "$triage_log" || {
                log "ERROR: Triage failed for issue #${number}"
                record_action "$number" "triage" "failed" "failure" "Claude Code exited non-zero"
                set_state "issue_${number}_state" "failed"
                break
            }

            # Citation-resolution check (Foundry Principle I, informational
            # form). Runs after triage but before the state branching; uses
            # the same workspace clone the rest of the orch already keeps
            # fresh. Never fails the run — if anything is unresolved it
            # gets a footnote on the comment, not a state regression.
            check_citations "$number" "$token" || true

            # Check if we asked questions (look for ? in our comment).
            # `|| true` on the bare assignment is critical: this fetches
            # from the GitHub API right after the citation-check PATCH,
            # and any transient API blip (rate limit, brief 5xx, jq
            # parse fail on a non-JSON error body) trips set -e and
            # silently kills the whole orchestrator. Saw this pattern
            # caught by the FATAL trap on traces a49338d0 (#2846),
            # c0c86fc8 (#2847), 4dd4f11e (#2841), and others —
            # TRIAGE → CITATION_CHECK → footnote → silent death,
            # state never persisted, claude-active label never removed.
            # Falling back to empty string is safe: the question-mark
            # check below treats empty as "no questions asked".
            local our_comment
            our_comment=$(github_api GET "/repos/${REPO}/issues/${number}/comments?per_page=5" "$token" | \
                jq -r '[.[] | select(.user.login == "aethersdr-agent[bot]")] | last | .body // ""' \
                2>/dev/null || echo "")

            if echo "$our_comment" | grep -q "?"; then
                record_action "$number" "triage" "waiting" "success" "Asked clarifying question"
                set_state "issue_${number}_state" "waiting"
                log "Issue #${number} — asked questions, moving to WAITING"
                remove_label "$number" "claude-active" "$token"
                add_label "$number" "awaiting-response" "$token"
            else
                # Triage complete with no questions — hand off to maintainer
                # for explicit authorization. Implementation MUST go through
                # 'maintainer-review' so that a maintainer adding
                # 'aetherclaude-eligible' mid-triage doesn't skip ahead, and
                # so the maintainer has a chance to review/decline before
                # code is written. If they've already added the label by
                # now, the next loop iteration (case 'maintainer-review')
                # will pick that up and advance to implement in this same
                # orch run.
                record_action "$number" "triage" "maintainer-review" "success" "Triage complete, awaiting maintainer authorization"
                set_state "issue_${number}_state" "maintainer-review"
                add_label "$number" "maintainer-review" "$token"
                remove_label "$number" "claude-active" "$token"
                remove_label "$number" "awaiting-response" "$token"
                log "Issue #${number} — triage complete, moving to MAINTAINER-REVIEW"
            fi
            set_state "issue_${number}_last_action" "$(date "+%Y-%m-%dT%H:%M:%S")"
            processed=$((processed + 1))
            ;;

        waiting)
            # ---------------------------------------------------------
            # STATE: WAITING — Check for user replies (or mid-orch
            # maintainer authorization labels)
            # ---------------------------------------------------------
            # Maintainer-authorization check: if the maintainer added
            # 'maintainer-review' or 'aetherclaude-eligible' after we
            # entered waiting (or even mid-triage, before the orch
            # finished asking the clarifying question), advance state
            # so the loop continues through maintainer-review → implement
            # in the same run. Override A at lines 864-879 only catches
            # this when state was ALREADY 'waiting' before the orch
            # started; this catches the mid-orch case. Fresh GET because
            # cached $issue_data is from the Phase-1 listing.
            local waiting_labels
            waiting_labels=$(github_api GET "/repos/${REPO}/issues/${number}" "$token" | jq -r '[.labels[].name]')
            if echo "$waiting_labels" | jq -e '
                    any(. == "maintainer-review")
                    or any(. == "aetherclaude-eligible")
                ' >/dev/null; then
                log "Issue #${number} — maintainer authorization label present in waiting, advancing → maintainer-review"
                record_action "$number" "waiting" "maintainer-review" "success" "Maintainer label applied mid-orch"
                set_state "issue_${number}_state" "maintainer-review"
                issue_state="maintainer-review"
                remove_label "$number" "awaiting-response" "$token"
                # Don't break or processed++. Falling out of the case
                # naturally lets the state-machine loop re-read state,
                # see the change, and enter the maintainer-review case
                # on the next iteration (which advances to implement if
                # aetherclaude-eligible is set).
            else

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
                local attachments_section
                attachments_section=$(prepare_attachments "$number" "$issue_body" "$issue_comments" "$WORKSPACE")

                local triage_log="$LOGDIR/continue-triage-${number}-$(date +%Y%m%d-%H%M%S).log"
                local skill_template
                skill_template=$(load_skill "continue-triage")
                local prompt
                prompt=$(render_skill "$skill_template"                     "ISSUE_NUMBER" "$number"                     "ISSUE_TITLE" "$title"                     "ISSUE_BODY" "$issue_body"                     "ISSUE_COMMENTS" "$issue_comments"                     "ATTACHMENTS" "$attachments_section")

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
                    post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
                        "{\"body\":\"Thanks for the report. Without the details requested above, I'm unable to reproduce this issue. Closing for now — please feel free to reopen with the requested information (OS, AetherSDR version, radio model and firmware, steps to reproduce) and we'll take another look.\\n\\n— AetherClaude (automated agent for AetherSDR)\"}" \
                        issue_comment > /dev/null 2>&1
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
            fi   # close the maintainer-label-override else
            # Waiting doesn't count as a processed action
            ;;

        maintainer-review)
            # STATE: MAINTAINER-REVIEW — triage and follow-ups have
            # completed; the issue is parked here until a maintainer
            # explicitly authorizes implementation by adding the
            # 'aetherclaude-eligible' label.
            #
            # Re-fetch labels (not the cached $issue_data ones, which
            # are from this orch's initial listing). This is what
            # closes the mid-run race: if the maintainer applied
            # 'aetherclaude-eligible' while we were still triaging,
            # this state is the first moment we're entitled to act on
            # it, and the fresh GET picks it up. If the label isn't
            # there yet, break out and wait for the next webhook
            # (maintainer's label-add).
            local mr_labels
            mr_labels=$(github_api GET "/repos/${REPO}/issues/${number}" "$token" | jq -r '[.labels[].name]')
            if echo "$mr_labels" | jq -e 'any(. == "aetherclaude-eligible")' >/dev/null; then
                log "Issue #${number} — maintainer authorized (aetherclaude-eligible present), moving to IMPLEMENT"
                record_action "$number" "maintainer-review" "implement" "success" "aetherclaude-eligible label present"
                set_state "issue_${number}_state" "implement"
            else
                log "Issue #${number} — in MAINTAINER-REVIEW, awaiting maintainer to add aetherclaude-eligible"
                processed=$((processed + 1))
                break
            fi
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
            closed_prs=$(github_api GET "/repos/${REPO}/pulls?head=aethersdr:${branch}&state=closed" "$token")
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

            # Pre-download attachments into the worktree so the
            # implement pass can Read screenshots / log files / etc.
            # Claude's sandbox blocks WebFetch outbound.
            local attachments_section
            attachments_section=$(prepare_attachments "$number" "$issue_body" "$issue_comments" "$WORKTREE")

            local skill_template
            skill_template=$(load_skill "implement-fix")
            local prompt
            prompt=$(render_skill "$skill_template" "ISSUE_NUMBER" "$number" "ISSUE_TITLE" "$title" "ISSUE_BODY" "$issue_body" "ISSUE_COMMENTS" "$issue_comments" "ATTACHMENTS" "$attachments_section" "RETRY_CONTEXT" "$retry_context" "BRANCH" "$branch" "WORKSPACE" "$WORKTREE")

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
                # Salvage: Claude sometimes exits cleanly after writing files
                # but without running git add/git commit (the `-p` print-mode
                # CLI can interpret post-edit commentary text as a final
                # answer and stop iterating). If the worktree has uncommitted
                # changes, commit them ourselves rather than discard the
                # work. See issue #2721 trace a8126990 — two correct surgical
                # Edits made, then Claude bailed before the commit step.
                if [ -n "$(git -C "$WORKTREE" status --porcelain 2>/dev/null)" ]; then
                    local touched_count touched_files
                    touched_count=$(git -C "$WORKTREE" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
                    # head -3 keeps the log line readable; report the true
                    # count so multi-file changes aren't misrepresented.
                    # Trace 04721520 (#2554) salvaged 15 files but the log
                    # said "[CMakeLists.txt LogManager.cpp LogManager.h]"
                    # — useful sample but misleading without the count.
                    touched_files=$(git -C "$WORKTREE" status --porcelain 2>/dev/null | awk '{print $2}' | head -3 | tr '\n' ' ' | sed 's/ $//')
                    log "Issue #${number} — Claude edited ${touched_count} file(s) [${touched_files}…] but didn't commit; salvaging"
                    git -C "$WORKTREE" \
                        -c user.name="aethersdr-agent[bot]" \
                        -c user.email="aethersdr-agent@users.noreply.github.com" \
                        add -A 2>/dev/null
                    git -C "$WORKTREE" \
                        -c user.name="aethersdr-agent[bot]" \
                        -c user.email="aethersdr-agent@users.noreply.github.com" \
                        commit --quiet -m "Fix #${number} (recovered after Claude Code exited before committing)" 2>/dev/null
                    commit_count=$(git -C "$WORKTREE" log main..HEAD --oneline 2>/dev/null | wc -l)
                fi

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
                    post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
                        "{\"body\":\"Claude here \u2014 I attempted a fix for #${number} but it failed the automated validation gate (changes required files outside my allowed paths or modified protected files).\\n\\nI won't retry until you reply. If you'd like me to try a different approach, let me know.\\n\\n73, Jeremy KK7GWY \\u0026 Claude (AI dev partner)\"}" \
                        issue_comment > /dev/null 2>&1 || true
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
            local commit_result commit_exit
            # `|| true` is LOAD-BEARING under `set -euo pipefail`. The
            # bare `var=$(node …)` form propagates the substitution's
            # exit code; if commit-signed.js exits non-zero for ANY
            # reason — including post-success conditions like an unhandled
            # warning, a deprecated-API exit, or a network blip on the
            # auto-merge call — set -e silently kills the orchestrator
            # right here, BEFORE the error-check `if echo "$commit_result"
            # | jq -e '.error'` 4 lines below can run. Capture the exit
            # code separately so failures still surface via the normal
            # flow rather than dying mid-line. Issue #2500 trace fe2b51d0
            # hit exactly this: branch was pushed (GraphQL succeeded),
            # node exited non-zero post-success, orchestrator died at
            # the assignment with no log, no PR created.
            commit_result=$(/opt/homebrew/bin/node /Users/aetherclaude/bin/commit-signed.js \
                "$branch" "$commit_msg" "$WORKTREE" 2>>"$LOGDIR/commit-signed-stderr.log") && commit_exit=0 || commit_exit=$?
            # Note: stderr is now redirected to a sidecar file rather than
            # being merged with stdout via 2>&1. Trace 04721520 (#2554) hit
            # the case where node printed a punycode DeprecationWarning to
            # stderr BEFORE commit-signed.js's success JSON on stdout. With
            # 2>&1 the captured string was "WARNING\n{...json...}" — jq
            # parse fails on the warning line (exit 5), the bare
            # `signed_sha=$(echo "$commit_result" | jq …)` propagated that
            # rc=5, set -e killed the orchestrator post-push, no PR opened.
            # Sidecar file keeps the diagnostic value of stderr without
            # corrupting our JSON parse.
            if [ "$commit_exit" -ne 0 ] || echo "$commit_result" | jq -e '.error' >/dev/null 2>&1; then
                local err
                err=$(echo "$commit_result" | jq -r '.error // empty' 2>/dev/null || echo "")
                [ -z "$err" ] && err="commit-signed.js exited rc=${commit_exit} with no error JSON (see ${LOGDIR}/commit-signed-stderr.log)"
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
            # `|| echo ""` guards the bare assignment from `set -e` if jq
            # can't extract .sha (e.g. node emitted a stderr warning that
            # contaminated stdout in some other future case). The branch
            # is already on the remote at this point, so even if signed_sha
            # is empty we still want to proceed to PR creation.
            signed_sha=$(echo "$commit_result" | jq -r '.sha // empty' 2>/dev/null || echo "")
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
            # Same set-e guard as the commit-signed.js call above —
            # create-pr.js's post-success path also has failure modes
            # (auto-merge enablement) that would otherwise silent-kill
            # the orchestrator at this assignment.
            local pr_result pr_exit
            pr_result=$(/opt/homebrew/bin/node /Users/aetherclaude/bin/create-pr.js "$pr_title" "$branch" "$number" "$pr_body_file" 2>/dev/null) && pr_exit=0 || pr_exit=$?
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
                post_bot_comment "/repos/${REPO}/issues/${number}/comments" "$token" \
                    "$comment_json" issue_comment \
                    > /dev/null 2>&1 || true
                remove_label "$number" "claude-active" "$token"
                # Eligibility was the maintainer's authorization to write
                # the fix; with the PR up that authorization has been
                # consumed. Removing it prevents accidental re-triggering
                # and signals to the maintainer that the implementation
                # phase is done.
                remove_label "$number" "aetherclaude-eligible" "$token"
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
    check_run|workflow_run|check_suite)
        # CI completion drives BOTH:
        #   - explain-ci: act on failures (post a CI-failure explainer)
        #   - review-pr:  act on successes (the PR is now ripe for review)
        # Without review-pr here, the only window to review a PR is the
        # pull_request:opened webhook, which fires ~1s after the PR opens
        # — long before CI has even started. review-pr's CI-status gate
        # at skill_review_prs() then skips with status=pending, and the
        # PR is never re-evaluated. Trace 446b7880 hit this: PR #3012 was
        # opened, scanned, deferred for pending CI, and never picked up
        # again. has_review guard inside the skill prevents double-posts
        # if multiple check_runs in one suite each re-trigger us.
        EVENT_SKILLS="explain-ci,review-pr"
        EVENT_TOOLS="get_ci_run_log,get_check_runs,read_issue,list_open_prs,list_pr_files,get_pr_diff,create_pr_review"
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
# Observability: log WHY the prompt scanner skips when it does. Without
# this, a missing binary or stripped exec bit silently disabled prompt
# inspection from May 7 to May 16 (9 days) because the conditional just
# fell through. The log line lets the dashboard's first-Ring-6 widget
# show "Prompt scanner skipped: <reason>" rather than just zero.
if ! command -v mcp-scanner &>/dev/null; then
    log "Prompt scanner skipped: mcp-scanner not in PATH"
elif [ ! -x /Users/aetherclaude/bin/skills-to-prompts-json.py ]; then
    log "Prompt scanner skipped: skills-to-prompts-json.py not executable"
elif [ -z "${EVENT_SKILLS:-}" ]; then
    log "Prompt scanner skipped: no EVENT_SKILLS for this trigger"
elif true; then
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
        # Fetch the issue/PR once — decides PR-review vs conversational reply.
        mention_data=$(github_api GET "/repos/${REPO}/issues/${MENTION_NUMBER}" "$APP_TOKEN")
        mention_is_pr=$(echo "$mention_data" | jq -r 'if .pull_request then "yes" else "no" end')

        # The most recent human (non-bot) comment is, in practice, the one
        # that @mentioned us. If this is a PR and that comment asks for a
        # review, route to review-pr (full diff + create_pr_review) instead
        # of the conversational mention responder, which has no PR-review
        # capability. Without this, "@AetherClaude review this PR" silently
        # no-ops — it lands in mention-respond, then the issue pipeline skips
        # it because it is a PR.
        mention_latest=$(github_api GET "/repos/${REPO}/issues/${MENTION_NUMBER}/comments?per_page=100" "$APP_TOKEN" \
            | jq -r '[.[] | select(.user.login | test("\\[bot\\]") | not)] | last | .body // ""')

        if [ "$mention_is_pr" = "yes" ] && echo "$mention_latest" | grep -iqE 'review'; then
            log "--- Skill: PR Review (via @mention on PR #${MENTION_NUMBER}) ---"
            mention_title=$(echo "$mention_data" | jq -r '.title // "Unknown"')
            mention_author=$(echo "$mention_data" | jq -r '.user.login // "unknown"')
            # Explicit request — review the named PR directly, bypassing the
            # scan's already-reviewed/CI gates so re-review-on-demand works.
            review_single_pr "$MENTION_NUMBER" "$mention_title" "$mention_author" "$APP_TOKEN" \
                || log "ERROR: PR review (via @mention) failed for #${MENTION_NUMBER}"
            log "--- PR Review (via @mention) complete for #${MENTION_NUMBER} ---"
        else
            log "--- Skill: @Mention Response (Issue #${MENTION_NUMBER}) ---"

            mention_title=$(echo "$mention_data" | jq -r '.title // "Unknown"')
            mention_body=$(sanitize_input "$(echo "$mention_data" | jq -r '.body // "No body"')")
            mention_comments=$(sanitize_input "$(github_api GET "/repos/${REPO}/issues/${MENTION_NUMBER}/comments?per_page=20" "$APP_TOKEN" | jq -r '.[] | "[\(.user.login)] \(.body)"' 2>/dev/null || echo "No comments")")

            mention_log="$LOGDIR/mention-${MENTION_NUMBER}-$(date +%Y%m%d-%H%M%S).log"

            cd "$WORKSPACE"
            # @Mention is conversational only. Tool surface is restricted to
            # read + comment via CLAUDE_ALLOWED_TOOLS_MENTION — no Edit/Write/
            # git-write/create_pull_request even if the user asks for them.
            # Implementation goes through the eligibility-label path, which
            # routes to implement-fix with the full default tool surface.
            # Prompt body lives in skills/mention-respond.md; render_skill_full
            # prepends `/goal comment_on_issue has been called…` so claude
            # iterates until the response is actually posted instead of
            # exiting after analysis without commenting.
            mention_prompt=$(render_skill_full "mention-respond" \
                "MENTION_NUMBER" "$MENTION_NUMBER" \
                "MENTION_TITLE" "$mention_title" \
                "MENTION_BODY" "$mention_body" \
                "MENTION_COMMENTS" "$mention_comments" \
                "WORKSPACE" "$WORKSPACE")
            run_claude "$mention_prompt" "$mention_log" "$CLAUDE_ALLOWED_TOOLS_MENTION" || {
                log "ERROR: @Mention response failed for #${MENTION_NUMBER}"
            }
            log "--- @Mention Response complete for #${MENTION_NUMBER} ---"
        fi
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
        # CI completion. The dashboard webhook receiver now forwards
        # both conclusion=failure AND conclusion=success (see commit
        # f0d6cf2 on tetragon-dashboard). Dispatch all three:
        #   - explain-ci:     act on failures (post a CI-failure explainer)
        #   - review-pr:      act on successes (the PR is now ripe for review)
        #   - process_issues: surface retry context for the affected PR's
        #                     source issue regardless of pass/fail
        # The May 25 series fixed receiver-forward + dispatcher EVENT_SKILLS
        # scoping but neglected to set run_review_prs here — so CI-success
        # webhooks correctly reached the orchestrator and the scanner
        # allowlisted review-pr's tools, but skill_review_prs was never
        # actually invoked. Trace 233bd1b0 (PR #3286 green CI → no review
        # despite the orchestrator firing) was the smoking gun.
        run_explain_ci=1
        run_review_prs=1
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
