#!/opt/homebrew/bin/bash
# AetherClaude Validation Gate
# Scans git diff for suspicious patterns and protected file modifications
# Exit 0 = pass, Exit 1 = fail

set -euo pipefail

WORKSPACE="${1:-.}"
LOGFILE="/Users/aetherclaude/logs/validation.log"

cd "$WORKSPACE"

log() {
    # Stamp each line with the orchestrator's trace prefix (when set) so
    # the dashboard's tail_validation_log can attribute codeguard/validation
    # events to the correct trace deterministically, even under parallel
    # orchestrators where the global active-trace heuristic could pick the
    # wrong one.
    #
    # Use UTC (-u + trailing Z) to match the timestamp format every other
    # event source in the system writes (WEBHOOK, defenseclaw audit, MCP
    # audit, claude transcripts — all UTC). Mixing local time here caused
    # issue #34 cousin: the dashboard's db_trace_backfill_correlator's
    # Pass 0 does a string compare to null out events that predate their
    # trace's "true start", and a PDT timestamp sorts 7 hours before its
    # corresponding UTC webhook arrival — so every CodeGuard event was
    # silently NULLed out of Agent Walk attribution.
    local prefix=""
    if [ -n "${AETHER_TRACE_ID:-}" ]; then
        prefix=" [${AETHER_TRACE_ID:0:8}]"
    fi
    echo "$(date -u "+%Y-%m-%dT%H:%M:%SZ")${prefix} VALIDATE: $1" >> "$LOGFILE"
}

ERRORS=0

# Get list of changed files
CHANGED_FILES=$(git diff --name-only main 2>/dev/null)

if [ -z "$CHANGED_FILES" ]; then
    log "No changes to validate"
    exit 0
fi

log "Validating $(echo "$CHANGED_FILES" | wc -l) changed files"

# Clear CodeGuard results from previous run
echo "[]" > /Users/aetherclaude/logs/codeguard-latest.json 2>/dev/null || true

# --- Check 1: Protected files ---
PROTECTED_PATTERNS=(
    ".github/"
    "Dockerfile"
    "CLAUDE.md"
    "CONTRIBUTING.md"
    ".gitignore"
    ".clang-format"
    "scripts/"
    "Makefile"
    ".docker/"
    "setup-"
)

for file in $CHANGED_FILES; do
    for pattern in "${PROTECTED_PATTERNS[@]}"; do
        if [[ "$file" == *"$pattern"* ]]; then
            log "BLOCKED: Protected file modified: $file (matches $pattern)"
            ERRORS=$((ERRORS + 1))
        fi
    done
done

# --- Check 2: Only allow changes in approved top-level paths ---
# tests/ is included because AetherSDR has an existing test harness wired
# into CMakeLists.txt (client_eq_test, client_eq_smoothing_test, …) and
# Claude correctly follows that pattern when adding regression coverage
# for a bug fix. Without it, every fix that adds a test gets blocked.
for file in $CHANGED_FILES; do
    if [[ "$file" != src/* ]] \
       && [[ "$file" != tests/* ]] \
       && [[ "$file" != docs/* ]] \
       && [[ "$file" != resources/* ]] \
       && [[ "$file" != resources.qrc ]] \
       && [[ "$file" != CMakeLists.txt ]] \
       && [[ "$file" != third_party/* ]] \
       && [[ "$file" != packaging/* ]] \
       && [[ "$file" != plugins/* ]]; then
        log "BLOCKED: File outside allowed directories: $file"
        ERRORS=$((ERRORS + 1))
    fi
done

# --- Check 3: Suspicious code patterns ---
DIFF_CONTENT=$(git diff main 2>/dev/null)

SUSPICIOUS_PATTERNS=(
    'system\s*('
    'popen\s*('
    'exec\s*('
    'eval\s*('
    '__import__\s*('
    'subprocess.*shell\s*=\s*True'
    'pickle\.load'
    'yaml\.load\s*('
    'curl.*\|\s*(bash|sh)'
    'wget.*\|\s*(bash|sh)'
    'os\.system\s*('
    'os\.popen\s*('
    'QSettings'
)

for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    MATCHES=$(echo "$DIFF_CONTENT" | grep -cE "^\+.*$pattern" 2>/dev/null || true)
    if [ "${MATCHES:-0}" -gt 0 ]; then
        log "WARNING: Suspicious pattern found: $pattern ($MATCHES occurrences)"
        # Warnings don't block, but are logged for review
    fi
done

# --- Check 4: Hardcoded credentials ---
CREDENTIAL_PATTERNS=(
    'ghp_[A-Za-z0-9]{36}'
    'ghs_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{80,}'
    'sk-ant-[A-Za-z0-9-]{40,}'
    'AKIA[A-Z0-9]{16}'
    '-----BEGIN.*PRIVATE KEY-----'
)

for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
    MATCHES=$(echo "$DIFF_CONTENT" | grep -cE "^\+.*$pattern" 2>/dev/null || true)
    if [ "${MATCHES:-0}" -gt 0 ]; then
        log "BLOCKED: Credential pattern found in diff: $pattern"
        ERRORS=$((ERRORS + 1))
    fi
done

# --- Check 4b: literal secret values from .env ---
#
# The patterns above only catch credentials whose vendor shape someone
# enumerated. Every secret this host actually holds — WEBHOOK_SECRET,
# VIRUSTOTAL_API_KEY, DEFENSECLAW_DASHBOARD_BEARER, GALILEO_API_KEY — is an
# opaque string matching none of them, so a diff carrying one sailed through
# this gate. The MCP server gained value-based scanning for comments; this is
# the same check on the push path, which matters more because writing files
# and pushing them is the agent's actual job.
#
# This is containment at the exit rather than at the read: the agent's uid can
# still open .env by some means (head, tail, git diff --no-index, whatever verb
# the allowlist hasn't thought of), so the durable guarantee is that the value
# cannot leave in a diff regardless of how it was obtained.
#
# Secret values never reach argv — `ps` is world-readable — so patterns are
# passed to grep over a pipe via process substitution. Only the variable NAME
# is ever logged.
ENV_FILE=/Users/aetherclaude/.env
if [ -r "$ENV_FILE" ]; then
    ADDED_LINES=$(printf '%s' "$DIFF_CONTENT" | grep '^+' || true)
    if [ -n "$ADDED_LINES" ]; then
        while IFS='=' read -r env_key env_val; do
            # Only credential-looking names. .env also holds GALILEO_PROJECT
            # ("aetherclaude") and a console URL — legitimate strings in real
            # diffs, and blocking on those would fail every PR.
            case "$env_key" in
                *SECRET*|*TOKEN*|*KEY*|*BEARER*|*PASSWORD*|*PASSWD*|*CREDENTIAL*|*PRIVATE*) ;;
                *) continue ;;
            esac
            # Length floor: a short or placeholder value would be a substring
            # of ordinary code and wedge every diff.
            [ "${#env_val}" -ge 8 ] || continue
            if grep -qF -f <(printf '%s\n' "$env_val") <<< "$ADDED_LINES"; then
                log "BLOCKED: diff contains the literal value of ${env_key}"
                ERRORS=$((ERRORS + 1))
            fi
        done < "$ENV_FILE"
    fi
fi

# --- Check 5: Binary files ---
BINARY_EXTENSIONS=(".so" ".dll" ".exe" ".bin" ".dylib" ".o" ".a")
for file in $CHANGED_FILES; do
    for ext in "${BINARY_EXTENSIONS[@]}"; do
        if [[ "$file" == *"$ext" ]]; then
            log "BLOCKED: Binary file addition: $file"
            ERRORS=$((ERRORS + 1))
        fi
    done
done

# --- Check 6: Diff size limit ---
TOTAL_LINES=$(echo "$DIFF_CONTENT" | grep -c "^[+-]" 2>/dev/null || true)
if [ "$TOTAL_LINES" -gt 1000 ]; then
    log "WARNING: Large diff ($TOTAL_LINES lines changed). Manual review strongly recommended."
fi

# --- Check 7: Cisco DefenseClaw CodeGuard static analysis ---
# Delegated to bin/codeguard-scan.sh — the SINGLE shared CodeGuard
# implementation, also used to scan every contributor PR (run-agent.sh
# review_single_pr). It scans the files changed vs main in this worktree,
# records findings to the events DB (tagged source=agent) + codeguard-
# latest.json, and prints the aggregated findings JSON. This gate then blocks
# on HIGH/CRITICAL.
CODEGUARD_SCAN="${CODEGUARD_SCAN_BIN:-/Users/aetherclaude/bin/codeguard-scan.sh}"
if [ -x "$CODEGUARD_SCAN" ]; then
    log "Running CodeGuard static analysis..."
    CG_RESULT=$("$CODEGUARD_SCAN" "$WORKSPACE" agent "${AETHER_ISSUE:-}" 2>/dev/null || echo '{"findings":[]}')

    HIGH_COUNT=$(echo "$CG_RESULT" | jq '[.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' 2>/dev/null || echo 0)
    MEDIUM_COUNT=$(echo "$CG_RESULT" | jq '[.findings[] | select(.severity == "MEDIUM")] | length' 2>/dev/null || echo 0)

    if [ "${HIGH_COUNT:-0}" -gt 0 ]; then
        log "BLOCKED: CodeGuard found $HIGH_COUNT HIGH/CRITICAL finding(s):"
        echo "$CG_RESULT" | jq -r '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | "  \(.id) [\(.severity)]: \(.title) at \(.file) \(.location // "")"' 2>/dev/null | while read -r detail; do
            log "  $detail"
        done
        ERRORS=$((ERRORS + 1))
    fi
    if [ "${MEDIUM_COUNT:-0}" -gt 0 ]; then
        log "WARNING: CodeGuard found $MEDIUM_COUNT MEDIUM finding(s) (review recommended)"
    fi
else
    log "WARNING: codeguard-scan.sh not available at $CODEGUARD_SCAN — skipping static analysis"
fi

# --- Check 8: Skill Scanner — injected .claude/ commands ---
if command -v skill-scanner &>/dev/null; then
    CLAUDE_CHANGES=$(echo "$CHANGED_FILES" | grep "^\.claude/" || true)
    if [ -n "$CLAUDE_CHANGES" ]; then
        log "Running Skill Scanner on .claude/ changes..."
        for dir in $(echo "$CLAUDE_CHANGES" | xargs -I{} dirname {} | sort -u); do
            if [ -d "$WORKSPACE/$dir" ]; then
                SKILL_RESULT=$(skill-scanner scan "$WORKSPACE/$dir" --lenient --format json 2>/dev/null || echo "{}")
                SKILL_HIGH=$(echo "$SKILL_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d if isinstance(d, list) else [d]
    print(sum(1 for r in items if r.get('max_severity') in ('HIGH','CRITICAL')))
except: print(0)
" 2>/dev/null)
                if [ "${SKILL_HIGH:-0}" -gt 0 ]; then
                    log "BLOCKED: Skill Scanner found HIGH/CRITICAL in $dir"
                    ERRORS=$((ERRORS + 1))
                fi
            fi
        done
    fi
fi

# --- Check 9: cpp-aibom — AI Bill of Materials + OSV.dev CVE scan (informational) ---
# Runs cpp-aibom against the full worktree to capture inventory and CVE
# findings for the dashboard. **Never** blocks the PR — CVEs in long-lived
# dependencies (OpenSSL, Qt6, etc.) are a baseline fact, not a regression
# introduced by any specific PR diff. Inventory + CVE list are persisted
# to events.db / aibom-latest.json for the dashboard's Ring 6 modal.
CPP_AIBOM="/Users/aetherclaude/bin/cpp-aibom"
if [ -x "$CPP_AIBOM" ]; then
    log "Running cpp-aibom AIBOM scan (informational, not a gate)..."
    AIBOM_TMP=$(mktemp -t aibom-pr.XXXXXX)
    trap 'rm -f "$AIBOM_TMP"' EXIT
    if "$CPP_AIBOM" scan "$WORKSPACE" -o "$AIBOM_TMP" 2>/dev/null; then
        AIBOM_SUMMARY=$(python3 -c "
import json
d = json.load(open('$AIBOM_TMP'))
s = d['aibom_analysis']['summary']
print(f\"{s['total_components']} components, {s['total_model_files']} ML, {s['vulnerabilities_found']} vulns\")
" 2>/dev/null || echo "summary unavailable")
        log "cpp-aibom: $AIBOM_SUMMARY (informational)"
    else
        log "WARNING: cpp-aibom scan failed (non-blocking)"
    fi
else
    log "WARNING: cpp-aibom not available at $CPP_AIBOM — skipping AIBOM scan"
fi

# --- Result ---
if [ "$ERRORS" -gt 0 ]; then
    log "FAILED: $ERRORS blocking issues found"
    exit 1
else
    log "PASSED: All checks clean"
    exit 0
fi
