#!/opt/homebrew/bin/bash
# AetherClaude Validation Gate
# Scans git diff for suspicious patterns and protected file modifications
# Exit 0 = pass, Exit 1 = fail

set -euo pipefail

WORKSPACE="${1:-.}"
LOGFILE="/Users/aetherclaude/logs/validation.log"

cd "$WORKSPACE"

log() {
    echo "$(date "+%Y-%m-%dT%H:%M:%S") VALIDATE: $1" >> "$LOGFILE"
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

# --- Check 2: Only allow changes in src/ and docs/ ---
for file in $CHANGED_FILES; do
    if [[ "$file" != src/* ]] && [[ "$file" != docs/* ]] && [[ "$file" != resources/* ]] && [[ "$file" != resources.qrc ]] && [[ "$file" != CMakeLists.txt ]] && [[ "$file" != third_party/* ]] && [[ "$file" != packaging/* ]]; then
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
CODEGUARD="/Users/aetherclaude/.local/bin/defenseclaw-gateway"
if [ -x "$CODEGUARD" ]; then
    log "Running CodeGuard static analysis..."

    for file in $CHANGED_FILES; do
        # Only scan files that exist and have supported extensions
        [ -f "$WORKSPACE/$file" ] || continue
        case "$file" in
            *.cpp|*.h|*.c|*.py|*.js|*.ts|*.go|*.java|*.rb|*.php|*.sh|*.yaml|*.yml|*.json|*.xml|*.rs)
                ;;
            *)
                continue
                ;;
        esac

        SCAN_RESULT=$("$CODEGUARD" scan code "$WORKSPACE/$file" --json 2>/dev/null || echo '{"findings":[]}')

        # Save findings to SQLite + JSON for dashboard
        echo "$SCAN_RESULT" | SCAN_FILE="$file" python3 -c "
import sys, json, sqlite3, os
try:
    d = json.loads(sys.stdin.read())
    findings = d.get('findings', [])
    scan_file = os.environ.get('SCAN_FILE', '')
    if findings:
        # Append to JSON (for backward compat)
        existing = []
        try:
            with open('/Users/aetherclaude/logs/codeguard-latest.json') as f:
                existing = json.load(f)
        except: pass
        existing.extend(findings)
        with open('/Users/aetherclaude/logs/codeguard-latest.json', 'w') as f:
            json.dump(existing, f)
        # Insert into SQLite
        db = sqlite3.connect('/Users/aetherclaude/data/events.db')
        db.execute('''CREATE TABLE IF NOT EXISTS codeguard_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT, rule_id TEXT, severity TEXT,
            title TEXT, description TEXT, location TEXT, remediation TEXT
        )''')
        for f in findings:
            db.execute(
                'INSERT INTO codeguard_findings (file_path, rule_id, severity, title, description, location, remediation) VALUES (?,?,?,?,?,?,?)',
                (scan_file, f.get('id',''), f.get('severity',''), f.get('title',''),
                 f.get('description',''), f.get('location',''), f.get('remediation',''))
            )
        db.commit()
        db.close()
except: pass
" 2>/dev/null

        # Check for HIGH or CRITICAL findings
        HIGH_COUNT=$(echo "$SCAN_RESULT" | jq '[.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' 2>/dev/null || echo 0)
        MEDIUM_COUNT=$(echo "$SCAN_RESULT" | jq '[.findings[] | select(.severity == "MEDIUM")] | length' 2>/dev/null || echo 0)

        if [ "$HIGH_COUNT" -gt 0 ]; then
            FINDING_DETAILS=$(echo "$SCAN_RESULT" | jq -r '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | "  \(.id) [\(.severity)]: \(.title) at \(.location)"' 2>/dev/null)
            log "BLOCKED: CodeGuard found $HIGH_COUNT HIGH/CRITICAL findings in $file:"
            echo "$FINDING_DETAILS" | while read -r detail; do
                log "  $detail"
            done
            ERRORS=$((ERRORS + 1))
        fi

        if [ "$MEDIUM_COUNT" -gt 0 ]; then
            log "WARNING: CodeGuard found $MEDIUM_COUNT MEDIUM findings in $file (review recommended)"
        fi
    done
else
    log "WARNING: CodeGuard not available at $CODEGUARD — skipping static analysis"
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

# --- Result ---
if [ "$ERRORS" -gt 0 ]; then
    log "FAILED: $ERRORS blocking issues found"
    exit 1
else
    log "PASSED: All checks clean"
    exit 0
fi
