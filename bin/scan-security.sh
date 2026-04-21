#!/opt/homebrew/bin/bash
# AI Agent Security Scanner Suite
# Runs Cisco AI Defense scanners against the agent's components
# Can be run standalone or as part of the validation gate
#
# Scanners:
#   1. mcp-scanner  — Scan MCP server tools for threats
#   2. skill-scanner — Scan workspace for injected commands/skills
#   3. aibom         — Generate AI Bill of Materials
#   4. ai-defense    — Cloud-based prompt/response inspection (optional, requires license)

set -euo pipefail

WORKSPACE="${1:-/home/agent/workspace/repo}"
MCP_SERVER="${2:-/home/agent/bin/github-mcp-server.js}"
LOGDIR="${3:-/home/agent/logs}"
SCAN_LOG="$LOGDIR/security-scan-$(date +%Y%m%d-%H%M%S).log"

log() { echo "$(date "+%Y-%m-%dT%H:%M:%S") SCAN: $1" | tee -a "$SCAN_LOG"; }

ERRORS=0
WARNINGS=0

log "=== Security scan starting ==="

# =====================================================================
# 1. MCP Scanner — Scan our MCP server for vulnerabilities
# =====================================================================
if command -v mcp-scanner &>/dev/null; then
    log "--- MCP Scanner: Scanning MCP server tools ---"

    # Generate a static description of our MCP server for scanning
    MCP_SCAN_FILE=$(mktemp --suffix=.json)
    node -e "
        const tools = $(node -e "
            process.stdin.resume();
            const msg = JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'scanner',version:'1.0'}}});
            const msg2 = JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/list',params:{}});
            process.stdout.write(msg + '\n' + msg2 + '\n');
        " | timeout 5 node "$MCP_SERVER" 2>/dev/null | tail -1 || echo '{"result":{"tools":[]}}');
        console.log(JSON.stringify(tools, null, 2));
    " > "$MCP_SCAN_FILE" 2>/dev/null || true

    MCP_RESULT=$(mcp-scanner --format raw static "$MCP_SCAN_FILE" 2>&1) || true
    FINDINGS=$(echo "$MCP_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    findings = d.get('findings', [])
    high = len([f for f in findings if f.get('severity') in ('HIGH', 'CRITICAL')])
    med = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    print(f'{high} HIGH/CRITICAL, {med} MEDIUM')
except: print('parse error')
" 2>/dev/null || echo "0 findings")

    log "MCP Scanner: $FINDINGS"
    rm -f "$MCP_SCAN_FILE"

    if echo "$FINDINGS" | grep -q "^[1-9].* HIGH"; then
        log "BLOCKED: MCP Scanner found HIGH/CRITICAL findings"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "MCP Scanner not installed — skipping (install: uv tool install cisco-ai-mcp-scanner)"
fi

# =====================================================================
# 2. Skill Scanner — Scan workspace for injected commands/skills
# =====================================================================
if command -v skill-scanner &>/dev/null; then
    log "--- Skill Scanner: Scanning workspace for injected skills ---"

    # Scan for .claude/commands/ that might have been injected
    if [ -d "$WORKSPACE/.claude" ]; then
        SKILL_RESULT=$(skill-scanner scan "$WORKSPACE/.claude" --lenient --format json 2>&1) || true
        SKILL_FINDINGS=$(echo "$SKILL_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    findings = d.get('findings', [])
    high = len([f for f in findings if f.get('severity') in ('HIGH', 'CRITICAL')])
    print(f'{high} HIGH/CRITICAL findings')
except: print('0 findings')
" 2>/dev/null || echo "0 findings")

        log "Skill Scanner (.claude/): $SKILL_FINDINGS"

        if echo "$SKILL_FINDINGS" | grep -q "^[1-9].* HIGH"; then
            log "BLOCKED: Skill Scanner found HIGH/CRITICAL findings in .claude/"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log "Skill Scanner: No .claude/ directory in workspace — clean"
    fi

    # Also scan the full workspace in lenient mode for any markdown-based skills
    SKILL_FULL=$(skill-scanner scan "$WORKSPACE" --lenient --format summary 2>&1 | tail -5) || true
    log "Skill Scanner (full workspace): $(echo "$SKILL_FULL" | head -3)"
else
    log "Skill Scanner not installed — skipping (install: pip install cisco-ai-skill-scanner)"
fi

# =====================================================================
# 3. AIBOM — Generate AI Bill of Materials
# =====================================================================
if command -v aibom || command -v cisco-aibom &>/dev/null; then
    log "--- AIBOM: Generating AI Bill of Materials ---"

    AIBOM_FILE="$LOGDIR/aibom-$(date +%Y%m%d).json"
    $(command -v aibom || command -v cisco-aibom) scan "$WORKSPACE" --format json > "$AIBOM_FILE" 2>/dev/null || true

    COMPONENT_COUNT=$(python3 -c "
import json
try:
    with open('$AIBOM_FILE') as f:
        d = json.load(f)
    components = d.get('components', [])
    print(f'{len(components)} AI components found')
except: print('0 components')
" 2>/dev/null || echo "0 components")

    log "AIBOM: $COMPONENT_COUNT (saved to $AIBOM_FILE)"
else
    log "AIBOM not installed — skipping (install: pip install aibom)"
fi

# =====================================================================
# 4. Cisco AI Defense SDK — Cloud-based inspection (optional)
# =====================================================================
if [ -n "${AI_DEFENSE_API_KEY:-}" ]; then
    log "--- Cisco AI Defense: Cloud inspection available ---"

    # This would be called per-prompt in the orchestrator, not here
    # Just verify connectivity
    DEFENSE_STATUS=$(python3 -c "
try:
    from cisco_ai_defense import AIDefenseClient
    client = AIDefenseClient(api_key='${AI_DEFENSE_API_KEY}')
    print('SDK available and configured')
except ImportError:
    print('SDK not installed (pip install cisco-ai-defense-python-sdk)')
except Exception as e:
    print(f'SDK error: {e}')
" 2>/dev/null || echo "SDK not available")

    log "AI Defense SDK: $DEFENSE_STATUS"
else
    log "AI Defense SDK: No API key configured — skipping (set AI_DEFENSE_API_KEY)"
fi

# =====================================================================
# Results
# =====================================================================
log "=== Security scan complete: $ERRORS errors, $WARNINGS warnings ==="

if [ "$ERRORS" -gt 0 ]; then
    log "SCAN FAILED: $ERRORS blocking findings"
    exit 1
fi

exit 0
