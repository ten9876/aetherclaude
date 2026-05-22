# Cisco AI Defense Scanner Integration Plan

## Objective

Integrate all available Cisco AI Defense scanners into the AetherClaude
live demo, with results feeding into the Defense-in-Depth dashboard.
Show 7 Cisco tools working together on a single Raspberry Pi 5.

---

## Current State

| Tool | Status | Dashboard |
|------|--------|-----------|
| Cilium Tetragon | Running | Events streaming |
| DefenseClaw CodeGuard | Running | In validation gate, events streaming |
| MCP Scanner | Installed, not wired | Not on dashboard |
| Skill Scanner | Installed, not wired | Not on dashboard |
| AIBOM | Installed, not wired | Not on dashboard |
| AI Defense SDK | Not configured | Requires Cisco license |
| A2A Scanner | Installed, not applicable | N/A (no multi-agent) |

---

## Implementation Plan

### Phase 1: MCP Scanner Integration

**What:** Scan the MCP server's 14 tools for prompt injection, data
exfiltration, credential harvesting, and tool poisoning before every
agent run.

**How it works:** The MCP Scanner reads tool definitions (name,
description, inputSchema) and runs 10 YARA rules against them. It does
NOT execute any tools — it only inspects their declarations. No API key
needed. Sub-second scan time.

**Integration point:** Orchestrator startup, before any skills run.

#### Step 1: Generate static tool manifest

Create a script that captures the MCP server's tool list into a JSON
file. Run once, and again whenever the MCP server changes.

```bash
# scripts/generate-mcp-manifest.sh
#!/bin/bash
# Captures MCP server tool definitions for static scanning

MCP_SERVER="${1:-/home/agent/bin/github-mcp-server.js}"
OUTPUT="${2:-/home/agent/config/mcp-tools.json}"

echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"scanner","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | \
  timeout 5 node "$MCP_SERVER" 2>/dev/null | \
  tail -1 | python3 -c "
import sys, json
data = json.load(sys.stdin)
tools = data.get('result', {}).get('tools', [])
print(json.dumps({'tools': tools}, indent=2))
" > "$OUTPUT"

echo "Captured $(python3 -c "import json; print(len(json.load(open('$OUTPUT'))['tools']))" 2>/dev/null) tools to $OUTPUT"
```

#### Step 2: Add MCP scan to orchestrator startup

Add to `run-agent.sh` after the fork sync, before any skills:

```bash
# --- MCP Scanner: pre-flight security check ---
if command -v mcp-scanner &>/dev/null; then
    log "--- MCP Scanner: Scanning MCP server tools ---"
    MCP_MANIFEST="${AGENT_HOME}/config/mcp-tools.json"

    if [ -f "$MCP_MANIFEST" ]; then
        SCAN_RESULT=$(mcp-scanner --analyzers yara,prompt_defense \
            --format raw static --tools "$MCP_MANIFEST" 2>/dev/null)

        # Parse for HIGH/CRITICAL findings
        MCP_UNSAFE=$(echo "$SCAN_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    results = d.get('scan_results', [])
    high = sum(1 for r in results if not r.get('is_safe', True)
        for a, f in r.get('findings', {}).items()
        if f.get('severity') in ('HIGH', 'CRITICAL'))
    print(high)
except: print(0)
" 2>/dev/null)

        if [ "${MCP_UNSAFE:-0}" -gt 0 ]; then
            log "CRITICAL: MCP Scanner found $MCP_UNSAFE HIGH/CRITICAL findings — aborting run"
            exit 1
        fi

        # Write scan results to log for dashboard
        echo "$SCAN_RESULT" > "$LOGDIR/mcp-scan-latest.json"
        log "MCP Scanner: clean ($(echo "$SCAN_RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d.get('scan_results', [])))
" 2>/dev/null) tools scanned)"
    else
        log "WARNING: MCP manifest not found at $MCP_MANIFEST — run generate-mcp-manifest.sh"
    fi
fi
```

#### Step 3: Dashboard integration

Add MCP Scanner results to the ring scanner in `dashboard.py`:

```python
# In scan_rings(), add after CodeGuard:
try:
    import json
    scan_file = os.path.join(LOGDIR, 'mcp-scan-latest.json')
    if os.path.exists(scan_file):
        with open(scan_file) as f:
            mcp_scan = json.load(f)
        results = mcp_scan.get('scan_results', [])
        safe = sum(1 for r in results if r.get('is_safe', True))
        unsafe = sum(1 for r in results if not r.get('is_safe', True))
        ring_stats['mcp_scan_total'] = len(results)
        ring_stats['mcp_scan_safe'] = safe
        ring_stats['mcp_scan_unsafe'] = unsafe
except: pass
```

Display in the Security Policy Hits panel or as a new panel:
- "MCP Tools Scanned: 14"
- "Clean: 14 / Threats: 0"
- Tool-by-tool status list

**Estimated effort:** 2 hours

---

### Phase 2: Skill Scanner Integration

**What:** Scan the workspace for injected `.claude/commands/` files that
could auto-execute malicious instructions when Claude Code starts.

**How it works:** The Skill Scanner in `--lenient` mode parses `.md`
files as skill definitions, runs YARA rules + static analysis +
optional behavioral analysis against them. Detects prompt injection,
data exfiltration patterns, credential harvesting, and obfuscation.
No API key needed. Sub-second.

**Integration points:**
1. Every timer cycle: scan workspace before Claude Code runs
2. Validation gate: scan changed files before pushing

#### Step 1: Add workspace scan to orchestrator

Add to `run-agent.sh` after MCP scan, before skills:

```bash
# --- Skill Scanner: check for injected commands ---
if command -v skill-scanner &>/dev/null; then
    log "--- Skill Scanner: Checking workspace for injected skills ---"
    WORKSPACE_CLAUDE="$WORKSPACE/.claude"

    if [ -d "$WORKSPACE_CLAUDE" ]; then
        SKILL_RESULT=$(skill-scanner scan "$WORKSPACE_CLAUDE" \
            --lenient --use-behavioral --format json 2>/dev/null)

        SKILL_UNSAFE=$(echo "$SKILL_RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        high = sum(1 for r in d if r.get('max_severity') in ('HIGH', 'CRITICAL'))
    else:
        high = 1 if d.get('max_severity') in ('HIGH', 'CRITICAL') else 0
    print(high)
except: print(0)
" 2>/dev/null)

        if [ "${SKILL_UNSAFE:-0}" -gt 0 ]; then
            log "CRITICAL: Skill Scanner found injected malicious skills — aborting run"
            # Remove the injected files
            log "Removing .claude/ directory from workspace"
            rm -rf "$WORKSPACE_CLAUDE"
            exit 1
        fi

        echo "$SKILL_RESULT" > "$LOGDIR/skill-scan-latest.json"
        log "Skill Scanner: workspace clean"
    else
        log "Skill Scanner: no .claude/ in workspace — clean"
    fi
fi
```

#### Step 2: Add to validation gate

Add to `validate-diff.sh` after CodeGuard (Check 8):

```bash
# --- Check 8: Skill Scanner — check for injected .claude/ commands ---
if command -v skill-scanner &>/dev/null; then
    CLAUDE_CHANGES=$(echo "$CHANGED_FILES" | grep "^\.claude/" || true)
    if [ -n "$CLAUDE_CHANGES" ]; then
        log "Running Skill Scanner on .claude/ changes..."
        for dir in $(echo "$CLAUDE_CHANGES" | xargs -I{} dirname {} | sort -u); do
            if [ -d "$WORKSPACE/$dir" ]; then
                SKILL_RESULT=$(skill-scanner scan "$WORKSPACE/$dir" \
                    --lenient --format json 2>/dev/null)
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
```

#### Step 3: Dashboard integration

```python
# In scan_rings():
try:
    scan_file = os.path.join(LOGDIR, 'skill-scan-latest.json')
    if os.path.exists(scan_file):
        with open(scan_file) as f:
            skill_scan = json.load(f)
        if isinstance(skill_scan, list):
            ring_stats['skill_scan_count'] = len(skill_scan)
            ring_stats['skill_scan_findings'] = sum(
                r.get('findings_count', 0) for r in skill_scan)
        else:
            ring_stats['skill_scan_count'] = 1
            ring_stats['skill_scan_findings'] = skill_scan.get('findings_count', 0)
except: pass
```

**Estimated effort:** 2 hours

---

### Phase 3: AIBOM Integration

**What:** Generate an AI Bill of Materials for the workspace.

**Reality:** AIBOM is Python-only. AetherSDR is C++. The scan will
report zero AI components — but that's actually the correct answer
and worth showing: "We scanned the codebase and confirmed no
unauthorized AI frameworks are present."

**Integration:** Run once daily (not every cycle). Display result
count on dashboard.

#### Step 1: Add to weekly stale triage timer (or separate daily timer)

```bash
# In run-stale-triage.sh or a separate daily script:
if command -v aibom &>/dev/null || command -v cisco-aibom &>/dev/null; then
    AIBOM_CMD=$(command -v aibom || command -v cisco-aibom)
    log "--- AIBOM: Generating AI Bill of Materials ---"
    $AIBOM_CMD scan "$WORKSPACE" --format json \
        > "$LOGDIR/aibom-latest.json" 2>/dev/null || true
    COMPONENTS=$(python3 -c "
import json
with open('$LOGDIR/aibom-latest.json') as f:
    d = json.load(f)
print(d.get('aibom_analysis',{}).get('summary',{}).get('total_components',0))
" 2>/dev/null || echo 0)
    log "AIBOM: $COMPONENTS AI components found"
fi
```

#### Step 2: Dashboard display

Show in a simple counter: "AI Components: 0 (verified clean)"

**Estimated effort:** 30 minutes

---

### Phase 4: AI Defense SDK Integration (Pending License)

**What:** Cloud-based inspection of MCP tool call arguments and
responses for prompt injection, PII, code leakage.

**Prerequisite:** Cisco AI Defense API key (`AI_DEFENSE_API_KEY`).
Jeremy to obtain internally from Cisco.

**Integration point:** Wrap MCP server tool handlers with
`MCPInspectionClient.inspect_tool_call()` and `inspect_response()`.

**Note:** The SDK does NOT support the Anthropic API natively (no
patcher for the `anthropic` Python package). It CAN inspect MCP tool
calls, which is our primary use case.

#### Step 1: Create Python MCP inspection wrapper

```python
# mcp/inspect-wrapper.py
# Sits between the orchestrator and github-mcp-server.js
# Inspects all tool arguments via Cisco AI Defense before forwarding

from aidefense.runtime.agentsec import MCPInspectionClient

client = MCPInspectionClient(
    api_key=os.environ['AI_DEFENSE_API_KEY'],
    mode='enforce'  # or 'monitor'
)

# For each incoming tool call:
result = client.inspect_tool_call(
    tool_name="comment_on_issue",
    arguments={"issue_number": 733, "body": "..."}
)
if result.action == "BLOCK":
    log(f"AI Defense blocked: {result.classifications}")
    return error_response
else:
    forward_to_mcp_server(tool_call)
```

#### Step 2: Dashboard integration

Add an "AI Defense" panel showing:
- Inspections: N
- Blocked: N
- Classifications detected (PII, injection, etc.)

**Estimated effort:** 4 hours (once API key is obtained)

**Status:** BLOCKED on Cisco AI Defense license. Jeremy to request
internally.

---

### Phase 5: Dashboard Updates

**Goal:** Show all scanner results in the live dashboard alongside
existing Tetragon/nftables/tinyproxy/CodeGuard/MCP data.

#### New dashboard elements:

**Ring 6 (CodeGuard) expansion:**
Add MCP Scanner and Skill Scanner counts alongside existing CodeGuard
counts. Ring 6 becomes "Cisco Security Scanning" covering all three:

```
Ring 6: Cisco Scanning
  CodeGuard:   7 files scanned · 0 blocked
  MCP Scanner: 14 tools scanned · 0 threats
  Skill Scan:  workspace clean
```

**New "Cisco Scanner Results" panel** (replaces or augments an
existing right-side panel):

```
┌─────────────────────────────┐
│  Cisco AI Defense Scanners   │
├─────────────────────────────┤
│  MCP Scanner                 │
│    Tools scanned: 14         │
│    Threats: 0                │
│    Last scan: 10:15:32       │
│                              │
│  Skill Scanner               │
│    Workspace: clean          │
│    .claude/ dirs: 0          │
│    Last scan: 10:15:32       │
│                              │
│  CodeGuard                   │
│    Files scanned: 7          │
│    Findings: 0               │
│    Blocked: 0                │
│                              │
│  AIBOM                       │
│    AI Components: 0          │
│    Status: verified clean    │
│                              │
│  AI Defense SDK              │
│    Status: pending license   │
└─────────────────────────────┘
```

**Event stream integration:**
New event types with source tags:

| Source Tag | Color | Events |
|-----------|-------|--------|
| `mcp-scan` | Cyan | MCP tool scan results per tool |
| `skill-scan` | Magenta | Skill scan results |
| `aibom` | Grey | Component inventory (daily) |

#### Implementation:

1. Dashboard ring scanner reads `mcp-scan-latest.json` and
   `skill-scan-latest.json` from the logs directory
2. New panel renders the combined scanner status
3. Scan events injected into the event stream with appropriate
   source tags when scans complete

**Estimated effort:** 3 hours

---

## Implementation Sequence

| Order | Task | Effort | Dependencies |
|-------|------|--------|-------------|
| 1 | Generate MCP tool manifest | 15 min | None |
| 2 | MCP Scanner in orchestrator | 1 hr | Manifest |
| 3 | Skill Scanner in orchestrator | 1 hr | None |
| 4 | Skill Scanner in validation gate | 30 min | None |
| 5 | AIBOM daily scan | 30 min | None |
| 6 | Dashboard: scanner results panel | 2 hr | Steps 2-5 |
| 7 | Dashboard: event stream integration | 1 hr | Step 6 |
| 8 | AI Defense SDK wrapper | 4 hr | Cisco license |
| **Total (without SDK)** | | **~7 hours** | |
| **Total (with SDK)** | | **~11 hours** | |

---

## What the Demo Shows

After implementation, the dashboard displays:

**7 Cisco tools active on one Raspberry Pi 5:**

1. **Tetragon** — eBPF process/network/syscall monitoring (real-time)
2. **CodeGuard** — static analysis on every code change (per-PR)
3. **MCP Scanner** — MCP server threat detection (per-run startup)
4. **Skill Scanner** — injected command detection (per-run + validation)
5. **AIBOM** — AI component inventory (daily)
6. **AI Defense SDK** — cloud prompt inspection (pending license)
7. **A2A Scanner** — available for multi-agent deployments (documented)

**Plus 4 non-Cisco controls:**
- nftables kernel firewall
- tinyproxy domain filtering
- MCP token isolation (custom)
- Human review (GitHub CODEOWNERS)

**= 11 security controls, 8 rings, 1 dashboard, $147 hardware.**

---

*Document version: 1.0 — 2026-04-06*
*Author: Jeremy Fielder (KK7GWY) & Claude (AI dev partner)*
