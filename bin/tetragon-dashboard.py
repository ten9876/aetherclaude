#!/usr/bin/env python3

# ── .env loader — required so launchd children see WEBHOOK_SECRET etc. ──
import os as _os
_env_path = _os.path.expanduser('~/.env')
if _os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith('#') or '=' not in _line:
                continue
            _k, _v = _line.split('=', 1)
            _os.environ.setdefault(_k.strip(), _v.strip())
# ──────────────────────────────────────────────────────────────────────────
"""
AetherClaude Defense-in-Depth Dashboard v4
Unified security observability across all 7 defense rings.
"""

import json, os, sys, time, re, sqlite3, threading, argparse, subprocess, glob
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque, defaultdict

AETHERCLAUDE_UID = 965
MAX_EVENTS = 5000
EVENTS_DB = '/Users/aetherclaude/data/events.db'
ISSUE_ACTIONS_DB = '/Users/aetherclaude/data/issue-actions.db'
REFRESH_INTERVAL_MS = 3000
TOKEN_REFRESH_SECS = 30
RING_REFRESH_SECS = 15
SESSION_DIR = '/Users/aetherclaude/.claude/projects'
VALIDATION_LOG = '/Users/aetherclaude/logs/validation.log'
MCP_AUDIT_LOG = '/Users/aetherclaude/logs/mcp-audit.log'
ORCHESTRATOR_LOG = '/Users/aetherclaude/logs/orchestrator.log'
SESSION_DIR = '/Users/aetherclaude/.claude/projects'
MCP_SCAN_FILE = '/Users/aetherclaude/logs/mcp-scan-latest.json'
SKILL_SCAN_FILE = '/Users/aetherclaude/logs/skill-scan-latest.json'
NOISE_BINARIES = {'/usr/bin/python3', '/usr/local/bin/tetragon-dashboard.py'}
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
WEBHOOK_EVENTS = {'issues', 'issue_comment', 'pull_request', 'pull_request_review', 'discussion', 'discussion_comment'}
_last_webhook_trigger = 0

# Track last-persisted scan file mtimes to avoid duplicate DB inserts
_last_mcp_mtime = 0.0
_last_aibom_mtime = 0.0

# 2-tier ring buffer: memory_buffer is the single source of truth
MEMORY_BUFFER_MAX = 10000
memory_buffer = []  # Ordered by insertion time, newest at end
memory_lock = threading.Lock()

# --- Secret redaction ---
import re as _re
_SECRET_PATTERNS = [
    # GitHub tokens (PAT, app, oauth, user-to-server)
    (_re.compile(r'(github_pat_[A-Za-z0-9_]{20,})'), '***'),
    (_re.compile(r'(ghp_[A-Za-z0-9]{20,})'), '***'),
    (_re.compile(r'(ghs_[A-Za-z0-9]{20,})'), '***'),
    (_re.compile(r'(gho_[A-Za-z0-9]{20,})'), '***'),
    (_re.compile(r'(ghu_[A-Za-z0-9]{20,})'), '***'),
    # Authorization headers (redact token value OR variable reference)
    (_re.compile(r'(Authorization:\s*(?:token|Bearer)\s+)(\$?[A-Za-z0-9_\-\.]{4,})'), r'\1***'),
    # GH_TOKEN=<actual value> or GH_APP_TOKEN=<actual value> (but not variable references like $GH_TOKEN)
    (_re.compile(r'(GH_(?:APP_)?TOKEN=)(?!\$)([A-Za-z0-9_\-\.]{10,})'), r'\1***'),
    # printenv that dumps token values
    (_re.compile(r'printenv\s+GH_(?:APP_)?TOKEN\b'), 'printenv ***'),
    # File paths to credential stores (full path or bare filename)
    (_re.compile(r'(?:/Users/aetherclaude/)?\.gh-token'), '***'),
    (_re.compile(r'(?:/Users/aetherclaude/)?\.git-credentials'), '***'),
    (_re.compile(r'/tmp/gh_app_token\.txt'), '***'),
    # Webhook secret
    (_re.compile(WEBHOOK_SECRET), '***'),
    # JWTs (eyJ...)
    (_re.compile(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})'), '***'),
    # Generic long hex/base64 that look like secrets (40+ chars of hex)
    (_re.compile(r'(?:secret|key|password|passwd)=([A-Za-z0-9+/=]{20,})', _re.IGNORECASE), r'***'),
]

def _redact(text):
    """Scrub secrets from event text."""
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def append_event(entry):
    """Append to memory ring buffer + DB queue. Redacts secrets. Generates alerts."""
    entry = dict(entry)
    entry['args'] = _redact(entry.get('args', ''))
    with memory_lock:
        memory_buffer.append(entry)
        if len(memory_buffer) > MEMORY_BUFFER_MAX:
            del memory_buffer[0]
    with db_write_lock:
        db_write_queue.append(entry)
    # Generate alerts for security events
    etype = entry.get('type', '')
    if etype == 'BLOCK':
        stats['alerts'].append({'time': entry.get('time', ''), 'msg': f"FIREWALL: {entry.get('args', '')}", 'severity': 'high'})
    elif entry.get('policy') == 'domain-filter':
        stats['alerts'].append({'time': entry.get('time', ''), 'msg': f"PROXY: {entry.get('args', '')}", 'severity': 'high'})
token_stats = {'input': 0, 'output': 0, 'cache_read': 0, 'cache_create': 0, 'messages': 0}
tool_stats = {'total': 0, 'breakdown': {}}
ring_stats = {
    'agent_running': False,
    'r1_packets_blocked': 0,
    'r2_allowed': 0, 'r2_denied': 0,
    'r3_shell': 'rbash', 'r3_sudo': 'none', 'r3_uid': 965,
    'r4_protect_system': True, 'r4_no_new_privs': True, 'r4_private_tmp': True,
    'r5_allowed_tools': 0, 'r5_denied_tools': 0,
    'r6_files_scanned': 0, 'r6_findings': 0, 'r6_blocked': 0,
    'r6_mcp_tools_scanned': 0, 'r6_mcp_threats': 0, 'r6_skill_status': 'unknown',
    'r7_mcp_ops': 0, 'r7_blocked': 0, 'r7_rate_limited': 0,
    'r8_validation_checks': 0, 'r8_validation_passed': 0, 'r8_validation_failed': 0,
    'r9_prs_total': 0, 'r9_prs_merged': 0, 'r9_prs_rejected': 0, 'r9_prs_open': 0,
}
stats = {
    'total_events': 0, 'exec_count': 0, 'kprobe_count': 0, 'exit_count': 0,
    'aetherclaude_events': 0, 'policy_hits': defaultdict(int),
    'binaries_seen': defaultdict(int), 'network_connections': 0,
    'alerts': deque(maxlen=50), 'suppressed': 0,
}
lock = threading.Lock()

# --- SQLite event store ---
db_write_queue = []
db_write_lock = threading.Lock()

def db_batch_writer():
    """Flush pending events to SQLite every 5 seconds."""
    while True:
        time.sleep(5)
        with db_write_lock:
            if not db_write_queue:
                continue
            batch = db_write_queue.copy()
            db_write_queue.clear()
        try:
            conn = sqlite3.connect(EVENTS_DB)
            conn.executemany(
                'INSERT INTO events (timestamp, type, uid, binary_name, args, policy, is_agent, source) VALUES (?,?,?,?,?,?,?,?)',
                [(e.get('time',''), e.get('type',''), e.get('uid',''),
                  e.get('binary',''), e.get('args',''), e.get('policy',''),
                  e.get('is_agent', False), e.get('source','')) for e in batch]
            )
            conn.commit()
            conn.close()
        except: pass

def init_db():
    conn = sqlite3.connect(EVENTS_DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        uid INTEGER,
        binary_name TEXT,
        args TEXT,
        policy TEXT,
        is_agent BOOLEAN,
        source TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_source ON events(source)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_type ON events(type)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_agent ON events(is_agent)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_created ON events(created_at)')
    conn.execute('''CREATE TABLE IF NOT EXISTS codeguard_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT,
        rule_id TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        location TEXT,
        remediation TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_cg_severity ON codeguard_findings(severity)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_cg_scan_time ON codeguard_findings(scan_time)')
    conn.execute('''CREATE TABLE IF NOT EXISTS mcp_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        tool_name TEXT,
        tool_description TEXT,
        is_safe BOOLEAN,
        severity TEXT,
        threat_name TEXT,
        threat_summary TEXT,
        analyzer TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_mcp_scan_time ON mcp_scan_results(scan_time)')
    conn.execute('''CREATE TABLE IF NOT EXISTS aibom_components (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        name TEXT,
        category TEXT,
        description TEXT,
        detection TEXT,
        location TEXT,
        evidence TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_aibom_scan_time ON aibom_components(scan_time)')
    conn.execute('''CREATE TABLE IF NOT EXISTS skill_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        skill_name TEXT,
        is_safe BOOLEAN,
        max_severity TEXT,
        findings_count INTEGER,
        finding_id TEXT,
        finding_severity TEXT,
        finding_title TEXT,
        finding_description TEXT,
        finding_remediation TEXT,
        analyzers TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_skill_scan_time ON skill_scan_results(scan_time)')
    conn.execute('''CREATE TABLE IF NOT EXISTS validation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_time TEXT,
        files_count INTEGER,
        result TEXT,
        blocked_reasons TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_val_run_time ON validation_runs(run_time)')
    conn.commit()
    conn.close()

def load_memory_buffer():
    """Load newest 10,000 events from SQLite into memory buffer on startup."""
    try:
        conn = sqlite3.connect(EVENTS_DB)
        cursor = conn.execute(
            'SELECT timestamp, type, uid, binary_name, args, policy, is_agent, source FROM events ORDER BY id DESC LIMIT ?',
            (MEMORY_BUFFER_MAX,))
        rows = cursor.fetchall()
        conn.close()
        entries = [{'time': r[0], 'type': r[1], 'uid': r[2], 'binary': r[3],
                    'args': r[4], 'policy': r[5], 'is_agent': bool(r[6]), 'source': r[7]}
                   for r in reversed(rows)]  # oldest first
        with memory_lock:
            memory_buffer.extend(entries)
        print(f"Loaded {len(entries)} events from DB into memory buffer")
    except Exception as e:
        print(f"Warning: could not load memory buffer from DB: {e}")

def db_insert_event(entry):
    try:
        conn = sqlite3.connect(EVENTS_DB)
        conn.execute(
            'INSERT INTO events (timestamp, type, uid, binary_name, args, policy, is_agent, source) VALUES (?,?,?,?,?,?,?,?)',
            (entry.get('time',''), entry.get('type',''), entry.get('uid',''),
             entry.get('binary',''), entry.get('args',''), entry.get('policy',''),
             entry.get('is_agent', False), entry.get('source',''))
        )
        conn.commit()
        conn.close()
    except: pass

def db_query_events(limit=1000, source=None, event_type=None):
    try:
        conn = sqlite3.connect(EVENTS_DB)
        query = 'SELECT timestamp, type, uid, binary_name, args, policy, is_agent, source FROM events'
        params = []
        conditions = []
        if source:
            conditions.append('source = ?')
            params.append(source)
        if event_type:
            conditions.append('type = ?')
            params.append(event_type)
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        query += ' ORDER BY id DESC LIMIT ?'
        params.append(limit)
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return [{'time': r[0], 'type': r[1], 'uid': r[2], 'binary': r[3],
                 'args': r[4], 'policy': r[5], 'is_agent': bool(r[6]), 'source': r[7]}
                for r in reversed(rows)]
    except:
        return []

def db_purge_if_needed(max_gb=250):
    """Purge oldest 10% of events if DB exceeds max_gb."""
    try:
        db_path = EVENTS_DB
        size_gb = os.path.getsize(db_path) / (1024**3)
        if size_gb >= max_gb:
            conn = sqlite3.connect(db_path)
            total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            purge_count = total // 10  # Remove oldest 10%
            conn.execute(f'DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT {purge_count})')
            conn.execute('VACUUM')
            conn.commit()
            conn.close()
            remaining = total - purge_count
            # Log the purge
            try:
                import datetime
                with open('/Users/aetherclaude/logs/orchestrator.log', 'a') as f:
                    f.write(f'{datetime.datetime.now().isoformat()} DASHBOARD: Purged {purge_count} events from DB ({size_gb:.1f}GB exceeded {max_gb}GB limit). {remaining} events remaining.\n')
            except: pass
    except: pass

def db_count():
    try:
        conn = sqlite3.connect(EVENTS_DB)
        count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def sh(cmd):
    try: return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except: return ''

def scan_rings():
    """Periodically refresh ring status from system state."""
    while True:
        try:
            with lock:
                # Ring 1: pf firewall (macOS) — read from root helper
                try:
                    with open('/Users/aetherclaude/logs/pf-blocked-count') as pff:
                        ring_stats['r1_packets_blocked'] = int(pff.read().strip() or 0)
                except: pass

                # Agent service status
                try:
                    agent_status = sh('pgrep -f run-agent.sh >/dev/null 2>&1 && echo active || echo inactive')
                    ring_stats['agent_running'] = agent_status.strip() == 'active'
                except: ring_stats['agent_running'] = False

                # Ring 2: tinyproxy — r2_allowed and r2_denied are updated by tail_tinyproxy_log

                # Ring 3: OS isolation — count agent processes + eslogger events
                try:
                    total_procs = int(sh("ps -ax | wc -l") or 0)
                    agent_procs = int(sh(f"ps -U {AETHERCLAUDE_UID} | wc -l") or 0)
                    ring_stats['r3_agent_procs'] = agent_procs
                    ring_stats['r3_total_procs'] = total_procs
                    # Count eslogger-captured events (EXEC, FORK, EXIT, etc.)
                    es_events = sum(1 for e in memory_buffer if e.get('source') == 'eslogger')
                    es_execs = sum(1 for e in memory_buffer if e.get('source') == 'eslogger' and e.get('type') == 'EXEC')
                    ring_stats['r3_es_events'] = es_events
                    ring_stats['r3_es_execs'] = es_execs
                except: pass

                # Ring 4: systemd — count sandboxed runs + uptime
                try:
                    runs = sh("grep -c 'Agent run starting' /Users/aetherclaude/logs/orchestrator.log 2>/dev/null")
                    ring_stats['r4_sandboxed_runs'] = int(runs) if runs.strip().isdigit() else 0
                    # Timer uptime
                    since = sh("stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' /Users/aetherclaude/logs/orchestrator.log 2>/dev/null")
                    ring_stats['r4_timer_since'] = since[:16] if since else ''
                except: pass

                # Ring 6: Cisco Scanners (CodeGuard + MCP Scanner + Skill Scanner)
                try:
                    if os.path.exists(MCP_SCAN_FILE):
                        with open(MCP_SCAN_FILE) as msf:
                            mcp_scan = json.load(msf)
                        results = mcp_scan.get('scan_results', [])
                        ring_stats['r6_mcp_tools_scanned'] = len(results)
                        ring_stats['r6_mcp_threats'] = sum(1 for r in results if not r.get('is_safe', True))
                    else:
                        # Fall back to DB counts (scanners not available on macOS)
                        dbc = sqlite3.connect(EVENTS_DB)
                        ring_stats['r6_mcp_tools_scanned'] = dbc.execute('SELECT COUNT(DISTINCT tool_name) FROM mcp_scan_results').fetchone()[0]
                        ring_stats['r6_mcp_threats'] = dbc.execute("SELECT COUNT(DISTINCT tool_name) FROM mcp_scan_results WHERE is_safe=0").fetchone()[0]
                        dbc.close()
                        mcp_details = []
                        for r in results:
                            detail = {'name': r.get('tool_name', '?'), 'safe': r.get('is_safe', True)}
                            if not r.get('is_safe', True):
                                for analyzer, finding in r.get('findings', {}).items():
                                    detail['severity'] = finding.get('severity', 'HIGH')
                                    threats = finding.get('threats', {}).get('items', [])
                                    if threats:
                                        detail['threat'] = threats[0].get('technique_name', 'Unknown threat')
                            mcp_details.append(detail)
                        ring_stats['r6_mcp_details'] = mcp_details
                        # Persist to DB if file changed
                        global _last_mcp_mtime
                        mcp_mtime = os.path.getmtime(MCP_SCAN_FILE)
                        if mcp_mtime != _last_mcp_mtime:
                            _last_mcp_mtime = mcp_mtime
                            try:
                                dbc = sqlite3.connect(EVENTS_DB)
                                for r in results:
                                    sev = 'SAFE'
                                    threat = ''
                                    analyzer = ''
                                    for aname, finding in r.get('findings', {}).items():
                                        analyzer = aname
                                        if not r.get('is_safe', True):
                                            sev = finding.get('severity', 'HIGH')
                                            threats = finding.get('threats', {}).get('items', [])
                                            if threats:
                                                threat = threats[0].get('technique_name', '')
                                    dbc.execute('INSERT INTO mcp_scan_results (tool_name, tool_description, is_safe, severity, threat_name, threat_summary, analyzer) VALUES (?,?,?,?,?,?,?)',
                                        (r.get('tool_name',''), r.get('tool_description',''), r.get('is_safe',True),
                                         sev, threat, r.get('findings',{}).get(analyzer,{}).get('threat_summary',''), analyzer))
                                dbc.commit(); dbc.close()
                            except: pass
                        # Inject scan events into event stream
                        for detail in mcp_details:
                            sev = 'SAFE' if detail.get('safe') else detail.get('severity', 'HIGH')
                            entry = {
                                'time': time.strftime('%Y-%m-%dT%H:%M:%S'),
                                'type': 'SCAN',
                                'uid': 965,
                                'binary': 'mcp-scanner',
                                'args': f"{detail['name']}: {sev}" + (f" — {detail.get('threat','')}" if not detail.get('safe') else ''),
                                'policy': 'mcp-scanner' if not detail.get('safe') else '',
                                'is_agent': True,
                                'source': 'mcp-scan'
                            }
                            # Only inject once per scan (check if already in events)
                            # Only inject once per scan cycle
                            if not any(e.get('source') == 'mcp-scan' and e.get('args','').startswith(detail['name']) for e in list(memory_buffer)[-50:]):
                                append_event(entry)
                except: pass

                try:
                    # Scan the actual skills directory with skill-scanner
                    skills_dir = '/Users/aetherclaude/skills'
                    skill_results = []
                    total_findings = 0
                    if os.path.isdir(skills_dir):
                        scan_out = sh(f"skill-scanner scan {skills_dir} --lenient --format json 2>/dev/null")
                        if scan_out:
                            try:
                                parsed = json.loads(scan_out)
                                # Detect stub response from macOS no-op scanner
                                if isinstance(parsed, dict) and parsed.get('status') == 'skipped':
                                    skill_results = []
                                else:
                                    skill_results = parsed if isinstance(parsed, list) else [parsed]
                            except: skill_results = []
                        skills_scanned = len([f for f in os.listdir(skills_dir) if f.endswith('.md')])
                        total_findings = sum(r.get('findings_count', 0) for r in skill_results if isinstance(r, dict))
                        ring_stats['r6_skill_status'] = f'{skills_scanned} skills scanned' if total_findings == 0 else f'{total_findings} findings in {skills_scanned} skills'
                        ring_stats['r6_skills_scanned'] = skills_scanned
                        ring_stats['r6_skill_findings'] = total_findings
                        # Persist to DB (once per cycle, check mtime-like dedup via event stream)
                        if skill_results and not any(e.get('source') == 'skill-scan' for e in list(memory_buffer)[-20:]):
                            try:
                                dbc = sqlite3.connect(EVENTS_DB)
                                for r in skill_results:
                                    for f in r.get('findings', []):
                                        dbc.execute('INSERT INTO skill_scan_results (skill_name, is_safe, max_severity, findings_count, finding_id, finding_severity, finding_title, finding_description, finding_remediation, analyzers) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                            (r.get('skill_name',''), r.get('is_safe',True), r.get('max_severity',''),
                                             r.get('findings_count',0), f.get('rule_id',''), f.get('severity',''),
                                             f.get('title',''), f.get('description',''), f.get('remediation',''),
                                             ','.join(r.get('analyzers_used',[]))))
                                    if not r.get('findings'):
                                        dbc.execute('INSERT INTO skill_scan_results (skill_name, is_safe, max_severity, findings_count, finding_id, finding_severity, finding_title, analyzers) VALUES (?,?,?,?,?,?,?,?)',
                                            (r.get('skill_name',''), r.get('is_safe',True), r.get('max_severity','SAFE'),
                                             0, '', 'SAFE', 'No findings', ','.join(r.get('analyzers_used',[]))))
                                dbc.commit(); dbc.close()
                            except: pass
                    else:
                        ring_stats['r6_skill_status'] = 'no skills dir'
                    # Also check workspace .claude/commands/ for injected skills
                    workspace_cmds = '/Users/aetherclaude/workspace/AetherSDR/.claude/commands'
                    injected_files = []
                    if os.path.isdir(workspace_cmds):
                        injected_files = [f for f in os.listdir(workspace_cmds) if f.endswith('.md')]
                    ring_stats['r6_skill_injected'] = len(injected_files) > 0
                    ring_stats['r6_skill_injected_count'] = len(injected_files)
                    ring_stats['r6_skill_injected_files'] = injected_files
                    # Inject scan event
                    has_injected = len(injected_files) > 0
                    sev = 'SAFE' if total_findings == 0 and not has_injected else 'HIGH'
                    status_msg = ring_stats.get('r6_skill_status', 'unknown')
                    if has_injected: status_msg += f' — {len(injected_files)} command(s) in .claude/commands/'
                    entry = {
                        'time': time.strftime('%Y-%m-%dT%H:%M:%S'),
                        'type': 'SCAN', 'uid': 965, 'binary': 'skill-scanner',
                        'args': status_msg,
                        'policy': '' if sev == 'SAFE' else 'skill-scanner',
                        'is_agent': True, 'source': 'skill-scan'
                    }
                    if not any(e.get('source') == 'skill-scan' for e in list(memory_buffer)[-20:]):
                        append_event(entry)
                except Exception as _e: ring_stats['r6_skill_status'] = f'error: {_e}'

                # AIBOM: read C++ AI Bill of Materials
                try:
                    aibom_file = '/Users/aetherclaude/logs/aibom-latest.json'
                    if os.path.exists(aibom_file):
                        with open(aibom_file) as af:
                            aibom = json.load(af)
                        summary = aibom.get('aibom_analysis', {}).get('summary', {})
                        ring_stats['r6_aibom_components'] = summary.get('total_components', 0)
                        ring_stats['r6_aibom_models'] = summary.get('total_model_files', 0)
                        ring_stats['r6_aibom_neural'] = summary.get('has_neural_components', False)
                        # Persist to DB if file changed
                        global _last_aibom_mtime
                        aibom_mtime = os.path.getmtime(aibom_file)
                        if aibom_mtime != _last_aibom_mtime:
                            _last_aibom_mtime = aibom_mtime
                            try:
                                dbc = sqlite3.connect(EVENTS_DB)
                                for c in aibom.get('aibom_analysis', {}).get('components', []):
                                    dbc.execute('INSERT INTO aibom_components (name, category, description, detection, location, evidence) VALUES (?,?,?,?,?,?)',
                                        (c.get('name',''), c.get('category',''), c.get('description',''),
                                         c.get('detection',''), c.get('location',''), c.get('evidence','')))
                                dbc.commit(); dbc.close()
                            except: pass
                except: pass

                # Ring 6: CodeGuard — count files scanned and findings from validation log
                try:
                    scanned = findings = blocked = 0
                    with open(VALIDATION_LOG) as vf:
                        for vline in vf:
                            if 'Running CodeGuard' in vline: scanned += 1
                            if 'CodeGuard found' in vline: findings += 1
                            if 'BLOCKED: CodeGuard' in vline: blocked += 1
                    ring_stats['r6_files_scanned'] = scanned
                    ring_stats['r6_findings'] = findings
                    ring_stats['r6_blocked'] = blocked
                except: pass

                # Ring 5: Claude Code permissions
                try:
                    with open('/Users/aetherclaude/.claude/settings.json') as f:
                        s = json.load(f)
                        ring_stats['r5_denied_tools'] = len(s.get('permissions', {}).get('deny', []))
                except: pass

                # Ring 7: MCP stats from audit log
                try:
                    total = blocked = rate_limited = 0
                    mcp_breakdown = {}
                    with open(MCP_AUDIT_LOG) as f:
                        for line in f:
                            total += 1
                            if 'BLOCKED' in line: blocked += 1
                            if 'RATE LIMITED' in line: rate_limited += 1
                            try:
                                d = json.loads(line)
                                op = d.get('operation', '?')
                                mcp_breakdown[op] = mcp_breakdown.get(op, 0) + 1
                            except: pass
                    ring_stats['r7_mcp_ops'] = total
                    ring_stats['r7_blocked'] = blocked
                    ring_stats['r7_rate_limited'] = rate_limited
                    ring_stats['r7_mcp_breakdown'] = mcp_breakdown
                    ring_stats['r7_reads'] = sum(v for k,v in mcp_breakdown.items() if k.startswith(('read_','list_','get_','search_')))
                    ring_stats['r7_writes'] = sum(v for k,v in mcp_breakdown.items() if k.startswith(('comment_','create_')))
                except: pass

                # Ring 7: Parse orchestrator log for stats
                try:
                    dbc = sqlite3.connect(EVENTS_DB)
                    v_passed = dbc.execute("SELECT COUNT(*) FROM validation_runs WHERE result='PASSED'").fetchone()[0]
                    v_failed = dbc.execute("SELECT COUNT(*) FROM validation_runs WHERE result='FAILED'").fetchone()[0]
                    dbc.close()
                    ring_stats['r8_validation_checks'] = v_passed + v_failed
                    ring_stats['r8_validation_passed'] = v_passed
                    ring_stats['r8_validation_failed'] = v_failed
                except: pass

                # Ring 9: PR stats from GitHub via app token
                try:
                    import urllib.request
                    token = sh('HTTPS_PROXY=http://127.0.0.1:8888 /Users/aetherclaude/bin/github-app-token.sh')
                    bot_logins = os.environ.get('BOT_USERNAME', 'aethersdr-agent[bot]')
                    agent_logins = ('AetherClaude', bot_logins)
                    if token:
                        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': 'http://127.0.0.1:8888'}))
                        hdrs = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github+json', 'User-Agent': 'AetherClaude-Dashboard'}
                        # Fetch open PRs separately to ensure we get them all
                        open_prs = []
                        try:
                            req_open = urllib.request.Request(
                                'https://api.github.com/repos/ten9876/AetherSDR/pulls?state=open&per_page=100', headers=hdrs)
                            open_prs = json.loads(opener.open(req_open, timeout=10).read().decode())
                        except: pass
                        # Fetch closed/merged PRs
                        closed_prs = []
                        try:
                            req_closed = urllib.request.Request(
                                'https://api.github.com/repos/ten9876/AetherSDR/pulls?state=closed&sort=updated&direction=desc&per_page=100', headers=hdrs)
                            closed_prs = json.loads(opener.open(req_closed, timeout=10).read().decode())
                        except: pass
                        ac_open = [p for p in open_prs if p.get('user', {}).get('login') in agent_logins]
                        ac_closed = [p for p in closed_prs if p.get('user', {}).get('login') in agent_logins]
                        ac_merged = [p for p in ac_closed if p.get('merged_at')]
                        ac_rejected = [p for p in ac_closed if not p.get('merged_at')]
                        ring_stats['r9_prs_total'] = len(ac_open) + len(ac_closed)
                        ring_stats['r9_prs_merged'] = len(ac_merged)
                        ring_stats['r9_prs_rejected'] = len(ac_rejected)
                        ring_stats['r9_prs_open'] = len(ac_open)
                        ring_stats['r9_pr_details'] = {
                            'open': [{'number': p['number'], 'title': p['title'], 'draft': p.get('draft', False)} for p in ac_open],
                            'merged': [{'number': p['number'], 'title': p['title']} for p in ac_merged][:20],
                            'rejected': [{'number': p['number'], 'title': p['title']} for p in ac_rejected][:20],
                        }
                except: pass

                # Read issue pipeline state from DB (no GitHub API needed)
                try:
                    dbc = sqlite3.connect(ISSUE_ACTIONS_DB)
                    rows = dbc.execute("""
                        SELECT ia.issue_number, ia.state, ia.outcome, ia.action, ia.detail, ia.created_at
                        FROM issue_actions ia
                        INNER JOIN (
                            SELECT issue_number, MAX(id) as max_id
                            FROM issue_actions GROUP BY issue_number
                        ) latest ON ia.issue_number=latest.issue_number AND ia.id=latest.max_id
                        ORDER BY ia.id DESC LIMIT 30
                    """).fetchall()
                    dbc.close()
                    ring_stats['r9_issue_details'] = [
                        {'number': r[0], 'state': r[1], 'outcome': r[2],
                         'last_action': r[3], 'detail': r[4] or '', 'last_seen': r[5]}
                        for r in rows
                    ]
                except: pass

                # Fetch recent discussions
                try:
                    if token:
                        gql_body = json.dumps({'query': 'query{repository(owner:"ten9876",name:"AetherSDR"){discussions(first:20,orderBy:{field:UPDATED_AT,direction:DESC}){nodes{number title category{name} comments{totalCount}}}}}'}).encode()
                        req_d = urllib.request.Request(
                            'https://api.github.com/graphql', data=gql_body,
                            headers={'Authorization': f'bearer {token}', 'Content-Type': 'application/json', 'User-Agent': 'AetherClaude-Dashboard'})
                        disc_out = opener.open(req_d, timeout=10).read().decode()
                        disc_data = json.loads(disc_out)
                        nodes = disc_data.get('data', {}).get('repository', {}).get('discussions', {}).get('nodes', [])
                        ring_stats['r9_discussion_details'] = [{'number': d['number'], 'title': d['title'], 'category': d.get('category',{}).get('name',''), 'comments': d.get('comments',{}).get('totalCount',0)} for d in nodes if d.get('comments',{}).get('totalCount',0) > 0][:20]
                except: pass

                # Recent activity: parse MCP audit for agent interactions
                try:
                    recent = []
                    with open(MCP_AUDIT_LOG) as af:
                        for aline in af:
                            try:
                                ad = json.loads(aline)
                                op = ad.get('operation', '')
                                ts = ad.get('timestamp', '')
                                try:
                                    result = json.loads(ad.get('result', '{}'))
                                except:
                                    result = {}
                                url = result.get('url', result.get('html_url', ''))
                                # Redact any auth headers in result data
                                for k in list(result.keys()):
                                    if isinstance(result[k], str):
                                        result[k] = re.sub(r'Authorization: (token|Bearer) [A-Za-z0-9_-]+', 'Authorization: \\1 ***', result[k])
                                num = result.get('number', '')
                                labels = {
                                    'comment_on_issue': 'Commented on issue',
                                    'create_pull_request': 'Created PR',
                                    'comment_on_discussion': 'Replied to discussion',
                                    'read_discussion': 'Read discussion',
                                    'read_issue': 'Read issue',
                                    'search_issues': 'Searched issues',
                                    'create_pr_review': 'Reviewed PR',
                                    'list_open_prs': 'Listed PRs',
                                    'get_check_runs': 'Checked CI',
                                }
                                label = labels.get(op, op)
                                # Extract number from result or from the operation endpoint
                                if not num:
                                    ep = ad.get('operation', '')
                                    m2 = re.search(r'/issues/(\d+)|/pulls/(\d+)|/discussions/(\d+)', ep)
                                    if m2:
                                        num = m2.group(1) or m2.group(2) or m2.group(3)
                                    # Also check args_data if present
                                    args_data = ad.get('args_data', {})
                                    if isinstance(args_data, dict):
                                        num = str(args_data.get('issue_number', args_data.get('pr_number', args_data.get('discussion_number', num or ''))))
                                write_ops = ('comment_on_issue', 'create_pull_request', 'create_pr_review', 'comment_on_discussion')
                                if (url or num) and op in write_ops:
                                    recent.append({'op': label, 'url': url, 'num': str(num), 'time': ts[:19]})
                            except:
                                pass
                    ring_stats['recent_activity'] = recent[-20:]
                except:
                    pass

                # Parse orchestrator log for issue titles
                try:
                    import re
                    issue_titles = {}
                    with open(ORCHESTRATOR_LOG) as of:
                        for oline in of:
                            m = re.search(r'Processing issue #(\d+): (.+)', oline)
                            if m:
                                issue_titles[m.group(1)] = m.group(2)
                            m = re.search(r'Responding to discussion #(\d+): (.+)', oline)
                            if m:
                                issue_titles['d' + m.group(1)] = m.group(2)
                    ring_stats['issue_titles'] = issue_titles
                except:
                    pass

        except: pass
        db_purge_if_needed(250)
        time.sleep(RING_REFRESH_SECS)

def scan_tokens():
    while True:
        try:
            total_in = total_out = total_cr = total_cc = total_msgs = 0
            for f in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
                if '/subagents/' in f: continue
                try:
                    with open(f) as fh:
                        for line in fh:
                            if '"usage"' not in line: continue
                            d = json.loads(line)
                            u = d.get('message', {}).get('usage', {})
                            if u:
                                total_in += u.get('input_tokens', 0)
                                total_out += u.get('output_tokens', 0)
                                total_cr += u.get('cache_read_input_tokens', 0)
                                total_cc += u.get('cache_creation_input_tokens', 0)
                                total_msgs += 1
                except: continue
            # Also count tool calls
            tool_total = 0
            tool_bd = defaultdict(int)
            for f2 in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
                if '/subagents/' in f2: continue
                try:
                    with open(f2) as fh2:
                        for line2 in fh2:
                            if '"tool_use"' not in line2: continue
                            d2 = json.loads(line2)
                            for c in d2.get('message', {}).get('content', []):
                                if c.get('type') == 'tool_use':
                                    name = c.get('name', '?')
                                    tool_total += 1
                                    tool_bd[name] += 1
                except: continue

            with lock:
                token_stats['input'] = total_in
                token_stats['output'] = total_out
                token_stats['cache_read'] = total_cr
                token_stats['cache_create'] = total_cc
                token_stats['messages'] = total_msgs
                tool_stats['total'] = tool_total
                tool_stats['breakdown'] = dict(tool_bd)
        except: pass
        time.sleep(TOKEN_REFRESH_SECS)

def tail_validation_log(logfile):
    current_run = {'time': '', 'files': 0, 'blocked': []}
    while not os.path.exists(logfile): time.sleep(5)
    with open(logfile) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line: time.sleep(1); continue
            line = line.strip()
            if not line or 'VALIDATE:' not in line: continue
            with lock:
                parts = line.split(' VALIDATE: ', 1)
                ts = parts[0] if len(parts) > 1 else ''
                msg = parts[1] if len(parts) > 1 else line
                # Track validation runs
                if msg.startswith('Validating '):
                    current_run = {'time': ts, 'files': 0, 'blocked': []}
                    try: current_run['files'] = int(msg.split()[1])
                    except: pass
                elif 'BLOCKED' in msg:
                    current_run['blocked'].append(msg.replace('BLOCKED: ', ''))
                    stats['alerts'].append({'time': ts, 'msg': f"VALIDATION: {msg}", 'severity': 'high'})
                elif msg.startswith('PASSED:') or msg.startswith('FAILED:'):
                    result = 'PASSED' if msg.startswith('PASSED') else 'FAILED'
                    try:
                        dbc = sqlite3.connect(EVENTS_DB)
                        dbc.execute('INSERT INTO validation_runs (run_time, files_count, result, blocked_reasons) VALUES (?,?,?,?)',
                            (current_run['time'], current_run['files'], result, '\n'.join(current_run['blocked'])))
                        dbc.commit(); dbc.close()
                    except: pass
                entry = {'time': ts, 'type': 'GUARD', 'uid': 965, 'binary': 'codeguard', 'args': msg[:120], 'policy': 'codeguard' if 'CodeGuard' in msg else 'validation-gate', 'is_agent': True, 'source': 'codeguard'}
                append_event(entry)

def tail_mcp_audit(logfile):
    while not os.path.exists(logfile): time.sleep(5)
    with open(logfile) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line: time.sleep(1); continue
            try:
                d = json.loads(line.strip())
                with lock:
                    op = d.get('operation', '?')
                    result_preview = d.get('result', '')[:80]
                    result_preview = re.sub(r"Authorization: (token|Bearer) [A-Za-z0-9_-]+", "Authorization: \\1 ***", result_preview)
                    entry = {'time': d.get('timestamp', ''), 'type': 'MCP', 'uid': 965, 'binary': 'mcp-server', 'args': f"{op} → {result_preview}", 'policy': '', 'is_agent': True, 'source': 'mcp'}
                    if 'BLOCKED' in result_preview or 'RATE LIMITED' in result_preview:
                        entry['policy'] = 'mcp-blocked'
                        stats['alerts'].append({'time': d.get('timestamp', ''), 'msg': f"MCP: {op} — {result_preview}", 'severity': 'high'})
                    append_event(entry)
            except: continue

def tail_tinyproxy_log():
    """Watch tinyproxy log for proxy connections and denials."""
    import subprocess, re, platform
    logfile = '/Users/aetherclaude/logs/tinyproxy-access.log'
    import time as _time
    while not os.path.exists(logfile):
        _time.sleep(5)
    f = open(logfile, 'r')
    f.seek(0, 2)  # seek to end
    while True:
        line = f.readline()
        if not line:
            _time.sleep(1)
            continue
        line = line.strip()
        if not line:
            continue
        with lock:
            ts = _time.strftime('%Y-%m-%dT%H:%M:%S')

            if 'Proxying refused on filtered domain' in line:
                m = re.search(r'filtered domain "([^"]+)"', line)
                domain = m.group(1) if m else '?'
                ring_stats['r2_denied'] += 1
                entry = {
                    'time': ts, 'type': 'PROXY', 'uid': 965,
                    'binary': 'tinyproxy', 'args': f"DENIED: {domain}",
                    'policy': 'domain-filter', 'is_agent': True, 'source': 'tinyproxy'
                }
                append_event(entry)
                # Alert generated by append_event()

            elif 'Established connection to host' in line:
                m = re.search(r'host "([^"]+)"', line)
                domain = m.group(1) if m else '?'
                ring_stats['r2_allowed'] += 1
                entry = {
                    'time': ts, 'type': 'PROXY', 'uid': 965,
                    'binary': 'tinyproxy', 'args': f"ALLOWED: {domain}",
                    'policy': '', 'is_agent': True, 'source': 'tinyproxy'
                }
                append_event(entry)

def tail_nftables_log():
    """Watch pf log for blocked packets. On macOS, Ring 1 uses pfctl counters instead."""
    return  # pf counters are read in scan_rings() — no live log tailing needed on macOS
    import subprocess, re, time as _time
    for line in proc.stdout:
        line = line.strip()
        if not line or 'block' not in line:
            continue
        with lock:
            ts = _time.strftime('%Y-%m-%dT%H:%M:%S')
            # Parse tcpdump pflog output: "... block out ... > dst.port: ..."
            dst = ''
            m = re.search(r'> (\S+?)[\.:]\s', line)
            if m: dst = m.group(1)

            entry = {
                'time': ts,
                'type': 'BLOCK',
                'uid': 965,
                'binary': 'pf',
                'args': f"Outbound blocked: {dst}" if dst else f"Blocked: {line[:80]}",
                'policy': 'pf-firewall',
                'is_agent': True,
                'source': 'nftables'
            }
            append_event(entry)
            stats['alerts'].append({'time': entry['time'], 'msg': f"FIREWALL: Blocked {detail}", 'severity': 'high'})

def tail_sessions():
    """Watch Claude Code session files for tool_use events."""
    import glob, re
    seen_files = set()
    last_positions = {}

    while True:
        try:
            # Find all session files
            files = glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True)
            files = [f for f in files if '/subagents/' not in f]

            for filepath in files:
                try:
                    size = os.path.getsize(filepath)
                    last_pos = last_positions.get(filepath, 0)

                    # Skip if file hasn't grown
                    if size <= last_pos:
                        continue

                    with open(filepath, 'r') as f:
                        f.seek(last_pos)
                        new_content = f.read()
                        last_positions[filepath] = f.tell()

                    for line in new_content.strip().split('\n'):
                        if 'tool_use' not in line:
                            continue
                        try:
                            d = json.loads(line)
                            ts = d.get('timestamp', '')
                            for content in d.get('message', {}).get('content', []):
                                if content.get('type') != 'tool_use':
                                    continue
                                name = content.get('name', '?')
                                inp = content.get('input', {})

                                if name == 'Read':
                                    detail = (inp.get('file_path') or '').split('/')[-1]
                                elif name in ('Edit', 'Write'):
                                    detail = (inp.get('file_path') or '').split('/')[-1]
                                elif name == 'Grep':
                                    detail = (inp.get('pattern') or '')[:40]
                                elif name == 'Glob':
                                    detail = (inp.get('pattern') or '')[:40]
                                elif name == 'Bash':
                                    cmd = (inp.get('command') or '')[:60]
                                    # Redact any credentials in bash commands
                                    cmd = re.sub(r'ghp_[A-Za-z0-9]{10,}', 'ghp_***', cmd)
                                    cmd = re.sub(r'ghs_[A-Za-z0-9]{10,}', 'ghs_***', cmd)
                                    detail = cmd
                                elif 'mcp__' in name:
                                    detail = name.split('__')[-1]
                                    name = 'MCP'
                                else:
                                    detail = ''

                                with lock:
                                    entry = {
                                        'time': ts,
                                        'type': 'TOOL',
                                        'uid': 965,
                                        'binary': f'claude:{name}',
                                        'args': detail,
                                        'policy': '',
                                        'is_agent': True,
                                        'source': 'claude-code'
                                    }
                                    append_event(entry)
                        except:
                            continue
                except (PermissionError, FileNotFoundError):
                    continue
        except:
            pass
        time.sleep(2)

def tail_orchestrator_skills(logfile):
    """Watch orchestrator log for skill dispatch events."""
    import re
    while not os.path.exists(logfile):
        time.sleep(5)
    with open(logfile, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue

            skill = None
            detail = None

            m = re.search(r'TRIAGE: Analyzing issue #(\d+)', line)
            if m: skill = 'triage-issue'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'IMPLEMENT: Fixing issue #(\d+)', line)
            if m: skill = 'implement-fix'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'Reviewing PR #(\d+): (.+)', line)
            if m: skill = 'review-pr'; detail = f'PR #{m.group(1)}: {m.group(2)[:40]}'

            m = re.search(r'Checking #(\d+) for duplicates', line)
            if m: skill = 'detect-duplicate'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'Responding to discussion #(\d+)', line)
            if m: skill = 'respond-discussion'; detail = f'Discussion #{m.group(1)}'

            m = re.search(r'Skill: @Mention Response \(Issue #(\d+)\)', line)
            if m: skill = '@mention'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'@Mention Response complete for #(\d+)', line)
            if m: skill = '@mention-done'; detail = f'Issue #{m.group(1)} responded'

            m = re.search(r'MCP Scanner: (.+)', line)
            if m: skill = 'mcp-scanner'; detail = m.group(1)

            m = re.search(r'Skill Scanner: (.+)', line)
            if m: skill = 'skill-scanner'; detail = m.group(1)

            if skill:
                ts = line[:19] if len(line) > 19 else ''
                with lock:
                    entry = {
                        'time': ts,
                        'type': 'SKILL',
                        'uid': 965,
                        'binary': f'skill:{skill}',
                        'args': detail,
                        'policy': '',
                        'is_agent': True,
                        'source': 'skill-dispatch'
                    }
                    append_event(entry)

def tail_log(logfile):
    while not os.path.exists(logfile): time.sleep(1)
    with open(logfile) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line: time.sleep(0.2); continue
            try: process_event(json.loads(line.strip()))
            except: continue

def process_event(event):
    with lock:
        stats['total_events'] += 1
        entry = {'time': event.get('time', ''), 'type': '', 'uid': '', 'binary': '', 'args': '', 'policy': '', 'is_agent': False, 'source': 'tetragon'}
        if 'process_exec' in event:
            p = event['process_exec']['process']
            entry.update({'type': 'EXEC', 'uid': p.get('uid', '?'), 'binary': p.get('binary', ''), 'args': p.get('arguments', '')[:120]})
            stats['exec_count'] += 1
            stats['binaries_seen'][os.path.basename(entry['binary'])] += 1
        elif 'process_kprobe' in event:
            p = event['process_kprobe']['process']
            entry.update({'type': 'KPROBE', 'uid': p.get('uid', '?'), 'binary': p.get('binary', ''), 'args': event['process_kprobe'].get('function_name', ''), 'policy': event['process_kprobe'].get('policy_name', '')})
            stats['kprobe_count'] += 1
            if entry['policy']: stats['policy_hits'][entry['policy']] += 1
            if 'tcp_connect' in entry['args']: stats['network_connections'] += 1
        elif 'process_exit' in event:
            p = event['process_exit']['process']
            entry.update({'type': 'EXIT', 'uid': p.get('uid', '?'), 'binary': p.get('binary', '')})
            stats['exit_count'] += 1
        else: return
        # Redact credentials from args before storing
        if entry.get('args'):
            entry['args'] = re.sub(r'ghp_[A-Za-z0-9]{36}', 'ghp_***', entry['args'])
            entry['args'] = re.sub(r'ghs_[A-Za-z0-9]{36}', 'ghs_***', entry['args'])
            entry['args'] = re.sub(r'github_pat_[A-Za-z0-9_]{20,}', 'github_pat_***', entry['args'])
            entry['args'] = re.sub(r'sk-ant-[A-Za-z0-9\-]{20,}', 'sk-ant-***', entry['args'])
            entry['args'] = re.sub(r'Authorization: (token|Bearer) [A-Za-z0-9_\-]+', 'Authorization: \1 ***', entry['args'])
        entry['is_agent'] = (entry['uid'] == AETHERCLAUDE_UID)
        if entry['is_agent']:
            stats['aetherclaude_events'] += 1
            if entry['type'] == 'EXEC':
                ring_stats['r3_agent_cmds'] = ring_stats.get('r3_agent_cmds', 0) + 1
        if entry['policy'] and 'canary' in entry['policy']:
            stats['alerts'].append({'time': entry['time'], 'msg': f"CANARY: {entry['binary']} accessed tripwire", 'severity': 'critical'})
        elif entry['policy'] and 'priv-escalation' in entry['policy'] and entry['is_agent']:
            stats['alerts'].append({'time': entry['time'], 'msg': f"PRIV: {entry['binary']} → {entry['args']}", 'severity': 'high'})
        if entry['binary'] in NOISE_BINARIES and not entry['is_agent']:
            stats['suppressed'] += 1; return
        append_event(entry)

HTML = r"""<!DOCTYPE html>
<html><head><title>AetherClaude Defense-in-Depth Dashboard</title><meta charset="utf-8">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a1a;color:#c8d8e8;font-family:'SF Mono','Fira Code',monospace;font-size:13px}
.header{background:#101028;padding:12px 24px;border-bottom:1px solid #203040;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px;color:#00b4d8;text-transform:uppercase;letter-spacing:4px;font-weight:300}
.header .sub{color:#607080;font-size:11px}
.header .live{color:#00ff88;font-size:12px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.rings{display:grid;grid-template-columns:repeat(9,1fr);gap:8px;padding:12px 24px}
.ring{background:#101028;border:1px solid #203040;border-radius:8px;padding:10px;text-align:center;position:relative}
.ring .num{font-size:10px;color:#404060;position:absolute;top:4px;left:8px}
.ring .name{font-size:10px;color:#8090a0;margin-bottom:4px}
.ring .value{font-size:22px;font-weight:bold;color:#00b4d8}
.ring .detail{font-size:10px;color:#8898a8;margin-top:2px}
.ring.ok{border-color:#00ff8844}
.ring.warn{border-color:#ffaa0044}
.ring.alert{border-color:#ff444444}
.ring .status{width:8px;height:8px;border-radius:50%;display:inline-block;position:absolute;top:6px;right:8px}
.ring .status.green{background:#00ff88}
.ring .status.yellow{background:#ffaa00}
.ring .status.red{background:#ff4444}

.filter-bar{padding:6px 24px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filter-bar label{color:#607080;font-size:11px}
.fbtn{background:#203040;border:1px solid #304050;color:#c8d8e8;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px;font-family:inherit}
.fbtn.active{background:#00b4d8;color:#0a0a1a;border-color:#00b4d8}
.fbtn:hover{border-color:#00b4d8}
.fbtn.guard{border-color:#ff6688}.fbtn.mcp-f{border-color:#aa88ff}
.finput{background:#101028;border:1px solid #304050;color:#c8d8e8;padding:3px 8px;border-radius:4px;font-size:11px;font-family:inherit;width:130px}

.main{display:grid;grid-template-columns:2fr 1fr;gap:10px;padding:0 24px 12px;height:calc(100vh - 310px)}
.panel{background:#101028;border:1px solid #203040;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.phdr{padding:6px 10px;background:#181830;border-bottom:1px solid #203040;font-size:11px;color:#00b4d8;font-weight:bold;display:flex;justify-content:space-between}
.pbody{overflow-y:auto;flex:1;padding:2px}

.ev{padding:2px 8px;border-bottom:1px solid #0f0f20;display:flex;gap:6px;font-size:11px}
.ev:hover{background:#181830}
.ev.agent{background:#0a1a0a;border-left:3px solid #00ff88}
.ev.guard{background:#1a0a10;border-left:3px solid #ff6688}
.ev.mcp{background:#0f0a1a;border-left:3px solid #aa88ff}
.ev .tp{width:50px;font-weight:bold}
.tp.EXEC{color:#00b4d8}.tp.KPROBE{color:#ffaa00}.tp.EXIT{color:#607080}.tp.GUARD{color:#ff6688}.tp.MCP{color:#aa88ff}.tp.BLOCK{color:#ff4444;font-weight:bold}.tp.PROXY{color:#44ddaa}
.ev.nftables{background:#1a0808;border-left:3px solid #ff4444}
.ev.tinyproxy{background:#081a10;border-left:3px solid #44ddaa}
.stag.nftables{background:#301010;color:#ff4444}
.stag.mcp-scan{background:#102030;color:#00ddff}
.stag.skill-scan{background:#201030;color:#dd88ff}
.ev.mcp-scan{background:#081018;border-left:3px solid #00ddff}
.ev.skill-scan{background:#100818;border-left:3px solid #dd88ff}
.tp.SCAN{color:#00ddff}
.tp.TOOL{color:#ff88cc}
.tp.SKILL{color:#ffdd44}
.ev.skill-dispatch{background:#181808;border-left:3px solid #ffdd44}
.ev.webhook{background:#081018;border-left:3px solid #44aaff}
.stag.skill-dispatch{background:#202010;color:#ffdd44}
.ev.claude-code{background:#180818;border-left:3px solid #ff88cc}
.stag.claude-code{background:#201020;color:#ff88cc}
.stag.tinyproxy{background:#103020;color:#44ddaa}
.ev .uid{width:40px;color:#888}
.ev .bin{width:150px;color:#e0e0e0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .args{flex:1;color:#888;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .pol{color:#ffaa00;font-size:10px}
.ev .tm{width:70px;color:#505060;font-size:10px}
.stag{font-size:8px;padding:1px 3px;border-radius:2px;margin-left:3px}
.stag.tetragon{background:#203040;color:#00b4d8}
.stag.codeguard{background:#301020;color:#ff6688}
.stag.mcp{background:#1a1030;color:#aa88ff}

.si{padding:5px 10px;border-bottom:1px solid #0f0f20;display:flex;justify-content:space-between;font-size:11px}
.si .n{color:#c8d8e8}.si .c{color:#00b4d8;font-weight:bold}
.ai{padding:6px 10px;border-bottom:1px solid #0f0f20}
.ai.critical{border-left:3px solid #f00;background:#1a0a0a}
.ai.high{border-left:3px solid #ffaa00;background:#1a1a0a}
.ai .msg{font-size:11px}.ai .at{font-size:9px;color:#505060}
.rpanels{display:flex;flex-direction:column;gap:8px;overflow:hidden}
.rpanels .pbody{max-height:25vh}
.muted{color:#404050}
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:#101028;border:1px solid #304050;border-radius:12px;padding:20px;max-width:700px;width:90%;max-height:80vh;overflow-y:auto;color:#c8d8e8}
.modal h2{color:#00b4d8;margin-bottom:12px;font-size:16px;text-transform:uppercase;letter-spacing:2px}
.modal-close{float:right;cursor:pointer;color:#607080;font-size:20px;border:none;background:none}
.modal-close:hover{color:#ff4444}
.modal-finding{padding:8px 12px;margin:6px 0;border-radius:6px;font-size:12px}
.modal-finding.HIGH{background:#1a0a0a;border-left:3px solid #ff4444}
.modal-finding.MEDIUM{background:#1a1a0a;border-left:3px solid #ffaa00}
.modal-finding.LOW{background:#0a1a0a;border-left:3px solid #44ddaa}
.modal-finding.SAFE{background:#0a0a1a;border-left:3px solid #203040}
.modal-finding .sev{font-weight:bold;margin-right:8px}
.modal-finding .sev.HIGH{color:#ff4444}.modal-finding .sev.MEDIUM{color:#ffaa00}.modal-finding .sev.SAFE{color:#00ff88}
.modal-finding .tool-name{color:#00b4d8}
.modal-finding .detail{color:#888;font-size:11px;margin-top:4px}
.modal-overlay.wp .modal{max-width:900px;max-height:90vh}
.wp-content{line-height:1.7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;color:#c8d8e8}
.wp-content h1{color:#00b4d8;font-size:22px;margin:24px 0 8px;letter-spacing:1px;text-align:center}
.wp-content h2{color:#00b4d8;font-size:17px;margin:20px 0 8px;border-bottom:1px solid #203040;padding-bottom:4px}
.wp-content h3{color:#4090d0;font-size:14px;margin:16px 0 6px}
.wp-content p{margin:8px 0}
.wp-content ul,ol{margin:8px 0 8px 20px}
.wp-content li{margin:4px 0}
.wp-content strong{color:#e0e8f0}
.wp-content table{border-collapse:collapse;width:100%;margin:12px 0;font-size:12px}
.wp-content th{background:#182030;color:#00b4d8;padding:8px 10px;text-align:left;border:1px solid #304050}
.wp-content td{padding:6px 10px;border:1px solid #203040}
.wp-content tr:nth-child(even){background:#0c0c1e}
.wp-content code{background:#182030;padding:1px 4px;border-radius:3px;font-family:'SF Mono','Fira Code',monospace;font-size:12px;color:#44ddaa}
.wp-content .cisco{color:#00bceb}
.wp-content .highlight{background:#101820;border-left:3px solid #00b4d8;padding:8px 12px;margin:10px 0;border-radius:4px}
.wp-content .meta{color:#607080;font-size:11px;text-align:center;margin:8px 0 20px}
.clickable{cursor:pointer;transition:background .2s}.clickable:hover{background:#181830}
</style></head><body>

<div class="header">
<img src="/logo.png" style="height:48px;margin-right:16px;border-radius:50%">
<div style="flex:1"><h1>AetherClaude Defense-in-Depth Dashboard</h1>
<div class="sub">Cisco Isovalent (Tetragon) &middot; Cisco DefenseClaw CodeGuard &middot; Cisco AI Defense &middot; MCP Token Isolation</div></div>
<a href="#" onclick="showWhitepaper();return false" style="color:#607080;font-size:11px;text-decoration:none;margin-right:16px;border:1px solid #304050;padding:4px 10px;border-radius:6px;white-space:nowrap" onmouseover="this.style.color='#00b4d8';this.style.borderColor='#00b4d8'" onmouseout="this.style.color='#607080';this.style.borderColor='#304050'">Agent Defense-in-Depth Whitepaper</a>
<div class="live" id="agent-status">&#9679; LIVE</div>
</div>

<div class="rings">
<div class="ring ok clickable" id="ring1" onclick="showRingEvents('nftables','Ring 1: nftables','Kernel-level packet filtering by UID — blocked outbound connections')"><span class="num">1 &gt;</span><span class="status green"></span>
<div class="name">nftables</div><div class="value" id="r1v">0</div><div class="detail">packets blocked</div></div>

<div class="ring ok clickable" id="ring2" onclick="showRingEvents('tinyproxy','Ring 2: tinyproxy','Domain-level HTTPS filtering — allowed and denied connections')"><span class="num">2 &gt;</span><span class="status green"></span>
<div class="name">tinyproxy</div><div class="value" id="r2v">0</div><div class="detail" id="r2d">allowed · 0 denied</div></div>

<div class="ring ok clickable" id="ring3" onclick="showRingEvents('tetragon','Ring 3: OS Isolation (Tetragon eBPF)','Process exec, syscalls, network connections for UID 965')"><span class="num">3 &gt;</span><span class="status green"></span>
<div class="name">OS Isolation</div><div class="value" id="r3v">0</div><div class="detail" id="r3d">agent cmds · rbash</div></div>

<div class="ring ok clickable" id="ring4" onclick="showRing4()"><span class="num">4 &gt;</span><span class="status green"></span>
<div class="name">systemd Sandbox</div><div class="value" id="r4v">0</div><div class="detail" id="r4d">sandboxed runs</div></div>

<div class="ring ok clickable" id="ring5" onclick="showRingEvents('claude-code','Ring 5: Claude Code Permissions','Tool calls tracked — per-tool type breakdown')"><span class="num">5 &gt;</span><span class="status green"></span>
<div class="name">Claude Code</div><div class="value" id="r5v">0</div><div class="detail" id="r5d">tool calls</div></div>

<div class="ring ok clickable" id="ring6" onclick="showRingEvents('codeguard','Ring 6: Cisco AI Defense','CodeGuard static analysis, MCP Scanner, Skill Scanner events')"><span class="num">6 &gt;</span><span class="status green"></span>
<div class="name">CodeGuard</div><div class="value" id="r6v">0</div><div class="detail" id="r6d">files scanned</div></div>

<div class="ring ok clickable" id="ring7" onclick="showRingEvents('mcp','Ring 7: MCP Token Isolation','GitHub API operations, content validation, rate limiting')"><span class="num">7 &gt;</span><span class="status green"></span>
<div class="name">MCP Isolation</div><div class="value" id="r7v">0</div><div class="detail" id="r7d">ops · 0 blocked</div></div>

<div class="ring ok clickable" id="ring8" onclick="showValidation()"><span class="num">8 &gt;</span><span class="status green"></span>
<div class="name">Validation Gate</div><div class="value" id="r8v">0</div><div class="detail" id="r8d">checks · 0 failed</div></div>

<div class="ring ok clickable" id="ring9" style="border-color:#d4af37" onclick="showRing9()"><span class="num" style="color:#d4af37">9</span><span class="status green"></span>
<div class="name" style="color:#d4af37">Human Review</div><div class="value" id="r9v">0</div><div class="detail" id="r9d">merged · 0 rejected</div></div>
</div>

<div class="filter-bar">
<button class="fbtn active" onclick="setFilter('')">All</button>
<button class="fbtn" onclick="setFilter('is_agent')">Agent</button>
<button class="fbtn" onclick="setFilter('EXEC')">EXEC</button>
<button class="fbtn" onclick="setFilter('KPROBE')">KPROBE</button>
<button class="fbtn" onclick="setFilter('tetragon')">Tetragon</button>
<button class="fbtn" onclick="setFilter('nftables')" style="border-color:#ff4444">Firewall</button>
<button class="fbtn" onclick="setFilter('tinyproxy')" style="border-color:#44ddaa">Proxy</button>
<button class="fbtn" onclick="setFilter('codeguard')" style="border-color:#ff6688">CodeGuard</button>
<button class="fbtn" onclick="setFilter('mcp')" style="border-color:#aa88ff">MCP</button>
<button class="fbtn" onclick="setFilter('skill')" style="border-color:#ffdd44">Skills</button>
<button class="fbtn" onclick="setFilter('claude-code')" style="border-color:#ff88cc">Claude</button>
<button class="fbtn" onclick="setFilter('webhook')" style="border-color:#44aaff">Webhook</button>
<label style="margin-left:8px">Search:</label>
<input class="finput" id="search" placeholder="grep pattern..." oninput="debouncedRefresh()" style="width:250px">
<span class="muted" id="sc"></span>
</div>

<div class="main">
<div class="panel">
<div class="phdr"><span>Event Stream &middot; <span style="color:#00ff88">&#9632;</span> Agent <span style="color:#ff4444">&#9632;</span> Firewall <span style="color:#44ddaa">&#9632;</span> Proxy <span style="color:#ff6688">&#9632;</span> CodeGuard <span style="color:#aa88ff">&#9632;</span> MCP <span style="color:#00ddff">&#9632;</span> Scanners <span style="color:#ffdd44">&#9632;</span> Skills <span style="color:#ff88cc">&#9632;</span> Claude</span><span class="muted" id="sup"></span></div>
<div class="pbody" id="evts"></div>
</div>
<div class="rpanels">
<div class="panel" style="flex:.7">
<div class="phdr">Token Usage (Claude MAX)</div>
<div class="pbody" id="tp"></div>
</div>
<div class="panel" style="flex:.7">
<div class="phdr">GitHub Activity</div>
<div class="pbody" id="github-activity"></div>
</div>
<div class="panel" style="flex:.8">
<div class="phdr">Cisco AI Defense Scanners</div>
<div class="pbody" id="cisco-scanners"></div>
</div>
<div class="panel" style="flex:.7">
<div class="phdr">Recent Agent Activity</div>
<div class="pbody" id="pols"></div>
</div>
<div class="panel" style="flex:1">
<div class="phdr">Alerts</div>
<div class="pbody" id="als"></div>
</div>
</div>
</div>

<script>
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
let _refreshTimer=null;
function debouncedRefresh(){clearTimeout(_refreshTimer);_refreshTimer=setTimeout(refresh,300)}
function setFilter(q){
document.getElementById('search').value=q;
document.querySelectorAll('.filter-bar .fbtn').forEach(b=>b.classList.remove('active'));
event.target.classList.add('active');
refresh()}
function renderEvents(events,total,filtered){
let h='';
for(const e of events){
let t='';
if(e.time){try{const dt=new Date(e.time);t=dt.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch{t=e.time.substring(11,19)}}
let c='ev';if(e.source==='skill-dispatch')c='ev skill-dispatch';else if(e.source==='claude-code')c='ev claude-code';else if(e.source==='nftables')c='ev nftables';else if(e.source==='mcp-scan')c='ev mcp-scan';else if(e.source==='skill-scan')c='ev skill-scan';else if(e.source==='tinyproxy')c='ev tinyproxy';else if(e.source==='codeguard')c='ev guard';else if(e.source==='mcp')c='ev mcp';else if(e.source==='webhook')c='ev webhook';else if(e.is_agent)c='ev agent';
const p=e.policy?`<span class="pol">[${e.policy}]</span>`:'';
const st=e.source||'tetragon';
h+=`<div class="${c}"><span class="tm">${t}</span><span class="tp ${e.type}">${e.type}</span><span class="uid">${e.uid}</span><span class="bin">${e.binary.split('/').pop()}</span><span class="args">${esc(e.args)} ${p} <span class="stag ${st}">${st}</span></span></div>`}
document.getElementById('evts').innerHTML=h;
document.getElementById('sc').textContent=filtered<total?`${events.length} shown · ${filtered} matched · ${total} total`:`${events.length} / ${total}`}
function refresh(){
const q=document.getElementById('search').value;
const url='/api/events'+(q?'?q='+encodeURIComponent(q):'');
fetch(url).then(r=>r.json()).then(d=>{
const s=d.stats,r=d.rings,t=d.stats.tokens||{};
// Rings
const asi=document.getElementById('agent-status');if(r.agent_running){asi.innerHTML='&#9679; LIVE';asi.style.color='#00ff88'}else{asi.innerHTML='&#9679; IDLE';asi.style.color='#ff4444'}
document.getElementById('r1v').textContent=r.r1_packets_blocked;
document.getElementById('r2v').textContent=r.r2_allowed||0;
document.getElementById('r2d').textContent=`allowed · ${r.r2_denied||0} denied`;
if(r.r2_denied>0)document.querySelector('#ring2 .status').className='status yellow';
document.getElementById('r3v').textContent=r.r3_es_events||0;
document.getElementById('r3d').textContent=`events · ${r.r3_es_execs||0} execs · ${r.r3_agent_procs||0} procs`;
document.getElementById('r4v').textContent=r.r4_sandboxed_runs||0;
document.getElementById('r4d').textContent=`sandboxed runs`;
const tools=d.stats.tools||{};
document.getElementById('r5v').textContent=tools.total||0;
const tb=Object.entries(tools.breakdown||{}).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([n,c])=>n.replace('mcp__aetherclaude-github__','')).join(', ');
document.getElementById('r5d').textContent=`tool calls · top: ${tb||'none'}`;
document.getElementById('r6v').textContent=(r.r6_files_scanned||0)+(r.r6_mcp_tools_scanned||0);
document.getElementById('r6d').textContent=`items scanned · ${r.r6_findings||0} findings · ${r.r6_blocked||0} blocked`;
document.getElementById('r7v').textContent=r.r7_mcp_ops||0;
document.getElementById('r7d').textContent=`ops · ${r.r7_blocked||0} blocked`;
document.getElementById('r8v').textContent=r.r8_validation_failed||0;
document.getElementById('r8d').textContent=`failed · ${r.r8_validation_passed||0} passed`;
document.getElementById('r9v').textContent=r.r9_prs_open||0;
document.getElementById('r9d').textContent=`open · ${r.r9_prs_merged||0} merged · ${r.r9_prs_rejected||0} rejected`;
// Ring status colors
if(r.r6_blocked>0)document.querySelector('#ring6 .status').className='status yellow';
if(r.r7_blocked>0)document.querySelector('#ring7 .status').className='status yellow';
if(r.r8_validation_failed>0){document.querySelector('#ring8 .status').className='status red';document.getElementById('r8v').style.color='#ff4444';}
else{document.getElementById('r8v').style.color='';}
if(r.r9_prs_rejected>0)document.querySelector('#ring9 .status').className='status yellow';

document.getElementById('sup').textContent=`${s.suppressed} noise hidden`;
// Tokens
const tk=Math.round((t.total||0)/1000);
let th='';
th+=`<div class="si"><span class="n">Input</span><span class="c">${((t.input||0)/1000).toFixed(1)}K</span></div>`;
th+=`<div class="si"><span class="n">Output</span><span class="c">${((t.output||0)/1000).toFixed(1)}K</span></div>`;
th+=`<div class="si"><span class="n">Cache Read</span><span class="c">${((t.cache_read||0)/1e6).toFixed(1)}M</span></div>`;
th+=`<div class="si"><span class="n">Cache Create</span><span class="c">${((t.cache_create||0)/1e6).toFixed(1)}M</span></div>`;
th+=`<div class="si"><span class="n">API Messages</span><span class="c">${t.messages||0}</span></div>`;
th+=`<div class="si"><span class="n" style="color:#00ff88">API Cost (avoided)</span><span class="c" style="color:#00ff88">$${t.estimated_cost_usd||0}</span></div>`;
const maxCost=200;
const roi=(t.estimated_cost_usd||0)-maxCost;
const roiColor=roi>=0?'#00ff88':'#ffaa00';
const roiLabel=roi>=0?'ROI (profit)':'ROI (building)';
const pct=Math.round(((t.estimated_cost_usd||0)/maxCost)*100);
th+=`<div class="si"><span class="n">MAX Subscription</span><span class="c">$${maxCost}</span></div>`;
th+=`<div class="si"><span class="n" style="color:${roiColor}">${roiLabel}</span><span class="c" style="color:${roiColor}">${roi>=0?'+':''}$${roi.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n">Breakeven</span><span class="c">${pct}%</span></div>`;
document.getElementById('tp').innerHTML=th;
// Binaries
// GitHub Activity from MCP breakdown
let gh='';const mb=r.r7_mcp_breakdown||{};
// GitHub Activity — simplified categories
const ops=Object.entries(mb);
let cats={ir:0,iw:0,pr_r:0,pr_w:0,dr:0,dw:0,ci:0};
for(const[op,cnt]of ops){
const o=op.toLowerCase();
if(o.includes('read_issue')||o.includes('list_issue')||o.includes('search_issue')||o.match(/get \/repos\/[^/]+\/[^/]+\/issues/)||o.match(/get \/search\/issues/))cats.ir+=cnt;
else if(o.includes('comment_on_issue')||o.includes('create_pull_request')||o.match(/post \/repos\/[^/]+\/[^/]+\/issues/))cats.iw+=cnt;
else if(o.includes('list_open_pr')||o.includes('list_pr_file')||o.includes('get_pr_diff')||o.match(/get \/repos\/[^/]+\/[^/]+\/pulls/))cats.pr_r+=cnt;
else if(o.includes('create_pr_review')||o.includes('create_pull')||o.match(/post \/repos\/[^/]+\/[^/]+\/pulls/))cats.pr_w+=cnt;
else if(o.includes('read_discussion')||o.includes('list_discussion'))cats.dr+=cnt;
else if(o.includes('comment_on_discussion'))cats.dw+=cnt;
else if(o.includes('check_runs')||o.includes('ci_run'))cats.ci+=cnt;
}
const tr=cats.ir+cats.pr_r+cats.dr+cats.ci;
const tw=cats.iw+cats.pr_w+cats.dw;
gh='';
gh+=`<div class="si"><span class="n" style="color:#44ddaa">Total Reads</span><span class="c">${tr}</span></div>`;
gh+=`<div class="si"><span class="n" style="color:#ffaa00">Total Writes</span><span class="c">${tw}</span></div>`;
gh+=`<div class="si"><span class="n">Issue Read</span><span class="c">${cats.ir}</span></div>`;
gh+=`<div class="si"><span class="n">Issue Write</span><span class="c">${cats.iw}</span></div>`;
gh+=`<div class="si"><span class="n">PR Read</span><span class="c">${cats.pr_r}</span></div>`;
gh+=`<div class="si"><span class="n">PR Write</span><span class="c">${cats.pr_w}</span></div>`;
gh+=`<div class="si"><span class="n">Discussion Read</span><span class="c">${cats.dr}</span></div>`;
gh+=`<div class="si"><span class="n">Discussion Write</span><span class="c">${cats.dw}</span></div>`;
gh+=`<div class="si"><span class="n">CI Checks</span><span class="c">${cats.ci}</span></div>`;
document.getElementById('github-activity').innerHTML=gh||'<div class="si"><span class="n muted">No activity yet</span></div>';
// Cisco AI Defense Scanners panel
let cs='';
cs+=`<div class="si clickable" onclick="showMcpScan()"><span class="n"><span class="stag codeguard">scan</span> MCP Scanner</span><span class="c">${r.r6_mcp_tools_scanned||0} tools · ${r.r6_mcp_threats||0} threats</span></div>`;
cs+=`<div class="si clickable" onclick="showSkillScan()"><span class="n"><span class="stag codeguard">scan</span> Skill Scanner</span><span class="c">${r.r6_skill_status||'unknown'}</span></div>`;
cs+=`<div class="si clickable" onclick="showCodeGuard()"><span class="n"><span class="stag codeguard">scan</span> CodeGuard</span><span class="c">${r.r6_files_scanned||0} files · ${r.r6_findings||0} findings</span></div>`;
cs+=`<div class="si clickable" onclick="showTetragon()"><span class="n"><span class="stag tetragon">ebpf</span> Tetragon</span><span class="c" style="color:#00ff88">active</span></div>`;
cs+=`<div class="si clickable" onclick="showAibom()"><span class="n"><span class=\"stag codeguard\">scan</span> AIBOM (C++)</span><span class="c">${r.r6_aibom_components||0} components · ${r.r6_aibom_models||0} models</span></div>`;
cs+=`<div class="si"><span class="n muted">AI Defense SDK</span><span class="c muted">pending license</span></div>`;
cs+=`<div class="si"><span class="n muted">A2A Scanner</span><span class="c muted">single agent (N/A)</span></div>`;
cs+=`<div class="si"><span class="n">Project SBOM</span><span class="c"><a href="/sbom.json" target="_blank" style="color:#00b4d8;text-decoration:none">View</a></span></div>`;
cs+=`<div class="si"><span class="n">Agent SBOM</span><span class="c"><a href="/agent-sbom.json" target="_blank" style="color:#00b4d8;text-decoration:none">View</a></span></div>`;
document.getElementById('cisco-scanners').innerHTML=cs;
// Policies
// Recent Agent Activity
let ph='';
const activity=r.recent_activity||[];
const titles=r.issue_titles||{};
const opColors={'Commented on issue':'#00b4d8','Created PR':'#00ff88','Replied to discussion':'#aa88ff','Read discussion':'#607080','Reviewed PR':'#ffaa00','Checked CI':'#44ddaa','Searched issues':'#607080'};
for(const a of [...activity].reverse()){
const col=opColors[a.op]||'#c8d8e8';
const t=a.time?a.time.substring(11,19):'';
let link=a.url;
let label=a.op;
// Extract #number from URL for title lookup
let num='';
if(link){const m=link.match(/\/(\d+)/g);if(m)num=m[m.length-1].substring(1)}
const title=titles[num]||titles['d'+num]||titles['pr'+num]||'';
const titleStr=title?` — ${title.substring(0,40)}`:'';
if(link)ph+=`<div class="si"><span class="n"><span style="color:#505060;font-size:10px">${t}</span> <span style="color:${col}">${label}</span> <a href="${link}" target="_blank" style="color:#c8d8e8;text-decoration:none">#${num}${titleStr}</a></span></div>`;
else{const ghUrl=a.num?`https://github.com/ten9876/AetherSDR/issues/${a.num}`:'';const numTitle=titles[a.num]||'';const numTitleStr=numTitle?` — ${numTitle.substring(0,40)}`:'';if(a.num)ph+=`<div class="si"><span class="n"><span style="color:#505060;font-size:10px">${t}</span> <span style="color:${col}">${label}</span> <a href="${ghUrl}" target="_blank" style="color:#c8d8e8;text-decoration:none">#${a.num}${numTitleStr}</a></span></div>`;else ph+=`<div class="si"><span class="n"><span style="color:#505060;font-size:10px">${t}</span> <span style="color:${col}">${label}</span></span></div>`;}
}
document.getElementById('pols').innerHTML=ph||'<div class="si"><span class="n muted">Waiting for agent activity...</span></div>';

// Alerts
let ah='';for(const a of(s.alerts||[]).reverse())ah+=`<div class="ai ${a.severity}"><div class="msg">${esc(a.msg)}</div><div class="at">${a.time}</div></div>`;
document.getElementById('als').innerHTML=ah||'<div class="si"><span class="n muted">No alerts</span></div>';
storeData(d);
renderEvents(d.events,d.total,d.filtered||d.total);
}).catch(()=>{})}
// Scanner detail modals
let lastData={};
function storeData(d){lastData=d}
function closeModal(){document.getElementById('modal').classList.remove('show')}
function showMcpScan(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">YARA + Prompt Defense analysis of MCP server tool declarations</p>';
h+=`<div class="modal-finding ${r.r6_mcp_threats>0?'HIGH':'SAFE'}"><span class="sev ${r.r6_mcp_threats>0?'HIGH':'SAFE'}">${r.r6_mcp_threats>0?'THREAT':'SAFE'}</span> ${r.r6_mcp_tools_scanned||0} tools scanned, ${r.r6_mcp_threats||0} threats</div>`;
h+=`<div id="mcp-findings-list" style="margin-top:12px"><p style="color:#607080">Loading scan details...</p></div>`;
document.getElementById('modal-title').textContent='MCP Scanner Results';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/mcp-scan').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} total scan records in database</p>`;
if(d.results.length===0)fh+='<p style="color:#607080">No scan data recorded yet.</p>';
const seen=new Set();
for(const t of d.results){
if(seen.has(t.tool_name))continue;seen.add(t.tool_name);
const sev=t.is_safe?'SAFE':(t.severity||'HIGH');
fh+=`<div class="modal-finding ${sev}" style="margin-bottom:6px">`;
fh+=`<span class="sev ${sev}">${sev}</span> <strong>${esc(t.tool_name)}</strong>`;
if(t.tool_description)fh+=`<div class="detail" style="margin-top:2px">${esc(t.tool_description)}</div>`;
if(t.threat_name)fh+=`<div class="detail" style="margin-top:2px;color:#ff6688">Threat: ${esc(t.threat_name)}</div>`;
if(t.is_safe)fh+=`<div class="detail" style="margin-top:2px">No threats detected</div>`;
if(t.analyzer)fh+=`<div class="detail" style="margin-top:2px;color:#405060;font-size:10px">Analyzer: ${esc(t.analyzer)}</div>`;
fh+=`</div>`}
document.getElementById('mcp-findings-list').innerHTML=fh;
}).catch(()=>{document.getElementById('mcp-findings-list').innerHTML='<p style="color:#604040">Failed to load scan data.</p>'})}
function showSkillScan(){
const r=lastData.rings||{};
const injected=r.r6_skill_injected||false;
let h='<p style="color:#607080;margin-bottom:12px">Cisco AI Defense Skill Scanner — analyzes agent skill templates for injection risks</p>';
const injCount=r.r6_skill_injected_count||0;
h+=`<div class="modal-finding ${injected?'MEDIUM':'SAFE'}"><span class="sev ${injected?'MEDIUM':'SAFE'}">${injected?injCount+' FOUND':'SAFE'}</span> Workspace .claude/commands/ check: ${injected?injCount+' skill file(s) in workspace':'clean — no injected commands'}</div>`;
h+=`<div class="modal-finding ${r.r6_skill_findings>0?'MEDIUM':'SAFE'}"><span class="sev ${r.r6_skill_findings>0?'MEDIUM':'SAFE'}">${r.r6_skill_findings||0}</span> findings across ${r.r6_skills_scanned||'?'} skills in /Users/aetherclaude/skills/</div>`;
h+=`<div id="skill-findings-list" style="margin-top:12px"><p style="color:#607080">Loading skill details...</p></div>`;
document.getElementById('modal-title').textContent='Skill Scanner Results';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/skill-scan').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} scan records in database</p>`;
if(d.results.length===0)fh+='<p style="color:#607080">No scan data recorded yet.</p>';
const seen=new Set();
for(const s of d.results){
const key=s.skill_name+'|'+s.finding_id;
if(seen.has(key))continue;seen.add(key);
const sev=s.finding_severity==='INFO'||s.finding_severity==='SAFE'?'SAFE':s.finding_severity==='MEDIUM'?'MEDIUM':'HIGH';
fh+=`<div class="modal-finding ${sev}" style="margin-bottom:6px">`;
fh+=`<span class="sev ${sev}">${esc(s.finding_severity||'SAFE')}</span> <strong>${esc(s.skill_name)}</strong>`;
if(s.finding_title&&s.finding_title!=='No findings')fh+=`: ${esc(s.finding_title)}`;
if(s.finding_description)fh+=`<div class="detail" style="margin-top:2px">${esc(s.finding_description)}</div>`;
if(s.finding_remediation)fh+=`<div class="detail" style="margin-top:2px;color:#4090d0">Fix: ${esc(s.finding_remediation)}</div>`;
if(s.analyzers)fh+=`<div class="detail" style="margin-top:2px;color:#405060;font-size:10px">Analyzers: ${esc(s.analyzers)}</div>`;
fh+=`</div>`}
document.getElementById('skill-findings-list').innerHTML=fh;
}).catch(()=>{document.getElementById('skill-findings-list').innerHTML='<p style="color:#604040">Failed to load skill scan data.</p>'})}
function showCodeGuard(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">Cisco DefenseClaw static analysis on changed source files</p>';
h+=`<div class="modal-finding ${r.r6_blocked>0?'HIGH':'SAFE'}"><span class="sev ${r.r6_blocked>0?'HIGH':'SAFE'}">${r.r6_blocked>0?'BLOCKED':'PASS'}</span> ${r.r6_files_scanned||0} files scanned</div>`;
if(r.r6_findings>0)h+=`<div class="modal-finding MEDIUM"><span class="sev MEDIUM">MEDIUM</span> ${r.r6_findings} findings (warnings, not blocking)</div>`;
if(r.r6_blocked>0)h+=`<div class="modal-finding HIGH"><span class="sev HIGH">HIGH</span> ${r.r6_blocked} findings blocked commit</div>`;
h+=`<div id="cg-findings-list" style="margin-top:12px"><p style="color:#607080">Loading finding details...</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Rules: CG-CRED (credentials), CG-EXEC (unsafe exec), CG-NET (outbound HTTP), CG-DESER (deserialization), CG-SQL (injection), CG-CRYPTO (weak crypto), CG-PATH (traversal)</div>`;
document.getElementById('modal-title').textContent='CodeGuard Results';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/codeguard?limit=100').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} total findings in database</p>`;
if(d.findings.length===0)fh+='<p style="color:#607080">No findings recorded yet.</p>';
for(const f of d.findings){
const sc=f.severity==='HIGH'||f.severity==='CRITICAL'?'HIGH':f.severity==='MEDIUM'?'MEDIUM':'SAFE';
fh+=`<div class="modal-finding ${sc}" style="margin-bottom:8px">`;
fh+=`<span class="sev ${sc}">${esc(f.severity)}</span> <strong>${esc(f.rule_id)}</strong>: ${esc(f.title)}`;
fh+=`<div class="detail" style="margin-top:4px">File: <code>${esc(f.file)}</code>`;
if(f.location)fh+=` at ${esc(f.location)}`;
fh+=`</div>`;
if(f.description)fh+=`<div class="detail" style="margin-top:2px">${esc(f.description)}</div>`;
if(f.remediation)fh+=`<div class="detail" style="margin-top:2px;color:#4090d0">Fix: ${esc(f.remediation)}</div>`;
fh+=`<div class="detail" style="margin-top:2px;color:#405060;font-size:10px">${esc(f.scan_time)}</div>`;
fh+=`</div>`}
document.getElementById('cg-findings-list').innerHTML=fh;
}).catch(()=>{document.getElementById('cg-findings-list').innerHTML='<p style="color:#604040">Failed to load findings from database.</p>'})}
function showAibom(){
const comps=lastData.rings?.r6_aibom_components||0;
const models=lastData.rings?.r6_aibom_models||0;
const neural=lastData.rings?.r6_aibom_neural||false;
let h='<p style="color:#607080;margin-bottom:12px">C++ AI Bill of Materials — scans for neural networks, ML frameworks, and DSP libraries</p>';
h+=`<div class="modal-finding ${neural?'MEDIUM':'SAFE'}"><span class="sev ${neural?'MEDIUM':'SAFE'}">${neural?'NEURAL':'CLEAN'}</span> ${comps} AI/ML components detected</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">INFO</span> ${models} model files found</div>`;
h+=`<div id="aibom-list" style="margin-top:12px"><p style="color:#607080">Loading component details...</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Scanner: cpp-aibom v1.0.0 (custom C++ AIBOM for Cisco AI Defense)</div>`;
document.getElementById('modal-title').textContent='C++ AI Bill of Materials';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/aibom').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} components in database</p>`;
if(d.components.length===0)fh+='<p style="color:#607080">No components recorded yet.</p>';
const seen=new Set();
const catColors={'audio_ml':'MEDIUM','audio_codec':'SAFE','dsp':'SAFE','audio_dsp':'SAFE','audio_io':'SAFE','rpc':'SAFE'};
for(const c of d.components){
if(seen.has(c.name))continue;seen.add(c.name);
const sev=catColors[c.category]||'SAFE';
fh+=`<div class="modal-finding ${sev}" style="margin-bottom:6px">`;
fh+=`<span class="sev ${sev}">${esc(c.category)}</span> <strong>${esc(c.name)}</strong>`;
fh+=`<div class="detail" style="margin-top:2px">${esc(c.description)}</div>`;
fh+=`<div class="detail" style="margin-top:2px;color:#405060;font-size:10px">Detection: ${esc(c.detection)} — ${esc(c.evidence)}</div>`;
fh+=`</div>`}
document.getElementById('aibom-list').innerHTML=fh;
}).catch(()=>{document.getElementById('aibom-list').innerHTML='<p style="color:#604040">Failed to load component data.</p>'})}
function showTetragon(){
const s=lastData.stats||{};
let h='<p style="color:#607080;margin-bottom:12px">Cilium Tetragon eBPF kernel-level observability</p>';
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">ACTIVE</span> TracingPolicies loaded</div>`;
const pols=Object.entries(s.policy_hits||{});
for(const[name,count]of pols)h+=`<div class="modal-finding MEDIUM"><span class="sev MEDIUM">${count}</span> ${name}</div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Monitors: tcp_connect, tcp_close, sys_ptrace, sys_mount, sys_setuid, sys_setgid, sys_unshare, sys_pivot_root</div>`;
document.getElementById('modal-title').textContent='Tetragon eBPF Status';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show')}
function showRingEvents(source,title,desc){
let h=`<p style="color:#607080;margin-bottom:12px">${desc}</p>`;
h+=`<div id="ring-events-list"><p style="color:#607080">Loading events...</p></div>`;
document.getElementById('modal-title').textContent=title;
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/events?q='+encodeURIComponent(source)).then(r=>r.json()).then(d=>{
let fh=`<div class="modal-finding SAFE"><span class="sev SAFE">EVENTS</span> ${d.filtered} events matched</div>`;
fh+='<div style="margin-top:12px;max-height:50vh;overflow-y:auto;font-family:monospace;font-size:11px">';
for(const e of d.events.slice(0,200)){
const isAlert=e.policy&&e.policy.length>0;
const cls=isAlert?'HIGH':'SAFE';
fh+=`<div class="modal-finding ${cls}" style="margin-bottom:2px;padding:4px 8px">`;
fh+=`<span style="color:#607080;margin-right:8px">${esc(e.time||'').substring(11,19)}</span>`;
if(e.type)fh+=`<span style="color:#ffaa00;margin-right:6px;font-weight:bold">${esc(e.type)}</span>`;
fh+=`${esc(e.args||'')}`;
if(e.policy)fh+=` <span style="color:#ff6688;font-size:10px">[${esc(e.policy)}]</span>`;
fh+=`</div>`}
if(d.filtered>200)fh+=`<p style="color:#607080;margin-top:8px">Showing 200 of ${d.filtered} events</p>`;
fh+='</div>';
document.getElementById('ring-events-list').innerHTML=fh;
}).catch(()=>{document.getElementById('ring-events-list').innerHTML='<p style="color:#604040">Failed to load events.</p>'})}
function showRing4(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">systemd service sandboxing — NoNewPrivileges, ProtectSystem=strict, read-only filesystem</p>';
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">RUNS</span> ${r.r4_sandboxed_runs||0} sandboxed agent runs completed</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> NoNewPrivileges=yes</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> ProtectSystem=strict</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> ProtectHome=read-only</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> PrivateTmp=yes, PrivateDevices=yes</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> ProtectKernelTunables, ProtectKernelModules, ProtectControlGroups</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">CONFIG</span> RestrictNamespaces=yes</div>`;
const writable=['workspace','logs','state','skills','.claude','.config','prompts','/tmp'];
h+='<div class="modal-finding SAFE" style="margin-top:8px"><span class="sev SAFE">R/W</span> Writable paths: '+writable.map(p=>`<code>${p}</code>`).join(', ')+'</div>';
if(r.r4_timer_since)h+=`<div class="detail" style="margin-top:8px;color:#607080">Timer active since: ${r.r4_timer_since}</div>`;
document.getElementById('modal-title').textContent='Ring 4: systemd Sandbox';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show')}
function showRing9(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">Human review — the final authority. All PRs require CODEOWNERS approval, GPG-signed commits, and CI checks.</p>';
h+=`<div class="modal-finding ${r.r9_prs_open>0?'MEDIUM':'SAFE'}"><span class="sev ${r.r9_prs_open>0?'MEDIUM':'SAFE'}">${r.r9_prs_open||0}</span> PRs awaiting review</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">${r.r9_prs_merged||0}</span> PRs merged (approved by maintainer)</div>`;
if(r.r9_prs_rejected>0)h+=`<div class="modal-finding HIGH"><span class="sev HIGH">${r.r9_prs_rejected}</span> PRs rejected (closed without merge)</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">TOTAL</span> ${r.r9_prs_total||0} total PRs created by agent</div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Controls: CODEOWNERS file, branch protection, GPG commit signing, CI status checks, draft PR quarantine</div>`;
h+=`<div id="r9-pr-list" style="margin-top:12px"><p style="color:#607080">Loading PR details...</p></div>`;
document.getElementById('modal-title').textContent='Ring 9: Human Review';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/prs').then(r=>r.json()).then(d=>{
let fh='';
if(d.open&&d.open.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;font-weight:bold">Open PRs awaiting review:</p>';
for(const p of d.open)fh+=`<div class="modal-finding MEDIUM" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/ten9876/AetherSDR/pull/${p.number}" target="_blank" style="color:#00b4d8;text-decoration:none">#${p.number}</a> ${esc(p.title)}${p.draft?' <span style="color:#607080;font-size:10px">(draft)</span>':''}</div>`}
if(d.merged&&d.merged.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Recently merged:</p>';
for(const p of d.merged)fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/ten9876/AetherSDR/pull/${p.number}" target="_blank" style="color:#00b4d8;text-decoration:none">#${p.number}</a> ${esc(p.title)}</div>`}
if(d.rejected&&d.rejected.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Rejected:</p>';
for(const p of d.rejected)fh+=`<div class="modal-finding HIGH" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/ten9876/AetherSDR/pull/${p.number}" target="_blank" style="color:#00b4d8;text-decoration:none">#${p.number}</a> ${esc(p.title)}</div>`}
if(d.issues&&d.issues.length>0){
const stateColors={done:'#00ff88',failed:'#ff4444',declined:'#607080',implement:'#ffaa00',waiting:'#44ddaa',triage:'#00b4d8','new':'#c8d8e8'};
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Issue pipeline (from DB):</p>';
for(const i of d.issues){
const col=stateColors[i.state]||'#c8d8e8';
const det=i.detail?` <span style="color:#607080;font-size:10px">— ${esc(i.detail.substring(0,60))}</span>`:'';
const ts=i.last_seen?i.last_seen.substring(11,19):'';
fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px;display:flex;align-items:center;gap:8px"><a href="https://github.com/ten9876/AetherSDR/issues/${i.number}" target="_blank" style="color:#00b4d8;text-decoration:none;min-width:40px">#${i.number}</a><span style="color:${col};font-weight:bold;min-width:70px">${i.state}</span><span style="color:#8090a0;font-size:10px;min-width:90px">${esc(i.last_action||'')}</span>${det}<span style="color:#505060;font-size:9px;margin-left:auto">${ts}</span></div>`}}
if(d.discussions&&d.discussions.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Discussions responded to:</p>';
for(const disc of d.discussions)fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/ten9876/AetherSDR/discussions/${disc.number}" target="_blank" style="color:#00b4d8;text-decoration:none">#${disc.number}</a> ${esc(disc.title)} <span style="color:#607080;font-size:10px">${esc(disc.category)} · ${disc.comments} comments</span></div>`}
document.getElementById('r9-pr-list').innerHTML=fh;
}).catch(()=>{document.getElementById('r9-pr-list').innerHTML='<p style="color:#604040">Failed to load PR data.</p>'})}
function showValidation(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">8-check automated pre-flight validation on every code change before push</p>';
h+=`<div class="modal-finding ${r.r8_validation_failed>0?'HIGH':'SAFE'}"><span class="sev ${r.r8_validation_failed>0?'HIGH':'SAFE'}">${r.r8_validation_failed>0?'BLOCKED':'PASS'}</span> ${r.r8_validation_passed||0} passed, ${r.r8_validation_failed||0} failed</div>`;
h+=`<div id="val-list" style="margin-top:12px"><p style="color:#607080">Loading validation history...</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Checks: Protected files, Directory restrictions, Suspicious patterns, Credential detection, Binary files, Diff size, CodeGuard scan, Skill Scanner</div>`;
document.getElementById('modal-title').textContent='Validation Gate History';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/validation').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} validation runs (${d.failed} failed)</p>`;
if(d.runs.length===0)fh+='<p style="color:#607080">No validation runs recorded yet.</p>';
for(const v of d.runs){
const isFail=v.result==='FAILED';
const sev=isFail?'HIGH':'SAFE';
fh+=`<div class="modal-finding ${sev}" style="margin-bottom:6px">`;
fh+=`<span class="sev ${sev}">${v.result}</span> ${esc(v.run_time)} — ${v.files_count} files`;
if(isFail&&v.blocked_reasons.length>0){
fh+=`<div style="margin-top:4px">`;
for(const reason of v.blocked_reasons){
if(reason)fh+=`<div class="detail" style="color:#ff4444;margin-top:2px">&#x2718; ${esc(reason)}</div>`;
}
fh+=`</div>`}
fh+=`</div>`}
document.getElementById('val-list').innerHTML=fh;
}).catch(()=>{document.getElementById('val-list').innerHTML='<p style="color:#604040">Failed to load validation data.</p>'})}
function showWhitepaper(){document.getElementById('wp-modal').classList.add('show')}
function closeWp(){document.getElementById('wp-modal').classList.remove('show')}
setInterval(refresh,REFRESH_MS);refresh();
</script><div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
<div class="modal">
<button class="modal-close" onclick="closeModal()">&times;</button>
<h2 id="modal-title">Scanner Details</h2>
<div id="modal-body"></div>
</div>
</div>
<div class="modal-overlay wp" id="wp-modal" onclick="if(event.target===this)closeWp()">
<div class="modal">
<button class="modal-close" onclick="closeWp()">&times;</button>
<div class="wp-content">
<h1>9 Rings of Defense</h1>
<p style="text-align:center;color:#00b4d8;font-size:15px">Securing an Autonomous AI Coding Agent<br>with Isovalent and Cisco AI Defense</p>
<p class="meta">Jeremy Fielder &middot; Systems Engineer, Strategic Accounts &middot; Cisco Systems<br>April 2026 &middot; v2.1 &middot; Red team review: Grok (xAI)</p>
<p style="text-align:center;margin:12px 0"><a href="/whitepaper.pdf" target="_blank" style="color:#00b4d8;font-size:12px;text-decoration:none;border:1px solid #00b4d844;padding:6px 14px;border-radius:6px" onmouseover="this.style.borderColor='#00b4d8';this.style.background='#00b4d810'" onmouseout="this.style.borderColor='#00b4d844';this.style.background='none'">Open printable version (save as PDF from browser)</a></p>

<h2>1. Executive Summary</h2>
<p><strong>An autonomous AI agent is writing code on a public open-source project right now, monitored by Cisco's Isovalent and AI Defense scanners, on an $80 Raspberry Pi.</strong></p>
<p>AetherClaude is an AI coding agent that triages GitHub issues, implements fixes, reviews community pull requests, detects duplicates, explains CI failures, answers community questions, and compiles release notes for AetherSDR&mdash;an open-source Linux-native SDR client for the amateur radio community. It runs eight skills triggered in real time by GitHub webhooks, with an hourly fallback timer, unattended, on dedicated commodity hardware.</p>
<p>AetherSDR has a community of over 1,000 users around the world actively consuming software produced by this pipeline&mdash;running AetherSDR builds that include AI-authored code, filing bug reports that the agent triages, and requesting features that the agent implements. Contributors who have never written a line of C++ are shaping the project through AI-assisted issue and feature requests that AetherClaude turns into production-ready code. This has democratized participation: the barrier to contributing is no longer knowing how to code, it's knowing how to describe what you need.</p>
<p>This paper documents the <strong>9-ring defense-in-depth model</strong> securing that deployment. Each ring addresses distinct attack vectors&mdash;from kernel-level packet filtering (Ring 1) through Cisco AI Defense static analysis (Ring 6) to mandatory human review (Ring 9). An attacker must penetrate all nine rings to cause damage to the upstream project.</p>
<p>Four <a href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html" target="_blank" style="color:#00bceb;text-decoration:none;border-bottom:1px solid #00bceb44" onmouseover="this.style.borderBottomColor='#00bceb'" onmouseout="this.style.borderBottomColor='#00bceb44'">Cisco AI Defense technologies</a> are in production today. <strong><a href="https://isovalent.com/products/runtime-security/" target="_blank" style="color:#00bceb;text-decoration:none">Cilium Tetragon (Isovalent)</a></strong> provides eBPF-based process execution tracking, network connection monitoring, and privilege escalation detection. <strong><a href="https://cisco-ai-defense.github.io/docs/defenseclaw" target="_blank" style="color:#00bceb;text-decoration:none">DefenseClaw CodeGuard</a></strong> scans every changed file and blocks HIGH/CRITICAL findings. <strong><a href="https://github.com/cisco-ai-defense/mcp-scanner" target="_blank" style="color:#00bceb;text-decoration:none">MCP Scanner</a></strong> performs YARA + Prompt Defense analysis on all MCP tool declarations. <strong><a href="https://github.com/cisco-ai-defense/skill-scanner" target="_blank" style="color:#00bceb;text-decoration:none">Skill Scanner</a></strong> analyzes agent skill templates for injection risks. Additionally, a custom <strong><a href="https://github.com/cisco-ai-defense/aibom" target="_blank" style="color:#00bceb;text-decoration:none">C++ AIBOM scanner</a></strong> generates AI Bills of Materials and <strong>agent-sbom</strong> inventories the agent infrastructure itself. All run on ARM64.</p>
<p>All nine rings feed into a <strong><a href="https://dashboard.aethersdr.com" target="_blank" class="print-link" style="color:#00bceb;text-decoration:none">live Defense-in-Depth Dashboard</a></strong> with SQLite-backed event history, real-time metrics from eight data sources, clickable scanner detail modals, and secret redaction on all API responses.</p>

<h2>2. The Problem</h2>
<p>Open-source projects have a scaling problem. A solo maintainer receives bug reports, feature requests, and community questions at a rate that exceeds available time. AI coding agents promise to bridge this gap&mdash;but they create a novel threat model.</p>
<p>The agent's input&mdash;GitHub issues, pull requests, discussion threads&mdash;is <strong>untrusted public text</strong> written by anyone on the internet. That text is fed into an LLM with code-writing capabilities, repository access, and credentials for GitHub APIs. A carefully crafted issue body is a prompt injection vector.</p>
<p>The existing tooling does not help. We evaluated OpenClaw, the dominant open-source AI agent orchestrator, and abandoned it within four days:</p>
<ul>
<li><strong>512 known vulnerabilities</strong> in the dependency tree at time of evaluation</li>
<li><strong>9 CVEs</strong> across direct and transitive dependencies</li>
<li><strong>12% of community-published skills on ClawHub</strong> contained behaviors classifiable as malicious: unrestricted shell access, credential harvesting, data exfiltration</li>
<li><strong>Anthropic banned OpenClaw</strong> from wrapping Claude Code, citing security concerns</li>
</ul>
<p>We replaced it with a 950-line custom orchestrator written in bash that has zero CVEs, zero external dependencies, and does exactly what the code says. The principle: <strong>the least privileged tool that solves the problem is the most secure tool.</strong></p>

<h2>3. The 9-Ring Defense-in-Depth Model</h2>
<p>Our solution: treat the AI agent the way you would treat any untrusted process with network access and write permissions&mdash;assume it will be compromised, and make compromise survivable. Rather than relying on any single control, we layer nine independent defenses so that no single failure can result in damage to the upstream project.</p>
<p>The architecture follows a 9-ring concentric defense model. Each ring addresses distinct attack vectors. An attacker must penetrate all nine to cause meaningful damage. Every ring feeds live metrics to this dashboard.</p>
<table>
<tr><th>Ring</th><th>Control</th><th>Protection</th><th>Dashboard Metric</th></tr>
<tr><td>1</td><td><strong>nftables</strong></td><td>Kernel-level egress by UID. Only GitHub + Anthropic IPs permitted. All other outbound dropped.</td><td>Packets blocked (counter)</td></tr>
<tr><td>2</td><td><strong>tinyproxy</strong></td><td>Domain-level HTTPS filtering, default-deny. Six permitted domains.</td><td>Sessions allowed / denied</td></tr>
<tr><td>3</td><td><strong>OS isolation</strong></td><td>Dedicated UID 965, rbash, no sudo, locked password, minimal PATH. Tetragon tracks every exec.</td><td>Agent commands executed (eBPF)</td></tr>
<tr><td>4</td><td><strong>systemd sandbox</strong></td><td>NoNewPrivileges, ProtectSystem=strict, read-only FS (except workspace/logs), private /tmp.</td><td>Sandboxed runs completed</td></tr>
<tr><td>5</td><td><strong>Claude Code perms</strong></td><td>Bash fully denied, --bare mode, --permission-mode dontAsk, explicit tool allow/deny.</td><td>Tool calls tracked (per type)</td></tr>
<tr><td>6</td><td><strong>Cisco AI Defense</strong></td><td>CodeGuard static analysis, MCP Scanner (YARA), Skill Scanner (injection detection), C++ AIBOM, Agent SBOM. HIGH/CRITICAL = block.</td><td>Files scanned / findings / blocks</td></tr>
<tr><td>7</td><td><strong>MCP token isolation</strong></td><td>Tokens held by deterministic server (14 ops). Rate limiting, content validation, credential blocking.</td><td>Operations / blocked / rate-limited</td></tr>
<tr><td>8</td><td><strong>Validation Gate</strong></td><td>8-check automated pre-flight: protected files, directory restrictions, suspicious patterns, credentials, binaries, diff size, CodeGuard, Skill Scanner.</td><td>Checks passed / failed</td></tr>
<tr><td style="color:#d4af37"><strong>9</strong></td><td><strong style="color:#d4af37">The One Ring</strong></td><td>Human review. All PRs draft-quarantined. CODEOWNERS approval, signed commits, CI status checks required. The maintainer is the final authority.</td><td>PRs merged / rejected / open</td></tr>
</table>
<p>A prompt injection might trick Claude into writing strange code (bypassing rings 1&ndash;5), but the Cisco AI Defense scanners analyze the output (ring 6), the MCP server prevents token theft (ring 7), and the validation gate blocks bad diffs (ring 8), and the maintainer must approve every merge (ring 9&mdash;The One Ring).</p>

<h3>Ring 1 &mdash; nftables (Kernel Packet Filter)</h3>
<p>The outermost ring operates at the Linux kernel level. An nftables ruleset filters all outbound traffic by UID&mdash;only the agent's UID 965 is restricted, so other users on the Pi are unaffected. The allowlist contains GitHub API servers and Anthropic API endpoints. Every other destination is silently dropped. Even if the agent is fully compromised, it cannot phone home to an attacker's C2 server, exfiltrate data to a paste site, or download additional tooling. The dashboard shows a live packet counter for blocked connections.</p>

<h3>Ring 2 &mdash; tinyproxy (Domain-Level HTTPS Filter)</h3>
<p>Ring 1 filters by IP, but IP allowlists can be broad (GitHub and Anthropic both use CDNs). Ring 2 adds domain-level precision. All agent HTTPS traffic is routed through a local tinyproxy instance configured as default-deny. Six domains are permitted: <code>api.github.com</code>, <code>github.com</code>, <code>api.anthropic.com</code>, <code>sentry.io</code>, <code>statsig.anthropic.com</code>, and <code>cdn.anthropic.com</code>. Any request to an unlisted domain (e.g., <code>evil.com</code>, <code>pastebin.com</code>) is rejected with a log entry visible in the dashboard event stream.</p>

<h3>Ring 3 &mdash; OS User Isolation (<span class="cisco">Cisco Isovalent Tetragon</span> eBPF)</h3>
<p>The agent runs as a dedicated unprivileged user (UID 965) with a restricted shell (<code>rbash</code>), no sudo access, a locked password, and a minimal <code>PATH</code>. <strong><span class="cisco">Cisco Isovalent Tetragon</span></strong> provides kernel-level observability for this UID via eBPF. Two TracingPolicies are deployed: <code>aetherclaude-network</code> monitors every TCP connection attempt (<code>tcp_connect</code>/<code>tcp_close</code>), and <code>aetherclaude-priv-escalation</code> watches for privilege escalation syscalls (<code>ptrace</code>, <code>mount</code>, <code>setuid</code>, <code>setgid</code>, <code>unshare</code>, <code>pivot_root</code>). Every process the agent spawns&mdash;with full command-line arguments&mdash;is captured and streamed to the dashboard. Canary tripwire files (fake AWS credentials, SSH keys, GitHub tokens) are planted in the agent's home directory to detect unauthorized file access.</p>

<h3>Ring 4 &mdash; systemd Sandbox</h3>
<p>The agent runs inside a systemd service unit with aggressive sandboxing: <code>NoNewPrivileges=yes</code> prevents privilege escalation via setuid binaries, <code>ProtectSystem=strict</code> makes the entire filesystem read-only except explicitly allowed paths (workspace, logs, state), <code>PrivateTmp=yes</code> gives the agent its own <code>/tmp</code> invisible to other processes, and <code>PrivateDevices=yes</code> hides hardware devices. The kernel tunables, modules, and control groups are all protected. Even if the agent escapes <code>rbash</code>, the systemd sandbox prevents filesystem damage.</p>

<h3>Ring 5 &mdash; Claude Code Permissions</h3>
<p>Claude Code itself enforces tool-level access control. The agent runs with <code>--permission-mode bypassPermissions</code> but with explicit tool allowlists and denylists. Allowed: <code>Read</code>, <code>Glob</code>, <code>Grep</code>, <code>Edit</code>, <code>Write</code>, and specific <code>git</code> subcommands (<code>add</code>, <code>commit</code>, <code>push</code>, <code>diff</code>, <code>log</code>, <code>status</code>, <code>checkout</code>). Denied: <code>sudo</code>, <code>curl</code>, <code>wget</code>, <code>ssh</code>, <code>rm -rf</code>, <code>chmod</code>, <code>systemctl</code>, <code>env</code>, <code>printenv</code>, <code>WebFetch</code>, <code>WebSearch</code>, and any command that reads credential files. The <code>Bash</code> tool is not blanket-denied&mdash;it is surgically restricted to safe operations. The dashboard tracks every tool call with per-tool type breakdown.</p>

<h3>Ring 6 &mdash; <span class="cisco">Cisco AI Defense</span> Scanners</h3>
<p>Five <span class="cisco">Cisco</span> security scanners form the code analysis ring:</p>
<ul>
<li><strong><span class="cisco">DefenseClaw CodeGuard</span></strong> performs static analysis on every changed file before code can be pushed. Ten built-in rules cover hardcoded credentials (CG-CRED), unsafe execution (CG-EXEC), outbound HTTP to variable URLs (CG-NET), deserialization (CG-DESER), SQL injection (CG-SQL), weak cryptography (CG-CRYPTO), and path traversal (CG-PATH). HIGH and CRITICAL findings block the commit.</li>
<li><strong><span class="cisco">MCP Scanner</span></strong> performs YARA + Prompt Defense analysis on all 14 MCP tool declarations, detecting prompt injection, credential harvesting, and exfiltration patterns in tool descriptions.</li>
<li><strong><span class="cisco">Skill Scanner</span></strong> analyzes the agent's skill templates for injection risks and policy violations using static, bytecode, and pipeline analyzers. Also monitors the workspace for injected <code>.claude/commands/</code> that could auto-execute.</li>
<li><strong>C++ AIBOM</strong> generates AI Bills of Materials identifying neural network components, ML frameworks, model files, and DSP libraries in the codebase.</li>
<li><strong>Agent SBOM</strong> inventories the agent infrastructure itself: 42 components across 7 layers in CycloneDX format.</li>
</ul>
<p>All findings persist to SQLite with full details&mdash;rule IDs, severity, file paths, remediation guidance&mdash;queryable through the dashboard's clickable scanner modals.</p>

<h3>Ring 7 &mdash; MCP Token Isolation</h3>
<p>The agent never sees a GitHub token. A deterministic MCP server holds all credentials in-process and exposes exactly 14 named operations (read issue, comment, create PR, review PR, list discussions, etc.). No delete operations, no repository admin, no settings changes. The server enforces rate limiting (3 comments/issue/hour, 5 PRs/hour), content validation (length limits, Base64 blocking, LLM delimiter detection), and credential pattern blocking (6 regex patterns for GitHub PATs, Anthropic keys, AWS keys, private key headers). GitHub App installation tokens are generated via JWT with 1-hour expiry&mdash;no long-lived PATs. Every operation is logged to an immutable append-only audit file.</p>

<h3>Ring 8 &mdash; Validation Gate</h3>
<p>Before any code leaves the agent, it must pass an automated 8-check validation gate. The gate inspects the diff for: (1) protected file modifications (CI/CD, CLAUDE.md, workflows), (2) changes outside allowed directories, (3) suspicious code patterns (eval, exec, subprocess with shell=True), (4) credential patterns (API keys, private key headers, token assignments), (5) binary files that shouldn't be committed, (6) diff size limits, (7) <span class="cisco">DefenseClaw CodeGuard</span> static analysis with HIGH/CRITICAL blocking, and (8) <span class="cisco">Skill Scanner</span> workspace injection check. Any single failure blocks the push. PRs are created as drafts and only promoted to ready-for-review after all 8 checks pass.</p>

<h3 style="color:#d4af37">Ring 9 &mdash; The One Ring (Human Review)</h3>
<p><em>"One Ring to rule them all."</em> The innermost ring is the simplest and most important: a human reviews every change before it reaches the codebase. Even after passing all eight automated rings, the PR requires CODEOWNERS approval from the project maintainer, GPG-signed commits, and CI build status checks before merge. No code enters the repository without a human decision. The agent proposes, the human decides. This ring cannot be bypassed, automated, or prompt-injected&mdash;it is the ultimate authority over what ships.</p>

<h2>4. MCP Token Isolation Pattern</h2>
<p>Of all the controls in this architecture, MCP token isolation delivers the highest security value per unit of effort. It solves the fundamental problem: <strong>if the AI has the credentials, a prompt injection can abuse them.</strong></p>
<h3>The Core Principle</h3>
<p>Rather than passing GitHub tokens to Claude Code as environment variables, we interpose a deterministic MCP server. It holds all credentials and exposes exactly 14 named operations across four categories (Issues, Pull Requests, CI, Discussions). No delete operations, no repository management, no settings changes.</p>
<p>The MCP server (v3) uses native Node.js <code>https</code> with CONNECT proxy tunneling&mdash;zero <code>execSync</code> or <code>curl</code> subprocess calls. All credentials stay in-process memory, invisible to eBPF process argument capture.</p>
<h3>v2.1 Hardening</h3>
<ul>
<li><strong>Rate limiting:</strong> 3 comments/issue/hour, 1 review/PR/hour, 5 PRs/hour, 20 comments globally/hour.</li>
<li><strong>Content validation:</strong> 5,000-char comments, 8,000-char PR bodies. Base64 blocks, hex strings, LLM delimiters, IP addresses: warn on first, block on second.</li>
<li><strong>Credential blocking:</strong> 6 regex patterns (GitHub PATs, Anthropic keys, AWS keys, private key headers). Any match = unconditional block.</li>
<li><strong>Immutable audit logs:</strong> Every operation logged to append-only files (chattr +a).</li>
<li><strong>Draft PR quarantine:</strong> All PRs created as drafts. Marked ready only after the 8-check validation gate passes.</li>
</ul>

<h2>5. Live Observability Dashboard</h2>
<p>All eight defense rings are monitored in real time through this unified web dashboard&mdash;the one you are reading this on. It aggregates events from eight independent data sources into a single live event stream, backed by SQLite for historical queries.</p>

<h3>9-Ring Status Bar</h3>
<p>The top of the dashboard displays nine ring cards with live counters updated every 3 seconds. Each ring shows its current metric (packets blocked, sessions allowed, tool calls tracked, files scanned, PRs merged, etc.) with green/yellow/red status indicators. Clicking Tetragon or any Cisco AI Defense scanner opens a detail modal.</p>

<h3>Unified Event Stream</h3>
<p>All security events are interleaved in a single scrolling feed, each tagged with a source label and color-coded for rapid scanning:</p>
<ul>
<li><strong style="color:#00ff88">Agent</strong> (green): AetherClaude UID 965 process activity</li>
<li><strong style="color:#ff4444">Firewall</strong> (red): nftables BLOCK events with destination details</li>
<li><strong style="color:#44ddaa">Proxy</strong> (teal): tinyproxy allowed/denied domain connections</li>
<li><strong style="color:#ff6688">CodeGuard</strong> (pink): DefenseClaw scan results and blocks</li>
<li><strong style="color:#aa88ff">MCP</strong> (purple): GitHub API operations and content validation</li>
<li><strong style="color:#00ddff">Scanners</strong> (cyan): MCP Scanner and Skill Scanner events</li>
<li><strong style="color:#ffdd44">Skills</strong> (yellow): Orchestrator skill dispatch (triage, implement, review, etc.)</li>
<li><strong style="color:#ff88cc">Claude</strong> (pink): Claude Code tool calls with per-tool breakdown</li>
</ul>
<p>Tetragon eBPF events have their own sub-filters: <strong>EXEC</strong> (process start with full command line), <strong>KPROBE</strong> (kernel probe intercepts&mdash;syscalls like tcp_connect, setuid, ptrace), and <strong>EXIT</strong> (process termination). Filter buttons toggle each event type and source. An "AetherClaude" filter isolates UID 965 events. A "Hide System" toggle removes OS noise to focus on agent activity. Full-text search spans all fields.</p>

<h3>Eight Data Sources</h3>
<table>
<tr><th>Source</th><th>Technology</th><th>Events Captured</th></tr>
<tr><td>Tetragon</td><td>Cilium/Isovalent eBPF</td><td>Process exec, syscalls, network connections for UID 965</td></tr>
<tr><td>nftables</td><td>Linux kernel firewall</td><td>Blocked outbound packets with destination IP/port</td></tr>
<tr><td>tinyproxy</td><td>HTTP proxy</td><td>Allowed/denied domain connections with session counts</td></tr>
<tr><td>CodeGuard</td><td>Cisco DefenseClaw</td><td>Static analysis findings on changed files</td></tr>
<tr><td>MCP Scanner</td><td>Cisco AI Defense</td><td>YARA + Prompt Defense analysis on MCP tool declarations</td></tr>
<tr><td>Skill Scanner</td><td>Cisco AI Defense</td><td>Injection risk analysis on agent skill templates</td></tr>
<tr><td>MCP Server</td><td>Custom Node.js</td><td>Every GitHub API operation, content validation, rate limiting</td></tr>
<tr><td>Orchestrator</td><td>Skill dispatch</td><td>Which skill is processing which issue/PR/discussion</td></tr>
</table>

<h3>Right-Side Panels</h3>
<ul>
<li><strong>Token Usage (Claude MAX):</strong> Input/output tokens, cache read/create counts, API messages, estimated API cost avoided, MAX subscription ROI tracking with breakeven percentage.</li>
<li><strong>GitHub Activity:</strong> Per-operation breakdown (issue reads/writes, PR reads/writes/creates, discussion reads/replies, issue searches, discussion lists, CI checks) with total counts.</li>
<li><strong>Cisco AI Defense Scanners:</strong> Clickable panel showing all five scanners&mdash;MCP Scanner (tools scanned, threats), Skill Scanner (skills scanned, findings), CodeGuard (files scanned, findings), Tetragon (eBPF policies), AIBOM (components, models). Each opens a detail modal with DB-backed findings. Also links to downloadable SBOMs: Agent Infrastructure SBOM (CycloneDX) and Project SBOM (CycloneDX).</li>
<li><strong>Recent Agent Activity:</strong> Clickable links to every issue, PR, and discussion the agent touched, with titles and timestamps. Links go directly to the GitHub item.</li>
<li><strong>Alerts:</strong> Canary tripwire violations, privilege escalation attempts, firewall blocks, proxy denials, MCP content blocks&mdash;color-coded by severity with timestamps.</li>
</ul>

<h3>Scanner Detail Modals</h3>
<p>Clicking any Cisco AI Defense scanner opens a modal with full DB-backed details:</p>
<ul>
<li><strong>MCP Scanner:</strong> Per-tool YARA analysis results with threat names, severity, analyzer type, and tool descriptions. Deduplicates across scan cycles.</li>
<li><strong>Skill Scanner:</strong> Per-skill findings with rule IDs, severity, descriptions, remediation, and analyzer list. Also shows workspace <code>.claude/commands/</code> injection check status.</li>
<li><strong>CodeGuard:</strong> Per-file findings with CG-* rule IDs, severity, file path + line number, description, remediation guidance, and scan timestamp.</li>
<li><strong>Tetragon:</strong> Active TracingPolicies with per-policy hit counts.</li>
<li><strong>AIBOM:</strong> Per-component details with category (audio_ml, dsp, etc.), detection method, and evidence from CMake/source analysis.</li>
</ul>

<h3>Security Features</h3>
<ul>
<li><strong>Secret redaction:</strong> All events are scrubbed at ingestion (before entering memory or DB) and again at API response. 13 regex patterns cover GitHub PATs, JWTs, Authorization headers, credential file paths, and environment variable assignments. Secrets never reach the browser.</li>
<li><strong>SQLite event store:</strong> 10,000+ events persisted across 5 tables (events, codeguard_findings, mcp_scan_results, skill_scan_results, aibom_components) with per-source indexes. Historical queries via <code>/api/history</code>. Auto-purge at 250GB.</li>
<li><strong>Per-source buffering:</strong> 1,000 events per source in memory for fast filtered queries without DB round-trips.</li>
</ul>

<h3>Infrastructure</h3>
<p>The dashboard is a ~1,500-line single-file Python application running as a systemd service. It tails all six log sources in separate threads and serves a self-contained HTML/CSS/JS page with no external dependencies. Auto-refreshes every 3 seconds. All JSON API responses pass through the redaction layer.</p>

<h2>6. Cisco AI Defense in Production</h2>
<p><strong>Four Cisco-owned technologies are running in this deployment today.</strong> All on ARM64, all on commodity hardware, all with zero issues.</p>
<h3>Cilium Tetragon (Isovalent) &mdash; eBPF Observability</h3>
<p>The Pi 5 runs a custom-compiled RPi Foundation kernel with <code>CONFIG_DEBUG_INFO_BTF=y</code> enabled, providing full BTF support for Tetragon's eBPF programs. Two TracingPolicies are deployed:</p>
<ul>
<li><strong>aetherclaude-network:</strong> Monitors tcp_connect and tcp_close for all outbound connection attempts from the agent UID.</li>
<li><strong>aetherclaude-priv-escalation:</strong> Monitors sys_ptrace, sys_mount, sys_setuid, sys_setgid, sys_unshare, and sys_pivot_root for privilege escalation attempts.</li>
</ul>
<h3>DefenseClaw CodeGuard &mdash; Static Analysis (Ring 6)</h3>
<p>CodeGuard is integrated into the validation gate. The DefenseClaw gateway binary runs locally on the Pi and scans every changed file before code can be pushed. It enforces 10 built-in rules covering hardcoded credentials (CG-CRED), unsafe execution (CG-EXEC), outbound HTTP (CG-NET), unsafe deserialization (CG-DESER), SQL injection (CG-SQL), weak cryptography (CG-CRYPTO), and path traversal (CG-PATH). HIGH and CRITICAL findings block the commit. All findings persist to SQLite for historical tracking.</p>
<h3>MCP Scanner &mdash; Tool Declaration Analysis</h3>
<p>The Cisco MCP Scanner performs YARA + Prompt Defense analysis on all 14 MCP server tool declarations. It detects prompt injection patterns, credential harvesting, and data exfiltration attempts embedded in tool descriptions. Results are stored in SQLite and displayed in the dashboard scanner modal with per-tool threat details.</p>
<h3>Skill Scanner &mdash; Injection Detection</h3>
<p>The Cisco Skill Scanner analyzes the agent's 7 skill templates in <code>/Users/aetherclaude/skills/</code> for injection risks, policy violations, and malicious patterns. It also monitors the workspace <code>.claude/commands/</code> directory for injected skills that could auto-execute. Static, bytecode, and pipeline analyzers run on each scan cycle.</p>
<h3>C++ AIBOM &amp; Agent SBOM</h3>
<p>A custom <code>cpp-aibom</code> scanner generates AI Bills of Materials for the AetherSDR C++ codebase, identifying 9 AI/ML components (RNNoise, Opus, FreeDV/RADE, ggmorse, FFTW3, r8brain, PortAudio, gRPC, KissFFT). A separate <code>agent-sbom</code> tool inventories the agent infrastructure itself: 42 components across 7 layers in CycloneDX format. Both are downloadable from this dashboard.</p>

<h2>7. Red Team Results</h2>
<p>An independent review by Grok (xAI) evaluated the security architecture and proposed 15 improvements across 5 categories:</p>
<table>
<tr><th>Status</th><th>Count</th><th>Details</th></tr>
<tr><td>Already implemented</td><td><strong>5</strong></td><td>Canary tripwires, eBPF monitoring, structured input format, credential pattern blocking, rate limiting</td></tr>
<tr><td>Implemented (from review)</td><td><strong>2</strong></td><td>Immutable audit logs (chattr +a), draft PR quarantine</td></tr>
<tr><td>Planned</td><td><strong>4</strong></td><td>Anomaly detection, entropy checks, weekly self-audit, PAT expiry reminder</td></tr>
<tr><td>Deferred</td><td><strong>1</strong></td><td>bubblewrap around MCP server</td></tr>
<tr><td>Declined with justification</td><td><strong>6</strong></td><td>MCP response schema validation (too brittle), HMAC signing (stdio transport), Semgrep (CodeGuard suffices), container testing (CI covers it), LLM judge (adds attack surface), air-gapped QEMU (impractical on Pi 5)</td></tr>
</table>

<h2>8. The Agent in Production</h2>
<p>AetherClaude is not a proof of concept. It is actively maintaining a public open-source project.</p>
<table>
<tr><th>#</th><th>Skill</th><th>AI?</th><th>Function</th></tr>
<tr><td>1</td><td>First-Time Welcome</td><td>No</td><td>Template welcome message for first-time issue/PR authors</td></tr>
<tr><td>2</td><td>Bug Report Quality</td><td>No</td><td>Requests missing info (OS, firmware, repro steps)</td></tr>
<tr><td>3</td><td>Issue Fix + PR</td><td>Yes</td><td>Implements fixes for labeled issues, creates draft PRs</td></tr>
<tr><td>4</td><td>Community PR Review</td><td>Yes</td><td>Reviews contributor PRs for convention compliance</td></tr>
<tr><td>5</td><td>Duplicate Detection</td><td>Yes</td><td>Searches for similar issues, asks reporter to confirm</td></tr>
<tr><td>6</td><td>CI Failure Explainer</td><td>Yes</td><td>Reads build logs, explains errors to contributors</td></tr>
<tr><td>7</td><td>Discussion Responder</td><td>Yes</td><td>Answers community questions in GitHub Discussions</td></tr>
<tr><td>8</td><td>Stale Issue Triage</td><td>Yes</td><td>Weekly check-in on issues with 30+ days of inactivity</td></tr>
</table>
<p><strong>Production results:</strong> 11+ PRs merged, community discussions answered, CI failures explained, contributors welcomed. All skills scannable by Cisco Skill Scanner. FlexLib C# API source available as read-only reference for protocol questions.</p>

<h2>9. The $147 AI Agent Governance Platform</h2>
<table>
<tr><th>Component</th><th>Cost</th><th>Purpose</th></tr>
<tr><td>Raspberry Pi 5 (8GB)</td><td>$80</td><td>Compute</td></tr>
<tr><td>NVMe SSD (256GB)</td><td>$40</td><td>Storage</td></tr>
<tr><td>M.2 HAT+ for Pi 5</td><td>$15</td><td>NVMe interface</td></tr>
<tr><td>USB-C power supply (27W)</td><td>$12</td><td>Power</td></tr>
<tr><td><strong>Total</strong></td><td><strong>$147</strong></td><td><strong>Complete platform</strong></td></tr>
</table>
<p><strong>Enterprise AI agent governance does not require enterprise infrastructure.</strong> No cloud accounts. No Kubernetes clusters. No container orchestration. No license servers. A commodity single-board computer, a bash script, and disciplined application of defense-in-depth principles.</p>

<h2>10. Conclusion</h2>
<p>AI coding agents are not a future concern&mdash;they are in production today, processing untrusted public input, writing code, and interacting with critical infrastructure. AetherClaude runs eight skills triggered by GitHub webhooks in real time, with Cisco Isovalent Tetragon providing eBPF observability, DefenseClaw CodeGuard scanning every code change, MCP Scanner validating tool declarations, and Skill Scanner detecting injection risks. An independent red team validated the architecture.</p>
<p>The 9-ring defense-in-depth model is a reusable framework. MCP token isolation is a reusable pattern. The live dashboard with SQLite-backed scanner details is a reusable approach to unified security observability. None of these are specific to AetherSDR&mdash;any team deploying an AI coding agent can adopt them.</p>
<div class="highlight"><strong>The agents are already deployed. The question is whether we govern them, or hope for the best.</strong></div>
<p class="meta" style="margin-top:20px">CISCO INTERNAL &middot; 9 Rings of Defense v2.1 &middot; April 2026</p>
</div>
</div>
</div>
</body></html>""".replace('REFRESH_MS',str(REFRESH_INTERVAL_MS))

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=='/':
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path == '/agent-sbom.json':
            try:
                with open('/Users/aetherclaude/logs/agent-sbom.cdx.json', 'r') as sf:
                    data = sf.read().encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Disposition', 'inline; filename="agent-sbom.cdx.json"')
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_response(404)
                self.end_headers()
        elif self.path == '/sbom.json':
            try:
                with open('/Users/aetherclaude/logs/sbom.cdx.json', 'r') as sf:
                    data = sf.read().encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Disposition', 'inline; filename="sbom.cdx.json"')
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_response(404)
                self.end_headers()
        elif self.path == '/whitepaper.pdf':
            # Serve whitepaper as print-friendly HTML page (browser Print > Save as PDF)
            # Extract the whitepaper content from the main HTML
            wp_start = HTML.find('<div class="wp-content">')
            wp_end = HTML.find('</div>\n</div>\n</div>\n</body>')
            if wp_start > 0 and wp_end > 0:
                wp_html = HTML[wp_start:wp_end + len('</div>')]
                page = f"""<!DOCTYPE html><html><head><title>9 Rings of Defense — AetherSDR Whitepaper</title>
<meta charset="utf-8"><style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;color:#1a1a2e;max-width:800px;margin:40px auto;padding:0 20px;line-height:1.7}}
h1{{color:#0a4a7a;font-size:22px;text-align:center;margin:24px 0 8px}}
h2{{color:#0a4a7a;font-size:17px;margin:20px 0 8px;border-bottom:1px solid #ccc;padding-bottom:4px}}
h3{{color:#1a6aaa;font-size:14px;margin:16px 0 6px}}
p{{margin:8px 0}}
ul,ol{{margin:8px 0 8px 20px}}
li{{margin:4px 0}}
strong{{color:#0a0a2e}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:12px}}
th{{background:#e8eef4;color:#0a4a7a;padding:8px 10px;text-align:left;border:1px solid #ccc}}
td{{padding:6px 10px;border:1px solid #ddd}}
tr:nth-child(even){{background:#f4f6f8}}
code{{background:#e8eef4;padding:1px 4px;border-radius:3px;font-family:monospace;font-size:12px;color:#2a6a3a}}
a{{color:#0a6aba}}
.meta{{color:#666;font-size:11px;text-align:center;margin:8px 0 20px}}
.highlight{{background:#e8f0f8;border-left:3px solid #0a6aba;padding:8px 12px;margin:10px 0;border-radius:4px}}
.cisco{{color:#0a6aba}}
@media print{{body{{font-size:11px;margin:0}} h1{{font-size:20px}} h2{{font-size:15px;page-break-after:avoid}} h3{{font-size:13px;page-break-after:avoid}} table{{page-break-inside:avoid}} .no-print{{display:none}}}}
</style></head><body>
<p class="no-print" style="text-align:center;margin-bottom:20px;padding:10px;background:#f0f4f8;border-radius:6px"><strong>Tip:</strong> Use your browser's Print function (Ctrl+P / Cmd+P) and select "Save as PDF" to download.</p>
{wp_html}</body></html>"""
                # Remove the "Open printable version" link
                import re as _re2
                page = _re2.sub(r'<p style="text-align:center;margin:12px 0"><a href="/whitepaper\.pdf"[^<]*>[^<]*</a></p>', '', page)
                # Fix dark-theme colors for print
                page = page.replace('color:#00b4d8', 'color:#0a4a7a').replace('color:#00bceb', 'color:#0a6aba').replace('color:#607080', 'color:#666').replace('color:#4090d0', 'color:#0a6aba').replace('color:#405060', 'color:#888')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(page.encode())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path == '/logo.png':
            try:
                with open('/usr/local/share/tetragon-dashboard/logo.png', 'rb') as lf:
                    data = lf.read()
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Cache-Control', 'max-age=86400')
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith('/api/prs'):
            try:
                details = ring_stats.get('r9_pr_details', {'open': [], 'merged': [], 'rejected': []})
                # Also include issue and discussion titles from ring_stats
                details['issues'] = ring_stats.get('r9_issue_details', [])
                details['discussions'] = ring_stats.get('r9_discussion_details', [])
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json(details)
            except:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'open': [], 'merged': [], 'rejected': [], 'issues': [], 'discussions': []})
        elif self.path.startswith('/api/validation'):
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT run_time, files_count, result, blocked_reasons FROM validation_runs ORDER BY id DESC LIMIT 100'
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM validation_runs').fetchone()[0]
                failed = conn.execute("SELECT COUNT(*) FROM validation_runs WHERE result='FAILED'").fetchone()[0]
                conn.close()
                runs = [{'run_time': r[0], 'files_count': r[1], 'result': r[2], 'blocked_reasons': r[3].split('\n') if r[3] else []} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'runs': runs, 'total': total, 'failed': failed})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'runs': [], 'total': 0, 'failed': 0, 'error': str(ex)})
        elif self.path.startswith('/api/codeguard'):
            try:
                from urllib.parse import urlparse, parse_qs
                params = parse_qs(urlparse(self.path).query)
                limit = min(int(params.get('limit', ['200'])[0]), 5000)
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT scan_time, file_path, rule_id, severity, title, description, location, remediation FROM codeguard_findings ORDER BY id DESC LIMIT ?',
                    (limit,)
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM codeguard_findings').fetchone()[0]
                conn.close()
                findings = [{'scan_time': r[0], 'file': r[1], 'rule_id': r[2], 'severity': r[3],
                             'title': r[4], 'description': r[5], 'location': r[6], 'remediation': r[7]} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'findings': findings, 'total': total})
            except Exception as ex:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self._send_json({'findings': [], 'total': 0, 'error': str(ex)})
        elif self.path.startswith('/api/mcp-scan'):
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT scan_time, tool_name, tool_description, is_safe, severity, threat_name, threat_summary, analyzer FROM mcp_scan_results ORDER BY id DESC LIMIT 200'
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM mcp_scan_results').fetchone()[0]
                conn.close()
                results = [{'scan_time': r[0], 'tool_name': r[1], 'tool_description': r[2], 'is_safe': bool(r[3]),
                            'severity': r[4], 'threat_name': r[5], 'threat_summary': r[6], 'analyzer': r[7]} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'results': results, 'total': total})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'results': [], 'total': 0, 'error': str(ex)})
        elif self.path.startswith('/api/skill-scan'):
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT scan_time, skill_name, is_safe, max_severity, findings_count, finding_id, finding_severity, finding_title, finding_description, finding_remediation, analyzers FROM skill_scan_results ORDER BY id DESC LIMIT 200'
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM skill_scan_results').fetchone()[0]
                conn.close()
                results = [{'scan_time': r[0], 'skill_name': r[1], 'is_safe': bool(r[2]), 'max_severity': r[3],
                            'findings_count': r[4], 'finding_id': r[5], 'finding_severity': r[6],
                            'finding_title': r[7], 'finding_description': r[8], 'finding_remediation': r[9],
                            'analyzers': r[10]} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'results': results, 'total': total})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'results': [], 'total': 0, 'error': str(ex)})
        elif self.path.startswith('/api/aibom'):
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT scan_time, name, category, description, detection, location, evidence FROM aibom_components ORDER BY id DESC LIMIT 200'
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM aibom_components').fetchone()[0]
                conn.close()
                components = [{'scan_time': r[0], 'name': r[1], 'category': r[2], 'description': r[3],
                               'detection': r[4], 'location': r[5], 'evidence': r[6]} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'components': components, 'total': total})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'components': [], 'total': 0, 'error': str(ex)})
        elif self.path.startswith('/api/history'):
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            limit = int(params.get('limit', ['1000'])[0])
            source = params.get('source', [None])[0]
            event_type = params.get('type', [None])[0]
            rows = db_query_events(limit=min(limit, 10000), source=source, event_type=event_type)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self._send_json({'events': rows, 'total': db_count()})
        elif self.path.startswith('/api/events'):
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            search = params.get('q', [''])[0].lower().strip()
            with memory_lock:
                if search == 'is_agent':
                    filtered = [e for e in memory_buffer if e.get('is_agent')]
                elif search:
                    filtered = [e for e in memory_buffer
                               if search in (e.get('args','') + ' ' + e.get('binary','') + ' ' + e.get('source','') + ' ' + e.get('type','') + ' ' + e.get('policy','')).lower()]
                else:
                    filtered = list(memory_buffer)
                buf_total = len(memory_buffer)
            # Last 1000, newest first
            display = filtered[-1000:]
            display = list(reversed(display))
            with lock:
                d = {'events': display, 'total': buf_total, 'filtered': len(filtered),
                     'stats':{'total_events':stats['total_events'],'exec_count':stats['exec_count'],'kprobe_count':stats['kprobe_count'],'exit_count':stats['exit_count'],'aetherclaude_events':stats['aetherclaude_events'],'network_connections':stats['network_connections'],'alert_count':len(stats['alerts']),'policy_hits':dict(stats['policy_hits']),'binaries_seen':dict(stats['binaries_seen']),'alerts':list(stats['alerts']),'suppressed':stats['suppressed'],'tokens':{'input':token_stats['input'],'output':token_stats['output'],'cache_read':token_stats['cache_read'],'cache_create':token_stats['cache_create'],'messages':token_stats['messages'],'total':token_stats['input']+token_stats['output'],'estimated_cost_usd':round(token_stats['input']/1e6*15+token_stats['output']/1e6*75,2)},'tools':{'total':tool_stats['total'],'breakdown':tool_stats['breakdown']}},'mcp_scan_details':ring_stats.get('r6_mcp_details',[]),'rings':dict(ring_stats)}
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Access-Control-Allow-Origin','*');self.end_headers()
            self._send_json(d)
        elif self.path.startswith('/api/issue-actions'):
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            issue_number = params.get('issue', [None])[0]
            limit = min(int(params.get('limit', ['100'])[0]), 1000)
            try:
                conn = sqlite3.connect(ISSUE_ACTIONS_DB)
                if issue_number:
                    rows = conn.execute(
                        'SELECT id,issue_number,action,state,outcome,detail,run_id,created_at '
                        'FROM issue_actions WHERE issue_number=? ORDER BY id DESC LIMIT ?',
                        (int(issue_number), limit)
                    ).fetchall()
                    total = conn.execute('SELECT COUNT(*) FROM issue_actions WHERE issue_number=?',
                                        (int(issue_number),)).fetchone()[0]
                else:
                    rows = conn.execute(
                        'SELECT id,issue_number,action,state,outcome,detail,run_id,created_at '
                        'FROM issue_actions ORDER BY id DESC LIMIT ?', (limit,)
                    ).fetchall()
                    total = conn.execute('SELECT COUNT(*) FROM issue_actions').fetchone()[0]
                conn.close()
                actions = [{'id':r[0],'issue_number':r[1],'action':r[2],'state':r[3],
                            'outcome':r[4],'detail':r[5],'run_id':r[6],'created_at':r[7]} for r in rows]
                self.send_response(200); self.send_header('Content-Type','application/json')
                self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
                self._send_json({'actions': actions, 'total': total})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
                self._send_json({'actions':[],'total':0,'error':str(ex)})
        elif self.path.startswith('/api/issue-status'):
            try:
                conn = sqlite3.connect(ISSUE_ACTIONS_DB)
                rows = conn.execute("""
                    SELECT ia.issue_number, ia.action, ia.state, ia.outcome, ia.detail, ia.created_at
                    FROM issue_actions ia
                    INNER JOIN (
                        SELECT issue_number, MAX(id) as max_id
                        FROM issue_actions GROUP BY issue_number
                    ) latest ON ia.issue_number=latest.issue_number AND ia.id=latest.max_id
                    ORDER BY ia.id DESC
                """).fetchall()
                conn.close()
                statuses = [{'issue_number':r[0],'last_action':r[1],'state':r[2],
                             'outcome':r[3],'detail':r[4] or '','last_seen':r[5]} for r in rows]
                self.send_response(200); self.send_header('Content-Type','application/json')
                self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
                self._send_json({'issues': statuses, 'total': len(statuses)})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
                self._send_json({'issues':[],'total':0,'error':str(ex)})
        else:self.send_response(404);self.end_headers()
    def do_POST(self):
        if self.path == '/api/ingest':
            # Accept events from PI and PIII
            import hmac, hashlib
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            # Validate HMAC
            sig_header = self.headers.get('X-Ingest-Signature', '')
            if WEBHOOK_SECRET and sig_header:
                expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig_header, expected):
                    self.send_response(401); self.end_headers(); self.wfile.write(b'Invalid signature'); return
            try:
                payload = json.loads(body)
                events = payload.get('events', [])
                count = 0
                for entry in events:
                    append_event(entry)
                    count += 1
                self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps({'accepted': count}).encode())
            except Exception as e:
                self.send_response(400); self.end_headers()
                self.wfile.write(f'Bad request: {e}'.encode())
            return
        elif self.path == '/webhook':
            import hmac, hashlib
            global _last_webhook_trigger
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            # Validate signature
            sig_header = self.headers.get('X-Hub-Signature-256', '')
            if not sig_header.startswith('sha256='):
                self.send_response(401); self.end_headers(); self.wfile.write(b'Missing signature'); return
            expected = 'sha256=' + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig_header, expected):
                self.send_response(401); self.end_headers(); self.wfile.write(b'Invalid signature'); return
            # Parse event
            event_type = self.headers.get('X-GitHub-Event', 'unknown')
            try:
                payload = json.loads(body)
            except:
                self.send_response(400); self.end_headers(); self.wfile.write(b'Bad JSON'); return
            action = payload.get('action', '')
            # Log the webhook event
            summary = ''
            if event_type == 'issues':
                summary = f"Issue #{payload.get('issue',{}).get('number','')} {action}: {payload.get('issue',{}).get('title','')[:60]}"
            elif event_type == 'issue_comment':
                summary = f"Comment on #{payload.get('issue',{}).get('number','')} by {payload.get('comment',{}).get('user',{}).get('login','')}"
            elif event_type == 'pull_request':
                summary = f"PR #{payload.get('pull_request',{}).get('number','')} {action}: {payload.get('pull_request',{}).get('title','')[:60]}"
            elif event_type == 'pull_request_review':
                summary = f"Review on PR #{payload.get('pull_request',{}).get('number','')} by {payload.get('review',{}).get('user',{}).get('login','')}"
            elif event_type in ('discussion', 'discussion_comment'):
                summary = f"Discussion #{payload.get('discussion',{}).get('number','')} {action}"
            elif event_type == 'ping':
                self.send_response(200); self.end_headers(); self.wfile.write(b'pong'); return
            with lock:
                entry = {'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'type': 'WEBHOOK', 'uid': 0,
                         'binary': f'github:{event_type}', 'args': summary,
                         'policy': '', 'is_agent': True, 'source': 'webhook'}
                append_event(entry)
            # Skip events from our own bot to avoid loops
            sender = payload.get('sender', {}).get('login', '')
            # Check if the bot was @mentioned in a comment
            comment_body = payload.get('comment', {}).get('body', '') or ''
            is_mention = '@aethersdr-agent' in comment_body.lower() or '@aetherclaude' in comment_body.lower()
            if sender in ('AetherClaude', 'aethersdr-agent[bot]'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (own event)'); return
            # Allow maintainer events through if they @mention the bot
            if sender == 'ten9876' and not is_mention:
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (maintainer)'); return
            # Skip irrelevant actions
            if event_type == 'issues' and action not in ('opened', 'edited', 'labeled', 'reopened'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'issue_comment' and action != 'created':
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'pull_request' and action not in ('opened', 'synchronize', 'reopened'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            # Debounce — don't trigger more than once per 60 seconds (unless @mention)
            now = time.time()
            if not is_mention and now - _last_webhook_trigger < 60:
                self.send_response(200); self.end_headers(); self.wfile.write(b'Debounced'); return
            _last_webhook_trigger = now
            # Write mention flag for orchestrator
            if is_mention:
                try:
                    mention_issue = payload.get('issue', payload.get('pull_request', {})).get('number', '')
                    with open('/Users/aetherclaude/state/mention', 'w') as mf:
                        mf.write(str(mention_issue))
                except: pass
            # Trigger agent run locally via launchctl
            try:
                import subprocess
                subprocess.Popen(['/bin/launchctl', 'kickstart', 'system/com.aetherclaude.agent'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with lock:
                    entry = {'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'type': 'WEBHOOK', 'uid': 0,
                             'binary': 'trigger', 'args': f'Agent triggered by {event_type}: {summary[:80]}',
                             'policy': '', 'is_agent': True, 'source': 'webhook'}
                    append_event(entry)
            except: pass
            self.send_response(200); self.end_headers(); self.wfile.write(b'Triggered')
        else:
            self.send_response(404); self.end_headers()
    def _send_json(self, data):
        """Serialize to JSON with final redaction safety net."""
        raw = json.dumps(data)
        raw = _redact(raw)
        self.wfile.write(raw.encode())
    def log_message(self,*a):pass

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8080);p.add_argument('--bind',default='0.0.0.0');p.add_argument('--log',default='/Users/aetherclaude/logs/tetragon.log');a=p.parse_args()
    init_db()
    load_memory_buffer()
    threading.Thread(target=tail_nftables_log,daemon=True).start()
    threading.Thread(target=tail_sessions,daemon=True).start()
    threading.Thread(target=tail_orchestrator_skills,args=(ORCHESTRATOR_LOG,),daemon=True).start()
    threading.Thread(target=tail_tinyproxy_log,daemon=True).start()
    for target,fn in [(a.log,tail_log),(VALIDATION_LOG,tail_validation_log),(MCP_AUDIT_LOG,tail_mcp_audit)]:
        threading.Thread(target=fn,args=(target,),daemon=True).start()
    threading.Thread(target=scan_tokens,daemon=True).start()
    threading.Thread(target=scan_rings,daemon=True).start()
    s=HTTPServer((a.bind,a.port),H);print(f"Dashboard at http://{a.bind}:{a.port}")
    try:s.serve_forever()
    except KeyboardInterrupt:print("\nShutdown")

if __name__=='__main__':main()
