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
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone

# Canonical event timestamp format: ISO-8601 UTC, millisecond precision,
# explicit Z marker (e.g. 2025-05-07T21:23:45.123Z). Every producer that
# stamps "now" goes through now_utc_iso(); producers that pass through an
# upstream timestamp go through coerce_ms_iso() so they all converge on the
# same shape before reaching the frontend.
def now_utc_iso():
    t = time.time()
    ms = int((t - int(t)) * 1000)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t)) + f'.{ms:03d}Z'

_iso_re = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$')

def coerce_ms_iso(s):
    """Coerce an ISO-8601 string to YYYY-MM-DDTHH:MM:SS.mmmZ. Accepts inputs
    with no fractional seconds, with arbitrary fractional precision (millis,
    micros, nanos), and with Z or +HH:MM zone markers. Non-UTC zones are
    converted to UTC. Naive inputs (no zone) are treated as UTC. Returns
    the input unchanged if it doesn't parse as ISO-8601."""
    if not s:
        return ''
    m = _iso_re.match(s.strip())
    if not m:
        return s
    base, frac, zone = m.group(1), m.group(2) or '', m.group(3) or ''
    # fromisoformat caps fractional precision at microseconds
    frac6 = (frac + '000000')[:6] if frac else '000000'
    iso_zone = '+00:00' if (zone == 'Z' or not zone) else zone
    if len(iso_zone) == 5:  # +HHMM -> +HH:MM
        iso_zone = iso_zone[:3] + ':' + iso_zone[3:]
    try:
        dt = datetime.fromisoformat(f'{base}.{frac6}{iso_zone}').astimezone(timezone.utc)
    except ValueError:
        return s
    return dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{dt.microsecond // 1000:03d}Z'

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

# Private fonts directory — for proprietary/branded font files that are
# NOT committed to the repo. Drop a .woff2/.woff/.otf/.ttf file here and
# it'll be served at /fonts/<filename>. CSS falls back to the system
# stack when the file is absent, so an empty dir is a no-op. Override
# with the env var if you want to keep fonts somewhere else on the box.
PRIVATE_FONTS_DIR = os.environ.get(
    'AETHERCLAUDE_PRIVATE_FONTS_DIR',
    '/Users/aetherclaude/private/fonts'
)

# Codegraph (AetherSDR knowledge-graph viz) — read by /codegraph and
# /api/codegraph/* routes. Built by bin/codegraph-extract.py +
# codegraph-analyze.py on a nightly launchd schedule. Static JS assets
# (Sigma.js + graphology) are vendored under the repo's assets/codegraph/.
# codegraph.db lives under /Users/Shared so the nightly refresh job
# (which writes via a Colima/Docker container running under jeremy's
# colima socket) can publish atomically without needing root or
# aetherclaude-owned data dir write access.
CODEGRAPH_DB = '/Users/Shared/aetherclaude/data/codegraph.db'
CODEGRAPH_ASSETS_DIR = '/Users/Shared/aetherclaude/assets/codegraph'
CLAUDE_PROJECTS_DIR = '/Users/aetherclaude/.claude/projects'
# How many chars of prompt/response text to surface in the args column.
# Long enough to be informative for the SE demo (the first paragraph of an
# agent prompt with the meta-instructions is usually the interesting part),
# short enough to keep the events.db rows reasonable.
_TRANSCRIPT_PREVIEW_CHARS = 500
SESSION_DIR = '/Users/aetherclaude/.claude/projects'
MCP_SCAN_FILE = '/Users/aetherclaude/logs/mcp-scan-latest.json'
SKILL_SCAN_FILE = '/Users/aetherclaude/logs/skill-scan-latest.json'
NOISE_BINARIES = {'/usr/bin/python3', '/usr/local/bin/tetragon-dashboard.py'}
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', '')
WEBHOOK_EVENTS = {'issues', 'issue_comment', 'pull_request', 'pull_request_review',
                  'discussion', 'discussion_comment',
                  'check_run', 'workflow_run', 'release'}
_last_webhook_trigger = 0
# Per-lock-key debounce: webhooks for issue-X don't debounce webhooks
# for pr-Y. Each key tracked independently.
_last_webhook_trigger_per_key = {}

# Active trace_id for the Agent Walk view. Mirrored from
# /Users/aetherclaude/state/active-trace-id, which run-agent.sh writes
# at orchestrator start and removes (via EXIT trap) at orchestrator end.
# Webhook handler also sets this directly during the brief window between
# webhook arrival and orchestrator startup. Cleared when the file
# disappears (orch finished) — without that, fallback stamping bled into
# events from later unrelated agent runs and corrupted trace boundaries.
# 10-minute wall-clock backstop in case the file disappears unexpectedly.
_active_trace_id = None
_active_trace_started_ts = 0
_TRACE_FALLBACK_WINDOW_SECS = 600
ACTIVE_TRACE_FILE = '/Users/aetherclaude/state/active-trace-id'
# Map first-8-chars-of-trace_id → full trace_id, populated when /webhook
# mints. tail_orchestrator_skills uses this to expand the [xxxxxxxx] prefix
# embedded in orchestrator.log lines back into a full UUID.
_trace_prefix_to_full = {}

# Track last-persisted scan file mtimes to avoid duplicate DB inserts
_last_mcp_mtime = 0.0
_last_prompt_scan_mtime = 0.0
# Mtime of newest .md file in ~/skills/ at the time of last skill-scanner
# invocation. Used to skip the (slow, ~1s startup) scan unless a skill file
# has actually changed. Triggers on first dashboard cycle (when this is 0).
_last_skills_mtime = 0.0
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

# Scrubber noise — orchestrator's per-issue secret-redaction sed pass produces
# 6–8 events per issue (EXEC sed with the redaction regex, sed's atomic-write
# RENAME of a hidden temp file in .claude/projects/, plus wrapping FORK/EXIT).
# The args column shows the literal regex source `ghs_[A-Za-z0-9]\{30,\}/...`
# which is unique to that scrubber — not something legitimate text would
# contain — so it's a safe filter. Bumps the existing `suppressed` counter.
_SCRUBBER_NOISE_PATTERNS = [
    _re.compile(r'ghs_\[A-Za-z0-9\]'),
    _re.compile(r'ghp_\[A-Za-z0-9\]'),
    _re.compile(r'github_pat_\[A-Za-z0-9'),
    _re.compile(r'sk-ant-\[A-Za-z0-9'),
    # sed atomic-write temp file: .claude/projects/.../.!<pid>!<orig>.jsonl
    _re.compile(r'\.claude/projects/.*/\.!\d+!.+\.jsonl'),
]

def _is_scrubber_noise(entry):
    args = entry.get('args', '')
    return any(p.search(args) for p in _SCRUBBER_NOISE_PATTERNS)


def append_event(entry):
    """Append to memory ring buffer + DB queue. Redacts secrets. Generates alerts."""
    entry = dict(entry)
    entry['args'] = _redact(entry.get('args', ''))
    # Backfill trace_id from the active trace if the producer didn't supply
    # one. TWO gates:
    #   - wall-clock window: don't keep stamping forever after a webhook
    #     (1h cutoff)
    #   - event-time gate: the EVENT's own timestamp must be at-or-after
    #     the webhook arrival (with 5s grace for clock skew). Tail
    #     readers can be backlogged — an MCP audit line with
    #     timestamp=02:27 can arrive in append_event at wall-clock 02:31
    #     just after a webhook fired. Without this gate, that pre-webhook
    #     event would get the new trace_id and cascade into the
    #     time-window correlator's MIN(ts), pulling in more pre-webhook
    #     rows.
    if not entry.get('trace_id') and _active_trace_id:
        now = time.time()
        if now - _active_trace_started_ts < _TRACE_FALLBACK_WINDOW_SECS:
            ev_ts_str = (entry.get('time', '') or '')[:19]
            try:
                ev_ts = datetime.strptime(ev_ts_str, '%Y-%m-%dT%H:%M:%S').replace(
                    tzinfo=timezone.utc).timestamp()
                if ev_ts >= _active_trace_started_ts - 5:
                    entry['trace_id'] = _active_trace_id
            except (ValueError, TypeError):
                # Unparseable timestamp — skip fallback rather than risk
                # mis-attribution.
                pass
    if _is_scrubber_noise(entry):
        stats['suppressed'] += 1
        return
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

DB_MAX_BYTES = 1024 * 1024 * 1024   # 1 GiB FIFO cap on events.db
DB_PRUNE_INTERVAL_SECS = 300         # check every 5 min
DB_PRUNE_FRACTION = 0.10             # drop oldest 10% when over cap

def db_pruner():
    """Enforce a 1 GiB FIFO cap on events.db. When the file exceeds the cap,
    drop the oldest 10% of rows from `events` and VACUUM to reclaim disk
    space. Sister tables (codeguard_findings, mcp_scan_results, etc.) are
    tiny and untouched. VACUUM acquires an exclusive lock briefly; writes
    during that window will queue or be lost (acceptable — the loss is
    bounded by the 5-second flush cadence)."""
    import os
    while True:
        time.sleep(DB_PRUNE_INTERVAL_SECS)
        try:
            sz = os.path.getsize(EVENTS_DB)
            if sz < DB_MAX_BYTES:
                continue
            conn = sqlite3.connect(EVENTS_DB)
            try:
                total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                drop_n = max(int(total * DB_PRUNE_FRACTION), 1000)
                conn.execute(
                    'DELETE FROM events WHERE id IN '
                    '(SELECT id FROM events ORDER BY id LIMIT ?)',
                    (drop_n,)
                )
                conn.commit()
                conn.execute('VACUUM')
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass


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
                'INSERT INTO events (timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id) VALUES (?,?,?,?,?,?,?,?,?)',
                [(e.get('time',''), e.get('type',''), e.get('uid',''),
                  e.get('binary',''), e.get('args',''), e.get('policy',''),
                  e.get('is_agent', False), e.get('source',''), e.get('trace_id')) for e in batch]
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
        trace_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # Idempotent ALTER for DBs created before trace_id existed. SQLite raises
    # OperationalError "duplicate column name" if the column is already there;
    # silence that and let any other error surface.
    try:
        conn.execute('ALTER TABLE events ADD COLUMN trace_id TEXT')
    except sqlite3.OperationalError as e:
        if 'duplicate column' not in str(e).lower():
            raise
    conn.execute('CREATE INDEX IF NOT EXISTS idx_source ON events(source)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_type ON events(type)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_agent ON events(is_agent)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_created ON events(created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_trace_id ON events(trace_id)')
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
    conn.execute('''CREATE TABLE IF NOT EXISTS prompt_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        prompt_name TEXT,
        is_safe BOOLEAN,
        advisory_findings INTEGER,
        analyzers TEXT,
        threat_summary TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_prompt_scan_time ON prompt_scan_results(scan_time)')
    # One row per (scan-run × prompt × analyzer × technique). prompt_defense
    # findings get is_advisory=1 (12-vector hardening audit, not threats).
    # yara findings get is_advisory=0 (real threat patterns).
    conn.execute('''CREATE TABLE IF NOT EXISTS prompt_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        prompt_name TEXT NOT NULL,
        analyzer TEXT NOT NULL,
        technique_name TEXT,
        severity TEXT,
        summary TEXT,
        is_advisory BOOLEAN
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_pf_scan_time ON prompt_findings(scan_time)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_pf_prompt ON prompt_findings(prompt_name)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_pf_analyzer ON prompt_findings(analyzer)')
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
    conn.execute('''CREATE TABLE IF NOT EXISTS aibom_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        component_name TEXT,
        purl TEXT,
        vuln_id TEXT,
        severity TEXT,
        score REAL,
        summary TEXT,
        refs_json TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_aibom_vuln_scan_time ON aibom_vulnerabilities(scan_time)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_aibom_vuln_component ON aibom_vulnerabilities(component_name)')
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
            'SELECT timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id FROM events ORDER BY id DESC LIMIT ?',
            (MEMORY_BUFFER_MAX,))
        rows = cursor.fetchall()
        conn.close()
        entries = [{'time': r[0], 'type': r[1], 'uid': r[2], 'binary': r[3],
                    'args': r[4], 'policy': r[5], 'is_agent': bool(r[6]), 'source': r[7],
                    'trace_id': r[8]}
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
            'INSERT INTO events (timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id) VALUES (?,?,?,?,?,?,?,?,?)',
            (entry.get('time',''), entry.get('type',''), entry.get('uid',''),
             entry.get('binary',''), entry.get('args',''), entry.get('policy',''),
             entry.get('is_agent', False), entry.get('source',''), entry.get('trace_id'))
        )
        conn.commit()
        conn.close()
    except: pass

def db_query_events(limit=1000, source=None, event_type=None):
    try:
        conn = sqlite3.connect(EVENTS_DB)
        query = 'SELECT timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id FROM events'
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
                 'args': r[4], 'policy': r[5], 'is_agent': bool(r[6]), 'source': r[7],
                 'trace_id': r[8]}
                for r in reversed(rows)]
    except:
        return []

# How long to look back when backfilling trace_ids. Older traces probably
# already have everything they're going to get, and scanning further wastes
# CPU + DB time on each correlator pass.
_TRACE_BACKFILL_LOOKBACK_SECS = 6 * 3600  # 6 hours
# Time window around a known-trace event window to claim NULL siblings.
# 5 seconds covers eslogger lag and DefenseClaw audit_sink batch latency,
# without bleeding across the gap between consecutive agent runs (they're
# typically minutes apart due to the lockfile + 60s webhook debounce).
_TRACE_BACKFILL_PADDING_SECS = 5

def db_trace_backfill_correlator():
    """Backfill NULL trace_ids on rows that fall inside a known trace's time
    window. Also expands 8-char prefix trace_ids (left over from
    tail_orchestrator_skills when the prefix→full lookup missed) into their
    full UUID by matching against trace_ids the same row's neighbors carry.

    Two passes per cycle:
      1. Expand prefix-only IDs (where trace_id is exactly 8 hex chars)
         into the full trace_id from any row whose trace_id LIKE prefix%.
      2. Time-window claim: for each known trace_id, UPDATE all NULL-trace
         rows between (min_ts - pad) and (max_ts + pad) for that trace.

    Runs once per minute. Idempotent — re-claiming an already-correctly-
    tagged row is a no-op."""
    while True:
        time.sleep(60)
        # Coordinate with db_batch_writer so our writes don't race
        # against its inserts. Without this, our UPDATEs were hitting
        # SQLITE_BUSY and getting swallowed by the catch-all below,
        # leaving Pass 0 a no-op for hours at a time.
        try:
          with db_write_lock:
            conn = sqlite3.connect(EVENTS_DB, timeout=30)
            cutoff = (datetime.utcnow() - timedelta(seconds=_TRACE_BACKFILL_LOOKBACK_SECS)
                      ).strftime('%Y-%m-%dT%H:%M:%S')

            # Pass 0: un-attribute pre-trace events. The trace's "true
            # start" is whichever happened first — the WEBHOOK arrival
            # OR the orchestrator's `agent-run starting` boundary. Both
            # matter because:
            #   - Webhook-triggered traces have WEBHOOK first, then orch
            #     starts a few hundred ms later.
            #   - Calendar-triggered traces have orch start first, and a
            #     later webhook can BURST-ADOPT into the running trace.
            #     The orchestrator activity that predates that webhook
            #     legitimately belongs to the trace.
            # Using MIN(webhook_ts, agent_run_starting_ts) as the floor
            # preserves the orch-pre-webhook activity in burst-adopted
            # cases, while still cleaning genuinely cross-trace bleed.
            conn.execute(
                "UPDATE events SET trace_id = NULL "
                "WHERE id IN ( "
                "    SELECT e.id FROM events e "
                "    JOIN ( "
                "        SELECT trace_id, "
                "               MIN(CASE WHEN starts_trace THEN timestamp END) AS true_start "
                "        FROM ( "
                "            SELECT trace_id, timestamp, "
                "                   ( type='WEBHOOK' "
                "                     OR (source='skill-dispatch' "
                "                         AND binary_name='skill:agent-run' "
                "                         AND args='starting') "
                "                   ) AS starts_trace "
                "            FROM events "
                "            WHERE trace_id IS NOT NULL AND LENGTH(trace_id) > 8 "
                "        ) "
                "        GROUP BY trace_id "
                "        HAVING true_start IS NOT NULL "
                "    ) w ON e.trace_id = w.trace_id "
                "    WHERE e.timestamp < w.true_start "
                ")"
            )

            # Pass 1: expand 8-char prefix trace_ids to full UUIDs. The
            # tail_orchestrator_skills handler stores the prefix when the
            # /webhook prefix→full dict misses (e.g. calendar-triggered
            # runs). Once any other event in the same window arrives with
            # the full UUID, we can rewrite the prefix to match.
            prefix_rows = conn.execute(
                "SELECT DISTINCT trace_id FROM events "
                "WHERE LENGTH(trace_id) = 8 AND timestamp > ? "
                "LIMIT 100",
                (cutoff,)
            ).fetchall()
            for (prefix,) in prefix_rows:
                full_row = conn.execute(
                    "SELECT trace_id FROM events "
                    "WHERE trace_id LIKE ? AND LENGTH(trace_id) > 8 "
                    "LIMIT 1",
                    (prefix + '%',)
                ).fetchone()
                if full_row:
                    conn.execute(
                        "UPDATE events SET trace_id = ? WHERE trace_id = ?",
                        (full_row[0], prefix)
                    )

            # Pass 2: time-window claim NULL rows. Each trace's left-
            # edge floor is the EARLIER of its WEBHOOK row and its
            # `agent-run starting` row — same reasoning as Pass 0
            # (burst-adopted webhooks arrive after the orch already
            # started). Right edge is MAX(timestamp) + 5s for trailing
            # audit_sink lag.
            traces = conn.execute(
                "SELECT e.trace_id, MIN(e.timestamp), MAX(e.timestamp), "
                "       (SELECT MIN(w.timestamp) FROM events w "
                "        WHERE w.trace_id = e.trace_id AND w.type='WEBHOOK'), "
                "       (SELECT MIN(s.timestamp) FROM events s "
                "        WHERE s.trace_id = e.trace_id "
                "          AND s.source='skill-dispatch' "
                "          AND s.binary_name='skill:agent-run' "
                "          AND s.args='starting') "
                "FROM events e "
                "WHERE e.trace_id IS NOT NULL AND LENGTH(e.trace_id) > 8 "
                "  AND e.timestamp > ? "
                "GROUP BY e.trace_id",
                (cutoff,)
            ).fetchall()
            for trace_id, t_min, t_max, hook_ts, run_start_ts in traces:
                try:
                    t_max_dt = datetime.strptime(t_max[:19], '%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue
                # Floor = earlier of (webhook, run-start). If neither
                # exists (legacy / non-canonical traces), fall back to
                # MIN(t) - 5s padding.
                candidates = [t for t in (hook_ts, run_start_ts) if t]
                if candidates:
                    start = min(candidates)[:19]
                else:
                    try:
                        t_min_dt = datetime.strptime(t_min[:19], '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        continue
                    start = (t_min_dt - timedelta(seconds=_TRACE_BACKFILL_PADDING_SECS)
                             ).strftime('%Y-%m-%dT%H:%M:%S')
                end = (t_max_dt + timedelta(seconds=_TRACE_BACKFILL_PADDING_SECS)
                       ).strftime('%Y-%m-%dT%H:%M:%S')
                conn.execute(
                    "UPDATE events SET trace_id = ? "
                    "WHERE trace_id IS NULL "
                    "  AND timestamp >= ? AND timestamp <= ?",
                    (trace_id, start, end)
                )
            conn.commit()
            conn.close()
        except Exception as e:
            # Don't kill the thread on a transient DB lock. Surface the
            # exception type to stderr so non-transient breakage (logic
            # bugs, schema drift) is diagnosable in dashboard.log.
            try:
                print(f'[correlator] {type(e).__name__}: {e}', file=sys.stderr, flush=True)
            except Exception:
                pass

def track_active_trace():
    """Mirror /Users/aetherclaude/state/active-trace-id.<lock_key> files
    into _trace_prefix_to_full + _active_trace_id. Each running
    orchestrator writes its own per-key file; multiple may exist
    concurrently when parallel webhooks for different issues are running.

    For _active_trace_id (single-valued global, used as a best-effort
    fallback in append_event for events lacking explicit trace_id):
    pick the most-recently-modified file. Under heavy parallel load
    this fallback gets noisier, but the explicit per-source stamping
    (DC via active-trace, claude-transcript via issue-number lookup,
    MCP via process env) carries most of the load.

    Runs every 2s.
    """
    global _active_trace_id, _active_trace_started_ts
    import glob
    last_seen_set = set()
    while True:
        time.sleep(2)
        try:
            paths = glob.glob('/Users/aetherclaude/state/active-trace-id.*')
            current_set = set()
            best_mtime = 0
            best_content = None
            for p in paths:
                try:
                    with open(p) as f:
                        content = f.read().strip()
                    if not content:
                        continue
                    current_set.add(content)
                    # Register the prefix→full mapping for every active
                    # orch so tail_orchestrator_skills can resolve any
                    # [xxxxxxxx] from any concurrent run.
                    if len(content) >= 8:
                        _trace_prefix_to_full[content[:8]] = content
                    mt = os.path.getmtime(p)
                    if mt > best_mtime:
                        best_mtime = mt
                        best_content = content
                except (FileNotFoundError, OSError):
                    continue
            if best_content and best_content != _active_trace_id:
                _active_trace_id = best_content
                _active_trace_started_ts = time.time()
            elif not current_set and last_seen_set:
                # All orchs gone. Clear fallback.
                _active_trace_id = None
                _active_trace_started_ts = 0
            last_seen_set = current_set
        except Exception:
            pass

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

                        # Build the per-tool detail list shown in the modal.
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

                        # Persist + emit only when the JSON file's mtime changed
                        # (i.e. the orchestrator just produced a fresh scan).
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
                            # Inject one SCAN event per tool into the event stream
                            for detail in mcp_details:
                                sev = 'SAFE' if detail.get('safe') else detail.get('severity', 'HIGH')
                                entry = {
                                    'time': now_utc_iso(),
                                    'type': 'SCAN',
                                    'uid': 965,
                                    'binary': 'mcp-scanner',
                                    'args': f"{detail['name']}: {sev}" + (f" — {detail.get('threat','')}" if not detail.get('safe') else ''),
                                    'policy': 'mcp-scanner' if not detail.get('safe') else '',
                                    'is_agent': True,
                                    'source': 'mcp-scan'
                                }
                                # Dedup against the last 50 buffered events to avoid
                                # spamming the stream when the watcher re-reads the
                                # same file before mtime changes again.
                                if not any(e.get('source') == 'mcp-scan' and e.get('args','').startswith(detail['name']) for e in list(memory_buffer)[-50:]):
                                    append_event(entry)
                    else:
                        # Scanner JSON missing — fall back to whatever's already
                        # in the DB so the ring counter stays accurate. No new
                        # SCAN events emitted in this branch (nothing to emit).
                        dbc = sqlite3.connect(EVENTS_DB)
                        ring_stats['r6_mcp_tools_scanned'] = dbc.execute('SELECT COUNT(DISTINCT tool_name) FROM mcp_scan_results').fetchone()[0]
                        ring_stats['r6_mcp_threats'] = dbc.execute("SELECT COUNT(DISTINCT tool_name) FROM mcp_scan_results WHERE is_safe=0").fetchone()[0]
                        dbc.close()
                except: pass

                # ── Prompt scan ingestion (parallel to MCP scan above) ──
                # Reads /Users/aetherclaude/logs/prompt-scan-latest.json (written
                # by the orchestrator's Prompt Scanner pre-flight via
                # scan-prompts-pd.py). On mtime change: persist per-prompt rows
                # to prompt_scan_results and emit one SCAN event per prompt
                # (source=prompt-scan) so the dashboard's [Scan] filter shows
                # them alongside MCP findings.
                try:
                    prompt_scan_file = os.path.join(
                        os.path.dirname(MCP_SCAN_FILE), 'prompt-scan-latest.json')
                    if os.path.exists(prompt_scan_file):
                        with open(prompt_scan_file) as psf:
                            prompt_scan = json.load(psf)
                        prompt_results = prompt_scan.get('scan_results', [])
                        ring_stats['r6_prompts_scanned'] = len(prompt_results)
                        ring_stats['r6_prompt_threats'] = sum(
                            1 for r in prompt_results if not r.get('is_safe', True))
                        ring_stats['r6_prompt_advisory'] = sum(
                            r.get('advisory_hardening_findings', 0) for r in prompt_results)

                        global _last_prompt_scan_mtime
                        psm = os.path.getmtime(prompt_scan_file)
                        if psm != _last_prompt_scan_mtime:
                            _last_prompt_scan_mtime = psm
                            try:
                                dbc = sqlite3.connect(EVENTS_DB)
                                for r in prompt_results:
                                    findings = r.get('findings', {}) or {}
                                    analyzers = ','.join(sorted(findings.keys())) or ''
                                    summary = next(
                                        (v.get('threat_summary', '') for v in findings.values()),
                                        '')
                                    pname = r.get('prompt_name', '')
                                    dbc.execute(
                                        'INSERT INTO prompt_scan_results '
                                        '(prompt_name, is_safe, advisory_findings, analyzers, threat_summary) '
                                        'VALUES (?,?,?,?,?)',
                                        (pname, r.get('is_safe', True),
                                         r.get('advisory_hardening_findings', 0),
                                         analyzers, summary))
                                    # Flatten each analyzer's threats.items[] into prompt_findings rows
                                    for analyzer_key, analyzer_data in findings.items():
                                        is_advisory = (analyzer_key == 'promptdefense_analyzer')
                                        items = ((analyzer_data or {}).get('threats') or {}).get('items') or []
                                        for item in items:
                                            dbc.execute(
                                                'INSERT INTO prompt_findings '
                                                '(prompt_name, analyzer, technique_name, severity, summary, is_advisory) '
                                                'VALUES (?,?,?,?,?,?)',
                                                (pname, analyzer_key,
                                                 item.get('technique_name', '') or '',
                                                 item.get('severity', '') or '',
                                                 item.get('summary', '') or '',
                                                 is_advisory))
                                dbc.commit(); dbc.close()
                            except: pass
                            for r in prompt_results:
                                pname = r.get('prompt_name', '?')
                                safe = r.get('is_safe', True)
                                advisory = r.get('advisory_hardening_findings', 0)
                                args = (f"{pname}: SAFE" if safe
                                        else f"{pname}: UNSAFE — {next((v.get('threat_summary','') for v in (r.get('findings') or {}).values()), '')}")
                                if advisory:
                                    args += f"  ({advisory} advisory)"
                                entry = {
                                    'time': now_utc_iso(),
                                    'type': 'SCAN',
                                    'uid': 965,
                                    'binary': 'prompt-scanner',
                                    'args': args,
                                    'policy': '' if safe else 'prompt-scanner',
                                    'is_agent': True,
                                    'source': 'prompt-scan',
                                }
                                if not any(
                                    e.get('source') == 'prompt-scan'
                                    and e.get('args', '').startswith(pname)
                                    for e in list(memory_buffer)[-50:]
                                ):
                                    append_event(entry)
                except: pass

                try:
                    # Skill scanner — event-driven (file-mtime gated). Only
                    # invokes skill-scanner when a .md file in ~/skills/ has
                    # actually changed since last scan; ring counters and
                    # persisted rows survive between events. First dashboard
                    # cycle still triggers a scan because _last_skills_mtime=0.
                    # Cuts ~5,760 unnecessary scanner exec/day.
                    skills_dir = '/Users/aetherclaude/skills'
                    workspace_cmds = '/Users/aetherclaude/workspace/AetherSDR/.claude/commands'
                    global _last_skills_mtime

                    if os.path.isdir(skills_dir):
                        files = [f for f in os.listdir(skills_dir) if f.endswith('.md')]
                        skills_scanned = len(files)
                        max_file_mtime = max(
                            (os.path.getmtime(os.path.join(skills_dir, f)) for f in files),
                            default=0,
                        )
                        # Catch additions/removals via dir mtime
                        current_mtime = max(max_file_mtime, os.path.getmtime(skills_dir))

                        if current_mtime > _last_skills_mtime:
                            _last_skills_mtime = current_mtime
                            scan_out = sh(f"skill-scanner scan {skills_dir} --lenient --format json 2>/dev/null")
                            skill_results = []
                            if scan_out:
                                try:
                                    parsed = json.loads(scan_out)
                                    if isinstance(parsed, dict) and parsed.get('status') == 'skipped':
                                        skill_results = []
                                    else:
                                        skill_results = parsed if isinstance(parsed, list) else [parsed]
                                except: skill_results = []
                            total_findings = sum(
                                r.get('findings_count', 0)
                                for r in skill_results if isinstance(r, dict)
                            )
                            ring_stats['r6_skills_scanned'] = skills_scanned
                            ring_stats['r6_skill_findings'] = total_findings
                            ring_stats['r6_skill_status'] = (
                                f'{skills_scanned} skills scanned' if total_findings == 0
                                else f'{total_findings} findings in {skills_scanned} skills'
                            )
                            # Persist this scan-run's rows
                            if skill_results:
                                try:
                                    dbc = sqlite3.connect(EVENTS_DB)
                                    for r in skill_results:
                                        for f in r.get('findings', []):
                                            dbc.execute(
                                                'INSERT INTO skill_scan_results (skill_name, is_safe, max_severity, findings_count, finding_id, finding_severity, finding_title, finding_description, finding_remediation, analyzers) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                                (r.get('skill_name',''), r.get('is_safe',True), r.get('max_severity',''),
                                                 r.get('findings_count',0), f.get('rule_id',''), f.get('severity',''),
                                                 f.get('title',''), f.get('description',''), f.get('remediation',''),
                                                 ','.join(r.get('analyzers_used',[]))))
                                        if not r.get('findings'):
                                            dbc.execute(
                                                'INSERT INTO skill_scan_results (skill_name, is_safe, max_severity, findings_count, finding_id, finding_severity, finding_title, analyzers) VALUES (?,?,?,?,?,?,?,?)',
                                                (r.get('skill_name',''), r.get('is_safe',True), r.get('max_severity','SAFE'),
                                                 0, '', 'SAFE', 'No findings', ','.join(r.get('analyzers_used',[]))))
                                    dbc.commit(); dbc.close()
                                except: pass
                            # Emit one SCAN event per real scan event
                            sev = 'SAFE' if total_findings == 0 else 'HIGH'
                            entry = {
                                'time': now_utc_iso(),
                                'type': 'SCAN', 'uid': 965, 'binary': 'skill-scanner',
                                'args': ring_stats['r6_skill_status'],
                                'policy': '' if sev == 'SAFE' else 'skill-scanner',
                                'is_agent': True, 'source': 'skill-scan',
                            }
                            append_event(entry)
                        else:
                            # No file change — keep counters from last real scan
                            ring_stats.setdefault('r6_skills_scanned', skills_scanned)
                            ring_stats.setdefault('r6_skill_findings', 0)
                            ring_stats.setdefault('r6_skill_status', f'{skills_scanned} skills scanned')
                    else:
                        ring_stats['r6_skill_status'] = 'no skills dir'

                    # Cheap directory listing — keep running every cycle so an
                    # injected skill is caught immediately.
                    injected_files = []
                    if os.path.isdir(workspace_cmds):
                        injected_files = [f for f in os.listdir(workspace_cmds) if f.endswith('.md')]
                    ring_stats['r6_skill_injected'] = len(injected_files) > 0
                    ring_stats['r6_skill_injected_count'] = len(injected_files)
                    ring_stats['r6_skill_injected_files'] = injected_files
                except Exception as _e:
                    ring_stats['r6_skill_status'] = f'error: {_e}'

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
                        ring_stats['r6_aibom_scanner_version'] = aibom.get('version', '1.0.0')
                        ring_stats['r6_aibom_vulns'] = summary.get('vulnerabilities_found', 0)
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
                                    for v in c.get('vulnerabilities', []) or []:
                                        dbc.execute(
                                            'INSERT INTO aibom_vulnerabilities (component_name, purl, vuln_id, severity, score, summary, refs_json) VALUES (?,?,?,?,?,?,?)',
                                            (c.get('name',''), c.get('purl',''), v.get('id',''),
                                             v.get('severity','UNKNOWN'), v.get('score'),
                                             v.get('summary',''), json.dumps(v.get('references', []))))
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
                        SELECT ia.issue_number, ia.state, ia.outcome, ia.action, ia.detail, ia.created_at || '.000Z'
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
                                    recent.append({'op': label, 'url': url, 'num': str(num),
                                                   'time': coerce_ms_iso(ts)})
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
                header = parts[0] if len(parts) > 1 else ''
                msg = parts[1] if len(parts) > 1 else line
                # Header is "<ISO-timestamp>" or "<ISO-timestamp> [<8-hex>]".
                # The orchestrator-side log() stamps the trace prefix; pull
                # it out and resolve to a full UUID via _trace_prefix_to_full
                # so codeguard events get deterministic trace attribution
                # instead of relying on append_event's global active-trace
                # heuristic (which races under parallel orchestrators).
                ts = header.split()[0] if header else ''
                m_prefix = re.search(r'\[([0-9a-f]{8})\]', header)
                trace_for_entry = None
                if m_prefix:
                    short = m_prefix.group(1)
                    trace_for_entry = _trace_prefix_to_full.get(short, short)
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
                entry = {'time': ts, 'type': 'GUARD', 'uid': 965, 'binary': 'codeguard',
                         'args': msg[:120],
                         'policy': 'codeguard' if 'CodeGuard' in msg else 'validation-gate',
                         'is_agent': True, 'source': 'codeguard',
                         'trace_id': trace_for_entry}
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
                    mcp_ts = coerce_ms_iso(d.get('timestamp', ''))
                    entry = {'time': mcp_ts, 'type': 'MCP', 'uid': 965, 'binary': 'mcp-server', 'args': f"{op} → {result_preview}", 'policy': '', 'is_agent': True, 'source': 'mcp', 'trace_id': d.get('trace_id')}
                    if 'BLOCKED' in result_preview or 'RATE LIMITED' in result_preview:
                        entry['policy'] = 'mcp-blocked'
                        stats['alerts'].append({'time': mcp_ts, 'msg': f"MCP: {op} — {result_preview}", 'severity': 'high'})
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
            ts = now_utc_iso()

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
            ts = now_utc_iso()
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

# --- Session→trace correlation (leveraged by --worktree wiring) ---
# Each orchestrator runs claude with cwd = $WORKSPACE/.claude/worktrees/<lock_key>,
# so Claude Code writes its session JSONL under
# ~/.claude/projects/-Users-aetherclaude-workspace-AetherSDR--claude-worktrees-<lock_key>/.
# Parsing lock_key out of the project dir gives us a deterministic lookup into
# state/trace-id.<lock_key>, eliminating the fuzzy time-window pass for the
# entire Claude swimlane.
_session_trace = {}  # filepath -> (trace_id, lock_key); stable for file lifetime
_WORKTREE_RE = re.compile(r'--claude-worktrees-(.+)$')

def _session_trace_lookup(filepath):
    """Return (trace_id, lock_key) for a Claude session JSONL path. Cached
    once per filepath. Returns (None, None) for legacy (pre-worktree)
    session paths; the caller may then fall back to a wider strategy
    (DB WEBHOOK-row join, or append_event's global _active_trace_id)."""
    cached = _session_trace.get(filepath)
    if cached is not None:
        return cached
    proj_dir = os.path.basename(os.path.dirname(filepath))
    m = _WORKTREE_RE.search(proj_dir)
    if not m:
        _session_trace[filepath] = (None, None)
        return None, None
    lk = m.group(1)
    try:
        with open(f'/Users/aetherclaude/state/trace-id.{lk}') as f:
            tid = f.read().strip() or None
    except (FileNotFoundError, PermissionError, OSError):
        tid = None
    if tid:
        # Cache only when both halves are resolved; if state file isn't
        # flushed yet (tight race at orch startup), retry on next event.
        _session_trace[filepath] = (tid, lk)
    return tid, lk

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

                                trace_id, _lk = _session_trace_lookup(filepath)
                                with lock:
                                    entry = {
                                        'time': ts,
                                        'type': 'TOOL',
                                        'uid': 965,
                                        'binary': f'claude:{name}',
                                        'args': detail,
                                        'policy': '',
                                        'is_agent': True,
                                        'source': 'claude-code',
                                        'trace_id': trace_id,
                                    }
                                    append_event(entry)
                        except:
                            continue
                except (PermissionError, FileNotFoundError):
                    continue
        except:
            pass
        time.sleep(2)

DEFENSECLAW_AUDIT_LOG = '/Users/aetherclaude/.defenseclaw/gateway.jsonl'

def tail_defenseclaw_audit(logfile):
    """Tail the DefenseClaw v7 OTel-schema gateway audit log and surface
    each entry as a DEFENSE event in the stream. Schema reference:
    docs/OBSERVABILITY-CONTRACT.md in the upstream repo."""
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
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = coerce_ms_iso(rec.get('ts', ''))
            etype = rec.get('event_type', 'unknown')
            sev = (rec.get('severity', 'INFO') or 'INFO').upper()

            # Build a short human summary for the args column
            args_text = ''
            policy = ''
            if etype == 'lifecycle':
                lc = rec.get('lifecycle', {}) or {}
                args_text = f"{lc.get('subsystem','?')} {lc.get('transition','?')}"
                detail = (lc.get('details') or {}).get('details') or ''
                if detail and not detail.startswith('<redacted'):
                    args_text += f" — {detail[:80]}"
            elif etype == 'error':
                err = rec.get('error', {}) or {}
                args_text = f"{err.get('code','ERROR')}: {err.get('subsystem','?')}"
                policy = err.get('code', '')
            elif etype == 'verdict':
                v = rec.get('verdict', {}) or {}
                args_text = f"{v.get('decision','?')} {v.get('rule_pack','?')} — {v.get('reason','')[:80]}"
                policy = v.get('rule_pack', '')
            elif etype == 'scan':
                s = rec.get('scan', {}) or {}
                args_text = f"{s.get('scanner','?')} → {s.get('result','?')}"
                policy = s.get('scanner', '')
            else:
                # Generic fallback — just show the event_type
                args_text = etype

            # NOTE: DC's `run_id` field is the DAEMON's lifetime process
            # ID (set once when the gateway boots, identical across all
            # subsequent agent runs). It is NOT the orchestrator's
            # AETHER_TRACE_ID. We previously extracted it here and
            # mistagged DC events into a single mega-trace spanning the
            # daemon's lifetime. Leave trace_id off — append_event's
            # active-trace fallback (mirrored from
            # /Users/aetherclaude/state/active-trace-id by
            # track_active_trace) gives the correct per-agent-run
            # tagging.
            entry = {
                'time': ts,
                'type': 'DEFENSE',
                'uid': 965,
                'binary': 'defenseclaw-gateway',
                'args': args_text,
                'policy': policy,
                'is_agent': True,
                'source': 'defenseclaw',
            }
            with lock:
                append_event(entry)


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

            # Run-level boundaries (lowest specificity — overridden below if a
            # later pattern matches the same line, which won't happen for these).
            m = re.search(r'=== Agent run starting ===', line)
            if m:
                skill = 'agent-run'; detail = 'starting'
                # Race fix: when we see an Agent-run-starting line, the
                # orchestrator has JUST written /Users/aetherclaude/state/
                # active-trace-id with its full UUID. The tracker thread
                # polls every 2s, so it might not have updated
                # _trace_prefix_to_full yet. Read the file directly so
                # the prefix→full lookup below resolves to the full UUID
                # instead of falling back to the 8-char stub.
                try:
                    with open(ACTIVE_TRACE_FILE) as _f:
                        _full = _f.read().strip()
                    if _full and len(_full) > 8:
                        _trace_prefix_to_full[_full[:8]] = _full
                        global _active_trace_id, _active_trace_started_ts
                        _active_trace_id = _full
                        _active_trace_started_ts = time.time()
                except (FileNotFoundError, OSError):
                    pass

            m = re.search(r'=== Agent run complete ===', line)
            if m: skill = 'agent-run'; detail = 'complete'

            # Generic skill-section header. Matches "--- Skill: NAME ---" for
            # every section the orchestrator enters (Welcome, Bug Report
            # Quality, Issue Pipeline, PR Review, Duplicate Detection, CI
            # Failure Explainer, Discussion Responder, @Mention Response).
            # Specific per-issue patterns below override this for richer detail.
            m = re.search(r'--- Skill: (.+?) ---', line)
            if m: skill = 'skill-section'; detail = m.group(1)

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

            m = re.search(r'VT Scan: (.+)', line)
            if m: skill = 'vt-scan'; detail = m.group(1)

            m = re.search(r'Prompt Scanner: (.+)', line)
            if m: skill = 'prompt-scanner'; detail = m.group(1)

            m = re.search(r'Token Rotated: (.+)', line)
            if m: skill = 'dc-rotate'; detail = m.group(1)

            # --- Orchestrator state-machine and substep markers ---
            # These describe the orchestrator's own work (state transitions,
            # phase boundaries, validation, push, PR creation) — not skill
            # dispatch. Their binary uses the 'skill:orch-*' prefix so the
            # classifier routes them to Stage 2 (Orchestrator) rather than
            # Stage 3 (Skill). Without these the Orchestrator lane has only
            # agent-run start/stop, which is what the dashboard previously
            # showed.
            m = re.search(r'Trigger: (\S+)\s*(?:\(([^)]+)\))?', line)
            if m: skill = 'orch-trigger'; detail = f'{m.group(1)}{":"+m.group(2) if m.group(2) else ""}'

            m = re.search(r'Found (\d+) candidate (issues|prs|discussions)', line)
            if m: skill = 'orch-pipeline'; detail = f'{m.group(1)} {m.group(2)}'

            m = re.search(r'Issue #(\d+) — detected state: (\S+)', line)
            if m: skill = 'orch-state'; detail = f'Issue #{m.group(1)}: {m.group(2)}'

            m = re.search(r'Issue #(\d+) — state changed to (\S+)', line)
            if m: skill = 'orch-transition'; detail = f'Issue #{m.group(1)} → {m.group(2)}'

            m = re.search(r'Issue #(\d+) — already (\S+), skipping', line)
            if m: skill = 'orch-skip'; detail = f'Issue #{m.group(1)} ({m.group(2)})'

            m = re.search(r'Issue #(\d+) — \d+ PR\(s\) already exist', line)
            if m: skill = 'orch-skip'; detail = f'Issue #{m.group(1)} (PR exists)'

            m = re.search(r'Issue #(\d+) — asked questions, moving to (\S+)', line)
            if m: skill = 'orch-transition'; detail = f'Issue #{m.group(1)} → {m.group(2)}'

            m = re.search(r'Issue #(\d+) — triage complete, moving to (\S+)', line)
            if m: skill = 'orch-transition'; detail = f'Issue #{m.group(1)} → {m.group(2)}'

            m = re.search(r'Issue #(\d+) — Claude handed off to maintainer', line)
            if m: skill = 'orch-transition'; detail = f'Issue #{m.group(1)} → maintainer-review'

            m = re.search(r'Issue #(\d+) — maintainer authorized', line)
            if m: skill = 'orch-transition'; detail = f'Issue #{m.group(1)} → implement'

            m = re.search(r'Running Claude Code for issue #(\d+)', line)
            if m: skill = 'orch-claude-start'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'Issue #(\d+) — (\d+) commit\(s\) from Claude Code', line)
            if m: skill = 'orch-commits'; detail = f'Issue #{m.group(1)}: {m.group(2)} commits'

            m = re.search(r'Running validation gate for issue #(\d+)', line)
            if m: skill = 'orch-validate'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'VALIDATION FAILED for issue #(\d+)', line)
            if m: skill = 'orch-validate-fail'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'Pushing branch (\S+) as signed commit', line)
            if m: skill = 'orch-push'; detail = f'branch {m.group(1)}'

            m = re.search(r'Signed commit ([0-9a-f]+) pushed to (\S+)', line)
            if m: skill = 'orch-push-done'; detail = f'{m.group(1)} → {m.group(2)}'

            m = re.search(r'Creating PR for issue #(\d+)', line)
            if m: skill = 'orch-pr'; detail = f'Issue #{m.group(1)}'

            m = re.search(r'PR #(\d+) created for issue #(\d+)', line)
            if m: skill = 'orch-pr-done'; detail = f'PR #{m.group(1)} for #{m.group(2)}'

            m = re.search(r'Completed issue #(\d+)', line)
            if m: skill = 'orch-complete'; detail = f'Issue #{m.group(1)}'

            # Errors / timeouts — last so a generic regex doesn't swallow
            # a more specific match above. Don't catch random ERROR: lines
            # from sub-tools (validate-diff, MCP); restrict to orchestrator-
            # framed errors via the leading [trace_prefix] log marker.
            m = re.search(r'(ERROR|TIMEOUT|CRITICAL): (.+)', line)
            if m and not skill: skill = f'orch-{m.group(1).lower()}'; detail = m.group(2)[:80]

            if skill:
                # The orchestrator log timestamps in local time without a zone
                # marker, which would parse as local in the browser only by
                # accident. We're tailing in real time, so just stamp "now" in
                # canonical UTC.
                ts = now_utc_iso()
                # Pull the [xxxxxxxx] trace_id prefix that run-agent.sh's
                # log() function stamps. Resolve to full UUID via the dict
                # populated by /webhook; fall back to the prefix itself so
                # Stage 5's PID-tree correlator can expand it later.
                m_prefix = re.search(r'\[([0-9a-f]{8})\]', line)
                trace_for_entry = None
                if m_prefix:
                    short = m_prefix.group(1)
                    trace_for_entry = _trace_prefix_to_full.get(short, short)
                # Scanner output emitted into the orchestrator log is not a
                # skill-dispatch event — it's a SCAN event. Classify it that
                # way so the Scan filter button picks it up and the agent-
                # walk classifier routes it to the right stage (4 = pre-
                # flight scanning; 5 = prompt-scanner, kept in Stage 5 with
                # the prompt itself). Everything else (real skill markers
                # like 'First-Time Contributor Welcome', '@Mention …',
                # 'Token Rotated …') stays SKILL.
                _SCANNERS = {
                    'skill-scanner':   'skill-scan',
                    'mcp-scanner':     'mcp-scan',
                    'vt-scan':         'vt-scan',
                    'prompt-scanner':  'prompt-scan',
                }
                if skill in _SCANNERS:
                    ev_type = 'SCAN'
                    ev_binary = skill
                    ev_source = _SCANNERS[skill]
                else:
                    ev_type = 'SKILL'
                    ev_binary = f'skill:{skill}'
                    ev_source = 'skill-dispatch'
                with lock:
                    entry = {
                        'time': ts,
                        'type': ev_type,
                        'uid': 965,
                        'binary': ev_binary,
                        'args': detail,
                        'policy': '',
                        'is_agent': True,
                        'source': ev_source,
                        'trace_id': trace_for_entry,
                    }
                    append_event(entry)

def tail_claude_transcripts():
    """Tail Claude Code's session JSONL transcripts under
    /Users/aetherclaude/.claude/projects/*/. Surfaces the actual prompt
    and response *content* — DefenseClaw's audit redacts these fields by
    default (`<redacted len=N sha=…>`), so we read from Claude Code's
    own stream instead. All output is _redact()-scrubbed for tokens
    before storage and truncated to TRANSCRIPT_PREVIEW_CHARS.

    Format observations (verified against a real session):
      - User prompts: type=user, message.role=user, message.content is
        a STRING. (Tool results are also type=user but content is a
        list with type=tool_result; we skip those.)
      - Assistant responses: type=assistant, message.content is a list
        of blocks; we extract the text blocks (skipping tool_use).

    Each project directory holds one JSONL per session. New files
    appear as new sessions start; existing files are append-only.
    Track per-file read offset; rescan the directory every few seconds
    for new files.
    """
    file_offsets = {}  # absolute path → byte offset of last-read end
    # Per-file trace_id snapshot. When we first see a new session file
    # we resolve which webhook (issue number → most recent WEBHOOK row)
    # triggered the orchestrator that created it. Using a snapshot
    # protects us from multi-webhook bursts where _active_trace_id
    # would get overwritten to a later (wrong) trace mid-session.
    file_trace_id = {}
    startup_ts = time.time()

    def _trace_for_session_path(p):
        """Map a session JSONL path to a trace_id. Strategy:
          1. State-file lookup via _session_trace_lookup — deterministic
             and free for paths under .claude/worktrees/<lock_key>/.
          2. DB WEBHOOK-row join — fallback for legacy session paths
             (calendar-era runs, manual claude invocations not under a
             worktree) where the state file doesn't exist.
        Returns None if neither resolves."""
        tid, _lk = _session_trace_lookup(p)
        if tid:
            return tid
        try:
            project_dir = os.path.basename(os.path.dirname(p))
            # Project dirs look like '-private-tmp-aetherclaude-issue-1028'
            # — pull the trailing -issue-NNNN if present.
            m = re.search(r'issue-(\d+)$', project_dir) or \
                re.search(r'pr-(\d+)$', project_dir) or \
                re.search(r'-(\d+)$', project_dir)
            if not m:
                return None
            issue_num = m.group(1)
            conn = sqlite3.connect(EVENTS_DB)
            # Webhook args look like 'Issue #1028 opened: …' or
            # 'Comment on #1028 by …' or 'PR #1028 opened: …'.
            # Anchor on '#NNNN ' (with trailing space) so '#1028' doesn't
            # match '#10280' too.
            row = conn.execute(
                "SELECT trace_id FROM events "
                "WHERE type='WEBHOOK' AND trace_id IS NOT NULL "
                "  AND args LIKE ? "
                "ORDER BY id DESC LIMIT 1",
                (f'%#{issue_num} %',)
            ).fetchone()
            conn.close()
            return row[0] if row else None
        except Exception:
            return None

    while True:
        try:
            # Enumerate every .jsonl under the projects tree.
            paths = []
            try:
                for project in os.listdir(CLAUDE_PROJECTS_DIR):
                    pdir = os.path.join(CLAUDE_PROJECTS_DIR, project)
                    if not os.path.isdir(pdir):
                        continue
                    for fname in os.listdir(pdir):
                        if fname.endswith('.jsonl'):
                            paths.append(os.path.join(pdir, fname))
            except FileNotFoundError:
                time.sleep(10)
                continue

            for path in paths:
                try:
                    st = os.stat(path)
                    size = st.st_size
                    mtime = st.st_mtime
                except OSError:
                    continue
                # First time we see this file. If it was modified BEFORE
                # the dashboard started, it's pre-existing transcript
                # history we don't want to replay — skip to end. If it
                # appeared AFTER startup (real new agent session, OR a
                # file written in one shot we haven't seen yet), start
                # from offset 0 so we capture its content.
                if path not in file_offsets:
                    file_offsets[path] = 0 if mtime > startup_ts else size
                    # Snapshot the trace_id at file-discovery time. For
                    # post-startup files this is "right when the
                    # orchestrator that created the file is running",
                    # which is the right correlation moment.
                    file_trace_id[path] = _trace_for_session_path(path)
                    if file_offsets[path] == size:
                        continue
                # File shrank? Could be a rotation or rewrite. Reset.
                if size < file_offsets[path]:
                    file_offsets[path] = size
                    continue
                if size == file_offsets[path]:
                    continue
                # New content
                try:
                    with open(path, 'r') as f:
                        f.seek(file_offsets[path])
                        new_data = f.read()
                        file_offsets[path] = f.tell()
                except OSError:
                    continue
                for line in new_data.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rtype = rec.get('type', '')
                    msg = rec.get('message') or {}
                    role = msg.get('role', '')
                    content = msg.get('content')
                    ts = rec.get('timestamp', '')
                    # Convert text into a single string preview, ignoring
                    # tool_result + tool_use blocks (those aren't the
                    # natural-language content prompt_defense scans).
                    text_preview = None
                    event_type = None
                    if rtype == 'user' and role == 'user':
                        if isinstance(content, str):
                            text_preview = content
                            event_type = 'PROMPT'
                        elif isinstance(content, list):
                            # If any block is tool_result, this whole entry is
                            # a tool-result echo — not a real prompt. Skip.
                            if any(isinstance(b, dict) and b.get('type') == 'tool_result' for b in content):
                                continue
                            texts = [b.get('text', '') for b in content
                                     if isinstance(b, dict) and b.get('type') == 'text']
                            if texts:
                                text_preview = '\n'.join(texts)
                                event_type = 'PROMPT'
                    elif rtype == 'assistant' and role == 'assistant':
                        if isinstance(content, list):
                            texts = [b.get('text', '') for b in content
                                     if isinstance(b, dict) and b.get('type') == 'text']
                            if texts:
                                text_preview = '\n'.join(texts)
                                event_type = 'RESPONSE'
                    if not event_type or not text_preview:
                        continue
                    # _redact in append_event will catch GitHub tokens, JWTs,
                    # sk-ant-*, etc. Truncate first so we don't store
                    # multi-KB blobs in events.db.
                    text_preview = text_preview.strip()[:_TRANSCRIPT_PREVIEW_CHARS]
                    entry = {
                        'time': coerce_ms_iso(ts) or now_utc_iso(),
                        'type': event_type,
                        'uid': 965,
                        'binary': 'claude-code',
                        'args': text_preview,
                        'policy': '',
                        'is_agent': True,
                        'source': 'claude-transcript',
                        # If we resolved a trace_id for this file at
                        # discovery time, use it. Otherwise leave None
                        # and let append_event's active-trace fallback
                        # try (best-effort for calendar-triggered runs
                        # where there's no webhook to look up).
                        'trace_id': file_trace_id.get(path),
                    }
                    with lock:
                        append_event(entry)
        except Exception:
            pass
        time.sleep(3)

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
        # eslogger emits RFC3339 with nanoseconds (e.g.
        # 2025-05-07T21:23:45.123456789Z); coerce to millisecond precision.
        ts = coerce_ms_iso(event.get('time', ''))
        entry = {'time': ts, 'type': '', 'uid': '', 'binary': '', 'args': '', 'policy': '', 'is_agent': False, 'source': 'tetragon'}
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
<html><head><title>AetherClaude Defense-In-Depth Dashboard</title><meta charset="utf-8">
<style>
/* CiscoSans (Cisco's official brand typeface) — served from
   PRIVATE_FONTS_DIR (NOT in the git tree). Full family with seven
   weights × Roman+Oblique. Files: CiscoSansTT{Thin,ExtraLight,Light,
   Regular,Medium,Bold,Heavy}{,Oblique}.ttf. Apply by adding 'CiscoSans'
   to any element's font-family stack; weights resolve naturally
   (font-weight:300 → Light, 400 → Regular, 500 → Medium, 700 → Bold,
   etc.). Falls back to the existing system stack if the files aren't
   present. */
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTThin.ttf')              format('truetype'); font-weight: 100; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTThinOblique.ttf')       format('truetype'); font-weight: 100; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTExtraLight.ttf')        format('truetype'); font-weight: 200; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTExtraLightOblique.ttf') format('truetype'); font-weight: 200; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTLight.ttf')             format('truetype'); font-weight: 300; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTLightOblique.ttf')      format('truetype'); font-weight: 300; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTRegular.ttf')           format('truetype'); font-weight: 400; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTRegularOblique.ttf')    format('truetype'); font-weight: 400; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTMedium.ttf')            format('truetype'); font-weight: 500; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTMediumOblique.ttf')     format('truetype'); font-weight: 500; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTBold.ttf')              format('truetype'); font-weight: 700; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTBoldOblique.ttf')       format('truetype'); font-weight: 700; font-style: italic;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTHeavy.ttf')             format('truetype'); font-weight: 800; font-style: normal;  font-display: swap; }
@font-face { font-family: 'CiscoSans'; src: url('/fonts/CiscoSansTTHeavyOblique.ttf')      format('truetype'); font-weight: 800; font-style: italic;  font-display: swap; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a1a;color:#c8d8e8;font-family:'SF Mono','Fira Code',monospace;font-size:13px}
.header{background:#101028;padding:12px 24px;border-bottom:1px solid #203040;display:flex;justify-content:space-between;align-items:center}
.header h1{font-family:'CiscoSans','SF Mono',monospace;font-size:20px;color:#00b4d8;letter-spacing:1px;font-weight:400}
.header .sub{font-family:'CiscoSans',system-ui,sans-serif;color:#607080;font-size:11px}
.header .live{color:#00ff88;font-size:12px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.rings{display:grid;grid-template-columns:repeat(9,1fr);gap:8px;padding:12px 24px}
.ring{background:#101028;border:1px solid #203040;border-radius:8px;padding:10px;text-align:center;position:relative}
.ring .num{font-size:10px;color:#404060;position:absolute;top:4px;left:8px}
.ring .name{font-family:'CiscoSans',system-ui,sans-serif;font-size:10px;font-weight:500;color:#8090a0;margin-bottom:4px}
.ring .value{font-family:'CiscoSans',system-ui,sans-serif;font-size:26px;font-weight:300;color:#00b4d8;letter-spacing:0}
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
.phdr{font-family:'CiscoSans',system-ui,sans-serif;padding:6px 10px;background:#181830;border-bottom:1px solid #203040;font-size:11px;color:#00b4d8;font-weight:600;letter-spacing:0.3px;display:flex;justify-content:space-between}
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
.ev.defenseclaw{background:#0c0c20;border-left:3px solid #6688ff}
.stag.defenseclaw{background:#181830;color:#6688ff}
.tp.DEFENSE{color:#6688ff}
.stag.skill-dispatch{background:#202010;color:#ffdd44}
.ev.claude-code{background:#180818;border-left:3px solid #ff88cc}
.stag.claude-code{background:#201020;color:#ff88cc}
.stag.tinyproxy{background:#103020;color:#44ddaa}
.ev .uid{width:40px;color:#888}
.ev .bin{width:150px;color:#e0e0e0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .args{flex:1;color:#888;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .pol{color:#ffaa00;font-size:10px}
.ev .tm{width:96px;color:#505060;font-size:10px}
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
.modal h2{font-family:'CiscoSans',system-ui,sans-serif;color:#00b4d8;margin-bottom:12px;font-size:17px;letter-spacing:0.5px;font-weight:500}
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
.wp-content h2{font-family:'CiscoSans',system-ui,sans-serif;color:#00b4d8;font-size:17px;font-weight:600;margin:20px 0 8px;border-bottom:1px solid #203040;padding-bottom:4px}
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
<div style="flex:1"><h1>AetherClaude Defense-In-Depth Dashboard</h1>
<div class="sub">Cisco Isovalent (Tetragon) &middot; Cisco DefenseClaw CodeGuard &middot; Cisco AI Defense &middot; MCP Token Isolation</div></div>
<!-- Button stack: two rows of children inside the same header.
     Top row = primary nav + LIVE indicator. Bottom row = the wider
     Whitepaper link, right-aligned under the others so the title row
     keeps its full flex budget. -->
<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
  <div style="display:flex;align-items:center;gap:8px">
    <a href="#" onclick="showConstitution();return false" style="color:#bb88ff;font-size:11px;text-decoration:none;border:1px solid #443060;padding:4px 10px;border-radius:6px;white-space:nowrap" onmouseover="this.style.color='#ccaaff';this.style.borderColor='#ccaaff'" onmouseout="this.style.color='#bb88ff';this.style.borderColor='#443060'">Constitution &harr; Rings</a>
    <a href="/agent-walk" target="_blank" style="color:#00ff88;font-size:11px;text-decoration:none;border:1px solid #205040;padding:4px 10px;border-radius:6px;white-space:nowrap" onmouseover="this.style.color='#88ffaa';this.style.borderColor='#88ffaa'" onmouseout="this.style.color='#00ff88';this.style.borderColor='#205040'">Agent Walk &#x2197;</a>
    <a href="#" onclick="openOperatorTui();return false" style="color:#6688ff;font-size:11px;text-decoration:none;border:1px solid #303860;padding:4px 10px;border-radius:6px;white-space:nowrap" onmouseover="this.style.color='#88aaff';this.style.borderColor='#88aaff'" onmouseout="this.style.color='#6688ff';this.style.borderColor='#303860'">Operator TUI &#x2197;</a>
    <div class="live" id="agent-status">&#9679; LIVE</div>
  </div>
  <a href="#" onclick="showWhitepaper();return false" style="color:#607080;font-size:11px;text-decoration:none;border:1px solid #304050;padding:4px 10px;border-radius:6px;white-space:nowrap" onmouseover="this.style.color='#00b4d8';this.style.borderColor='#00b4d8'" onmouseout="this.style.color='#607080';this.style.borderColor='#304050'">Agent Defense-in-Depth Whitepaper</a>
</div>
</div>

<div class="rings">
<div class="ring ok clickable" id="ring1" onclick="showRingEvents('nftables','Ring 1: Firewall','Kernel-level packet filtering by UID — blocked outbound connections')"><span class="num">1 &gt;</span><span class="status green"></span>
<div class="name">Firewall</div><div class="value" id="r1v">0</div><div class="detail">packets blocked</div></div>

<div class="ring ok clickable" id="ring2" onclick="showRingEvents('tinyproxy','Ring 2: Web Proxy — denied connections','Last 100 HTTPS connections rejected by the domain allowlist (allowed connections omitted)',{policy:'domain-filter'})"><span class="num">2 &gt;</span><span class="status green"></span>
<div class="name">Web Proxy</div><div class="value" id="r2v">0</div><div class="detail" id="r2d">allowed · 0 denied</div></div>

<div class="ring ok clickable" id="ring3" onclick="showRingEvents('eslogger','Ring 3: OS Isolation (Tetragon eBPF)','Last 100 process executions under UID 965 — what the agent has been running',{type:'EXEC'})"><span class="num">3 &gt;</span><span class="status green"></span>
<div class="name">OS Isolation</div><div class="value" id="r3v">0</div><div class="detail" id="r3d">agent cmds · rbash</div></div>

<div class="ring ok clickable" id="ring4" onclick="showRing4()"><span class="num">4 &gt;</span><span class="status green"></span>
<div class="name">Agent Sandbox</div><div class="value" id="r4v">0</div><div class="detail" id="r4d">sandboxed runs</div></div>

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
<button class="fbtn active" data-types="" onclick="toggleFilter(this)">All</button>
<button class="fbtn" data-preset="agent" onclick="toggleFilter(this)">Agent</button>
<button class="fbtn" data-types="EXEC,FORK,EXIT,SIGNAL" onclick="toggleFilter(this)">Tetragon</button>
<button class="fbtn" data-types="RENAME,UNLINK" onclick="toggleFilter(this)">Files</button>
<button class="fbtn" data-types="BLOCK" style="border-color:#ff4444" onclick="toggleFilter(this)">Firewall</button>
<button class="fbtn" data-types="PROXY" style="border-color:#44ddaa" onclick="toggleFilter(this)">Proxy</button>
<button class="fbtn" data-types="SCAN" style="border-color:#00ddff" onclick="toggleFilter(this)">Scan</button>
<button class="fbtn" data-types="GUARD" style="border-color:#ff6688" onclick="toggleFilter(this)">CodeGuard</button>
<button class="fbtn" data-types="TOOL" style="border-color:#ff88cc" onclick="toggleFilter(this)">Claude</button>
<button class="fbtn" data-types="MCP" style="border-color:#aa88ff" onclick="toggleFilter(this)">MCP</button>
<button class="fbtn" data-types="SKILL" style="border-color:#ffdd44" onclick="toggleFilter(this)">Skills</button>
<button class="fbtn" data-types="WEBHOOK" style="border-color:#44aaff" onclick="toggleFilter(this)">Webhook</button>
<button class="fbtn" data-types="DEFENSE" style="border-color:#6688ff" onclick="toggleFilter(this)">AI-Defense</button>
<label style="margin-left:8px">Search:</label>
<input class="finput" id="search" placeholder="grep pattern..." oninput="debouncedRefresh()" style="width:250px">
</div>

<div class="main">
<div class="panel">
<div class="phdr"><span><span style="margin-right:16px">Event Stream &middot;</span><span style="margin-right:4px"><span style="color:#00ff88">&#9632;</span> Agent</span> <span style="margin-right:4px"><span style="color:#ff4444">&#9632;</span> Firewall</span> <span style="margin-right:4px"><span style="color:#44ddaa">&#9632;</span> Proxy</span> <span style="margin-right:4px"><span style="color:#ff6688">&#9632;</span> CodeGuard</span> <span style="margin-right:4px"><span style="color:#aa88ff">&#9632;</span> MCP</span> <span style="margin-right:4px"><span style="color:#00ddff">&#9632;</span> Scanners</span> <span style="margin-right:4px"><span style="color:#ffdd44">&#9632;</span> Skills</span> <span><span style="color:#ff88cc">&#9632;</span> Claude</span></span><span class="muted" id="sup"></span></div>
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
// Server emits all event timestamps as ISO-8601 UTC with Z and millisecond
// precision. Render in local wall-clock time as HH:MM:SS.mmm — toLocale-
// TimeString doesn't expose millis, so we append them from getMilliseconds().
function fmtTime(s){
  if(!s) return '';
  const dt=new Date(s);
  if(isNaN(dt.getTime())) return s.substring(11,23);
  const hms=dt.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const ms=String(dt.getMilliseconds()).padStart(3,'0');
  return `${hms}.${ms}`;
}
// Multi-select filter: clicking a button toggles its active state. "All" is
// implicit — it lights up only when no other buttons are active. Multiple
// buttons combine OR-style; the search box is additive (AND) on top.
function toggleFilter(btn){
const all=document.querySelector('.filter-bar .fbtn[data-types=""]');
if(btn===all){
  document.querySelectorAll('.filter-bar .fbtn').forEach(b=>b.classList.remove('active'));
  all.classList.add('active');
}else if(btn.dataset.preset==='agent'){
  const presetTypes=new Set(['BLOCK','SCAN','GUARD','TOOL','MCP','SKILL','WEBHOOK','DEFENSE']);
  document.querySelectorAll('.filter-bar .fbtn').forEach(b=>{
    if(presetTypes.has(b.dataset.types))b.classList.add('active');
    else b.classList.remove('active');
  });
}else{
  all.classList.remove('active');
  btn.classList.toggle('active');
  if(document.querySelectorAll('.filter-bar .fbtn.active').length===0)all.classList.add('active');
}
refresh();
}
function renderEvents(events,total,filtered){
let h='';
for(const e of events){
let t='';
t=fmtTime(e.time);
let c='ev';if(e.source==='skill-dispatch')c='ev skill-dispatch';else if(e.source==='claude-code')c='ev claude-code';else if(e.source==='nftables')c='ev nftables';else if(e.source==='mcp-scan')c='ev mcp-scan';else if(e.source==='skill-scan')c='ev skill-scan';else if(e.source==='tinyproxy')c='ev tinyproxy';else if(e.source==='codeguard')c='ev guard';else if(e.source==='mcp')c='ev mcp';else if(e.source==='webhook')c='ev webhook';else if(e.source==='defenseclaw')c='ev defenseclaw';else if(e.is_agent)c='ev agent';
const p=e.policy?`<span class="pol">[${e.policy}]</span>`:'';
const st=e.source||'tetragon';
h+=`<div class="${c}"><span class="tm">${t}</span><span class="tp ${e.type}">${e.type}</span><span class="uid">${e.uid}</span><span class="bin">${e.binary.split('/').pop()}</span><span class="args">${esc(e.args)} ${p} <span class="stag ${st}">${st}</span></span></div>`}
document.getElementById('evts').innerHTML=h;
}
function refresh(){
const q=document.getElementById('search').value;
const types=new Set();
document.querySelectorAll('.filter-bar .fbtn.active').forEach(b=>{
  const t=b.dataset.types;
  if(t)t.split(',').forEach(x=>types.add(x));
});
const params=new URLSearchParams();
if(types.size)params.set('types',Array.from(types).join(','));
if(q)params.set('q',q);
const url='/api/events'+(params.toString()?'?'+params.toString():'');
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
cs+=`<div class="si clickable" onclick="showPromptScan()"><span class="n"><span class="stag codeguard">scan</span> Prompt Scanner</span><span class="c">${r.r6_prompts_scanned||0} prompts · ${r.r6_prompt_threats||0} threats · ${r.r6_prompt_advisory||0} advisory</span></div>`;
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
const t=fmtTime(a.time);
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
let ah='';for(const a of(s.alerts||[]).reverse())ah+=`<div class="ai ${a.severity}"><div class="msg">${esc(a.msg)}</div><div class="at">${fmtTime(a.time)}</div></div>`;
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
function showPromptScan(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">YARA threat-pattern detection + 12-vector prompt-defense hardening audit on AetherClaude skill templates</p>';
const threats=r.r6_prompt_threats||0;
const adv=r.r6_prompt_advisory||0;
h+=`<div class="modal-finding ${threats>0?'HIGH':'SAFE'}"><span class="sev ${threats>0?'HIGH':'SAFE'}">${threats>0?threats+' THREAT':'SAFE'}</span> ${r.r6_prompts_scanned||0} prompts scanned, ${threats} real threats</div>`;
if(adv>0)h+=`<div class="modal-finding MEDIUM"><span class="sev MEDIUM">${adv}</span> advisory hardening findings (12-vector audit, not threats)</div>`;
h+=`<div id="prompt-findings-list" style="margin-top:12px"><p style="color:#607080">Loading findings...</p></div>`;
document.getElementById('modal-title').textContent='Prompt Scanner Results';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/prompt-scan').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} findings persisted</p>`;
if(!d.findings || d.findings.length===0){fh+='<p style="color:#607080">No findings yet.</p>';document.getElementById('prompt-findings-list').innerHTML=fh;return}
// Group by prompt_name (most recent scan_time per prompt)
const byPrompt={};
for(const f of d.findings){
  if(!byPrompt[f.prompt_name])byPrompt[f.prompt_name]={threats:[],advisory:[]};
  if(f.is_advisory)byPrompt[f.prompt_name].advisory.push(f);
  else byPrompt[f.prompt_name].threats.push(f);
}
for(const name of Object.keys(byPrompt).sort()){
  const g=byPrompt[name];
  const headSev=g.threats.length>0?'HIGH':'SAFE';
  fh+=`<div class="modal-finding ${headSev}" style="margin-bottom:8px">`;
  fh+=`<span class="sev ${headSev}">${headSev}</span> <strong>${esc(name)}</strong>`;
  fh+=` <span style="color:#607080;font-size:10px;margin-left:6px">${g.threats.length} threats · ${g.advisory.length} advisory</span>`;
  for(const f of g.threats){
    fh+=`<div class="detail" style="margin-top:4px;color:#ff6688">⚠ ${esc(f.severity||'')} ${esc(f.technique_name||'')}: ${esc(f.summary||'')}</div>`;
  }
  for(const f of g.advisory){
    fh+=`<div class="detail" style="margin-top:2px;color:#888a98">${esc(f.severity||'')} · ${esc(f.summary||'')}</div>`;
  }
  fh+=`</div>`;
}
document.getElementById('prompt-findings-list').innerHTML=fh;
}).catch(()=>{document.getElementById('prompt-findings-list').innerHTML='<p style="color:#604040">Failed to load prompt scan data.</p>'})}
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
const vulns=lastData.rings?.r6_aibom_vulns||0;
const ver=lastData.rings?.r6_aibom_scanner_version||'1.0.0';
let h='<p style="color:#607080;margin-bottom:12px">C++ AI Bill of Materials — scans for neural networks, ML frameworks, and DSP libraries</p>';
h+=`<div class="modal-finding ${neural?'MEDIUM':'SAFE'}"><span class="sev ${neural?'MEDIUM':'SAFE'}">${neural?'NEURAL':'CLEAN'}</span> ${comps} AI/ML components detected</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">INFO</span> ${models} model files found</div>`;
if(vulns>0)h+=`<div class="modal-finding HIGH"><span class="sev HIGH">VULN</span> ${vulns} vulnerabilities found (OSV.dev)</div>`;
h+=`<div id="aibom-list" style="margin-top:12px"><p style="color:#607080">Loading component details...</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#607080">Scanner: cpp-aibom v${ver} (custom C++ AIBOM for Cisco AI Defense)</div>`;
document.getElementById('modal-title').textContent='C++ AI Bill of Materials';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/aibom').then(r=>r.json()).then(d=>{
let fh='';
if(d.total>0)fh+=`<p style="color:#607080;margin-bottom:8px">${d.total} components in database</p>`;
if(d.components.length===0)fh+='<p style="color:#607080">No components recorded yet.</p>';
const seen=new Set();
const catColors={'audio_ml':'MEDIUM','audio_codec':'SAFE','dsp':'SAFE','audio_dsp':'SAFE','audio_io':'SAFE','rpc':'SAFE'};
const vulnSev=(s)=>{s=(s||'').toUpperCase();return (s==='CRITICAL'||s==='HIGH')?'HIGH':(s==='MEDIUM')?'MEDIUM':(s==='LOW')?'LOW':'SAFE'};
for(const c of d.components){
if(seen.has(c.name))continue;seen.add(c.name);
const vs=c.vulnerabilities||[];
const cardSev=vs.length>0?'HIGH':(catColors[c.category]||'SAFE');
fh+=`<div class="modal-finding ${cardSev}" style="margin-bottom:6px">`;
fh+=`<span class="sev ${catColors[c.category]||'SAFE'}">${esc(c.category)}</span> <strong>${esc(c.name)}</strong>`;
if(vs.length>0)fh+=` <span class="sev HIGH" style="font-size:9px;padding:1px 4px;margin-left:4px">${vs.length} CVE${vs.length>1?'s':''}</span>`;
fh+=`<div class="detail" style="margin-top:2px">${esc(c.description)}</div>`;
fh+=`<div class="detail" style="margin-top:2px;color:#405060;font-size:10px">Detection: ${esc(c.detection)} — ${esc(c.evidence)}</div>`;
if(vs.length>0){
  fh+=`<div class="detail" style="margin-top:6px;color:#a0a8b0;font-size:10px;border-top:1px solid #2a3040;padding-top:4px">Vulnerabilities (OSV.dev):</div>`;
  for(const v of vs){
    const sc=vulnSev(v.severity);
    const sum=esc((v.summary||'').substring(0,120))||'(no summary)';
    const link=(v.references&&v.references[0])?` <a href="${esc(v.references[0])}" target="_blank" style="color:#00bceb;text-decoration:none">[advisory]</a>`:'';
    fh+=`<div class="detail" style="margin-left:6px;margin-top:3px;font-size:10px;color:#a0a8b0;line-height:1.4"><span class="sev ${sc}" style="font-size:9px;padding:1px 5px">${esc(v.severity||'UNKNOWN')}</span> <code style="color:#7080a0">${esc(v.id||'')}</code>${link} — ${sum}</div>`;
  }
}
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
function showRingEvents(source,title,desc,extra){
extra=extra||{};
let h=`<p style="color:#607080;margin-bottom:12px">${desc}</p>`;
h+=`<div id="ring-events-list"><p style="color:#607080">Loading events...</p></div>`;
document.getElementById('modal-title').textContent=title;
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
// Query the persistent events.db (not the in-memory ring buffer, which
// empties on dashboard restart). Last 100 rows per source, newest first.
// Optional `extra` adds policy/type filters (e.g. ring 2 passes
// {policy:'domain-filter'} to keep only tinyproxy denials).
let url='/api/ring-events?source='+encodeURIComponent(source)+'&limit=100';
if(extra.policy)url+='&policy='+encodeURIComponent(extra.policy);
if(extra.type)url+='&type='+encodeURIComponent(extra.type);
fetch(url).then(r=>r.json()).then(d=>{
const shown=d.events.length, total=d.total||0;
let fh=`<div class="modal-finding SAFE"><span class="sev SAFE">EVENTS</span> Showing ${shown} of ${total} persisted events</div>`;
if(shown===0){
fh+='<p style="color:#607080;margin-top:12px">No events recorded yet for this source. The ring counter aggregates a periodic poll; individual events appear here once ingested into events.db.</p>';
}else{
fh+='<div style="margin-top:12px;max-height:50vh;overflow-y:auto;font-family:monospace;font-size:11px">';
for(const e of d.events){
const isAlert=e.policy&&e.policy.length>0;
const cls=isAlert?'HIGH':'SAFE';
// Truncate args at 200 chars and collapse whitespace — EXEC args often
// embed multi-line Python heredocs that would blow out the modal.
let args=(e.args||'').replace(/\s+/g,' ').trim();
if(args.length>200)args=args.slice(0,200)+'…';
// Pull just the basename of binary for compact display.
const bin=e.binary?(e.binary.split('/').pop()||e.binary):'';
fh+=`<div class="modal-finding ${cls}" style="margin-bottom:2px;padding:4px 8px">`;
fh+=`<span style="color:#607080;margin-right:8px">${fmtTime(e.time||'')}</span>`;
if(e.type)fh+=`<span style="color:#ffaa00;margin-right:6px;font-weight:bold">${esc(e.type)}</span>`;
if(bin)fh+=`<span style="color:#80c0ff;margin-right:6px">${esc(bin)}</span>`;
fh+=`${esc(args)}`;
if(e.policy)fh+=` <span style="color:#ff6688;font-size:10px">[${esc(e.policy)}]</span>`;
fh+=`</div>`}
fh+='</div>';}
document.getElementById('ring-events-list').innerHTML=fh;
}).catch(()=>{document.getElementById('ring-events-list').innerHTML='<p style="color:#604040">Failed to load events.</p>'})}
function showRing4(){
const r=lastData.rings||{};
let h='<p style="color:#607080;margin-bottom:12px">Each agent run executes inside a UID-965 process tree managed by launchd. NoNewPrivileges, sandboxed PATH, restricted file access.</p>';
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">RUNS</span> ${r.r4_sandboxed_runs||0} sandboxed agent runs completed</div>`;
h+=`<div id="ring4-traces" style="margin-top:12px"><p style="color:#607080">Loading recent runs...</p></div>`;
document.getElementById('modal-title').textContent='Ring 4: Agent Sandbox';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
// Each /api/agent-walk-traces row is one webhook-triggered sandboxed
// run (one orchestrator invocation under UID 965). Render the last 20,
// clickable to jump to the trace's agent-walk timeline.
fetch('/api/agent-walk-traces?limit=20').then(r=>r.json()).then(d=>{
const traces=d.traces||[];
let fh=`<div class="detail" style="color:#a0a8b0;font-size:11px;margin-bottom:6px">Last ${traces.length} sandboxed runs (click to inspect the trace timeline):</div>`;
if(traces.length===0){
fh+='<p style="color:#607080">No traces recorded yet.</p>';
}else{
fh+='<div style="max-height:50vh;overflow-y:auto;font-family:monospace;font-size:11px">';
for(const t of traces){
// Compute duration
const start=t.first_ts?new Date(t.first_ts):null;
const end=t.last_ts?new Date(t.last_ts):null;
let dur='';
if(start&&end){const ms=end-start; const m=Math.floor(ms/60000); const s=Math.floor((ms%60000)/1000); dur=m>0?`${m}m${s}s`:`${s}s`;}
const evType=(t.binary||'').replace('github:','');
const startStr=start?start.toISOString().substr(11,8):'';
const summary=t.summary||'(no summary)';
fh+=`<div class="modal-finding SAFE clickable" style="margin-bottom:2px;padding:4px 8px;cursor:pointer" onclick="window.open('/agent-walk?trace='+encodeURIComponent('${t.trace_id}'),'_blank')">`;
fh+=`<span style="color:#607080;margin-right:8px">${esc(startStr)}</span>`;
if(dur)fh+=`<span style="color:#80ffaa;margin-right:6px">(${dur})</span>`;
fh+=`<span style="color:#ffaa00;margin-right:6px">${(t.event_count||0).toLocaleString()} ev</span>`;
if(evType)fh+=`<span style="color:#80c0ff;margin-right:6px">${esc(evType)}</span>`;
fh+=`<span>${esc(summary).substring(0,80)}</span>`;
fh+='</div>';}
fh+='</div>';}
// Brief sandboxing config (compressed from the prior static dump)
fh+='<div class="detail" style="margin-top:12px;color:#607080;font-size:10px">';
fh+='Sandboxing: NoNewPrivileges, ProtectSystem=strict, PrivateTmp, restricted PATH. ';
fh+='Writable: <code>workspace</code> <code>logs</code> <code>state</code> <code>skills</code> <code>.claude</code> <code>/tmp</code>.';
fh+='</div>';
if(r.r4_timer_since)fh+=`<div class="detail" style="margin-top:4px;color:#607080;font-size:10px">Timer active since: ${esc(r.r4_timer_since)}</div>`;
document.getElementById('ring4-traces').innerHTML=fh;
}).catch(()=>{document.getElementById('ring4-traces').innerHTML='<p style="color:#604040">Failed to load recent runs.</p>'})}
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
const ts=fmtTime(i.last_seen);
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
function showConstitution(){
const principles=[
{n:'I',t:'Evidence Over Assertion',s:'PARTIAL',a:'validate-diff + CodeGuard gate; post-triage citation health check footnotes unresolved path:line claims'},
{n:'II',t:'Surface Only What Survives',s:'STRONG',a:'zero-effort auto-close, 7-day stale-close, one-comment-per-triage, label-gated promotion to maintainer review'},
{n:'III',t:'Liveness By Heartbeat, Never By Clock',s:'STRONG',a:'session-JSONL mtime heartbeat (CLAUDE_MAX_IDLE=180s); CLAUDE_HARD_CEILING=3600s is the only wall-clock bound'},
{n:'IV',t:'Claims Are Atomic And Mortal',s:'STRONG',a:'per-issue lockfiles + issue-actions.db ledger with mortal run_id'},
{n:'V',t:'The Provider Is The Rate Arbiter',s:'STRONG',a:'webhook-paced cadence + adaptive auto-retry on Anthropic backpressure'},
{n:'VI',t:'Coverage Before Yield',s:'N/A',a:'event-driven; no termination decision to make'},
{n:'VII',t:'Exploited Means Demonstrated',s:'MEDIUM',a:'validate-diff runs independently of Claude; human review on every merge'},
{n:'VIII',t:'Fingerprints Are Stable Under Edit',s:'N/A',a:'no finding domain (GitHub issue # is the stable identifier)'},
{n:'IX',t:'Sandbox By Infrastructure, Not By Prompt',s:'STRONG',a:'pf + tinyproxy + launchd UID-965 + Claude permission system'},
{n:'X',t:'The Operator Outranks Every Agent',s:'STRONG',a:'aetherclaude-eligible label is maintainer-only; Override A/B/C gates'},
{n:'XI',t:'Persist Atomically',s:'STRONG',a:'SQLite ACID + temp-then-rename for every JSON artifact'},
];
let h='<p style="color:#607080;margin-bottom:12px">11 inviolable principles from <a href="https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md" target="_blank" style="color:#00b4d8">CiscoDevNet/foundry-security-spec</a> mapped to AetherClaude rings and files. Strong&times;7, Partial&times;2, N/A&times;2 (domain mismatch).</p>';
for(const p of principles){
const cls=p.s==='STRONG'?'SAFE':(p.s==='MEDIUM'||p.s==='PARTIAL')?'MEDIUM':'SAFE';
const chipColor=p.s==='STRONG'?'#80ffaa':(p.s==='PARTIAL'||p.s==='MEDIUM')?'#ffaa00':'#607080';
h+=`<div class="modal-finding ${cls}" style="margin-bottom:4px">`;
h+=`<span style="display:inline-block;min-width:54px;font-size:9px;padding:1px 5px;background:#1a2030;color:${chipColor};border:1px solid ${chipColor}40;border-radius:3px;text-align:center;margin-right:6px">${p.s}</span>`;
h+=`<span style="color:#a0a8b0;margin-right:6px;font-weight:bold">${p.n}.</span>`;
h+=`<strong>${p.t}</strong>`;
h+=`<div class="detail" style="margin-top:2px;color:#90a0b8;font-size:11px;margin-left:60px">${p.a}</div>`;
h+=`</div>`;}
h+='<div class="detail" style="margin-top:12px;color:#607080;font-size:10px">Full mapping with source-file links: <a href="https://github.com/ten9876/aetherclaude/blob/main/docs/constitution-mapping.md" target="_blank" style="color:#00b4d8">docs/constitution-mapping.md</a>. Pinned at foundry-security-spec @ <code>c770bf77</code>.</div>';
document.getElementById('modal-title').textContent='Foundry Constitution ↔ AetherClaude Mapping';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
}
function closeWp(){document.getElementById('wp-modal').classList.remove('show')}
// Pick the right TUI URL based on how the dashboard itself was reached:
// when accessed via the cloudflared tunnel the dashboard is on HTTPS but
// :7681 isn't tunneled at the same hostname, so route to a sibling
// tui.<domain> route. On LAN the TUI is just the same hostname on :7681.
function openOperatorTui(){
  const host=location.hostname;
  const url=host.endsWith('.aethersdr.com')
    ? 'https://tui.aethersdr.com/'
    : `${location.protocol}//${host}:7681/`;
  window.open(url,'_blank');
}
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

CODEGRAPH_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AetherSDR Codegraph</title>
<style>
  html, body { margin:0; padding:0; height:100%; background:#0a0a1a; color:#d0d8e0; font-family:'SF Pro Text', system-ui, sans-serif; }
  header { position:fixed; top:0; left:0; right:0; height:48px; background:#101020; border-bottom:1px solid #203050; display:flex; align-items:center; padding:0 16px; gap:16px; z-index:10; }
  header h1 { margin:0; font-size:14px; font-weight:600; color:#00bceb; letter-spacing:0.5px; text-transform:uppercase; }
  header a.back { color:#607080; text-decoration:none; font-size:11px; border:1px solid #203050; padding:4px 10px; border-radius:4px; }
  header a.back:hover { color:#00bceb; border-color:#00bceb; }
  .controls { display:flex; align-items:center; gap:14px; font-size:11px; color:#809090; }
  .controls label { display:flex; align-items:center; gap:6px; }
  .controls input[type=range] { width:120px; }
  .controls input[type=text] { background:#0a0a1a; color:#d0d8e0; border:1px solid #203050; padding:3px 8px; border-radius:3px; width:200px; font-family:inherit; font-size:11px; }
  #stats { color:#607080; font-size:11px; margin-left:auto; }
  #sigma-container { position:fixed; top:48px; left:0; right:320px; bottom:0; background:#08081a; }
  aside#side { position:fixed; top:48px; right:0; bottom:0; width:320px; background:#0f0f22; border-left:1px solid #203050; overflow-y:auto; padding:16px; box-sizing:border-box; font-size:11px; }
  aside h3 { color:#00bceb; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; margin:18px 0 8px 0; border-bottom:1px solid #203050; padding-bottom:4px; }
  aside h3:first-child { margin-top:0; }
  .field { display:flex; gap:6px; margin:4px 0; }
  .field .k { color:#607080; min-width:80px; }
  .field .v { color:#d0d8e0; word-break:break-all; font-family:'SF Mono', monospace; font-size:10px; }
  .neighbor { padding:3px 6px; margin:2px 0; border:1px solid #203050; border-radius:3px; cursor:pointer; font-family:'SF Mono', monospace; font-size:10px; color:#a0b0c0; }
  .neighbor:hover { border-color:#00bceb; color:#00bceb; }
  .community-row { display:flex; justify-content:space-between; padding:3px 6px; cursor:pointer; border-radius:3px; }
  .community-row:hover { background:#1a1a2a; }
  .community-swatch { display:inline-block; width:10px; height:10px; border-radius:50%; vertical-align:middle; margin-right:6px; }
  #empty-state { padding:20px; text-align:center; color:#607080; font-size:12px; line-height:1.6; }
  .loading-spinner { display:inline-block; width:12px; height:12px; border:2px solid #203050; border-top-color:#00bceb; border-radius:50%; animation:spin 0.8s linear infinite; vertical-align:middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
  /* Phase-3 live overlay. The .live-dot pulses while the SSE stream
   * is connected. Per-trace rows list the active claude runs and the
   * file they last touched. */
  #live-status { display:flex; align-items:center; gap:6px; color:#607080; font-size:11px; }
  .live-dot { width:8px; height:8px; border-radius:50%; background:#404050; display:inline-block; }
  .live-dot.on { background:#00ff88; box-shadow:0 0 6px #00ff88; animation:livepulse 1.5s ease-in-out infinite; }
  @keyframes livepulse { 0%,100% { opacity:1; } 50% { opacity:0.35; } }
  .trace-row { display:flex; align-items:center; gap:6px; padding:3px 6px; font-family:'SF Mono', monospace; font-size:10px; color:#a0b0c0; }
  .trace-swatch { width:8px; height:8px; border-radius:50%; flex:0 0 8px; }
  .trace-row .tfile { color:#809090; flex:1; text-overflow:ellipsis; overflow:hidden; white-space:nowrap; }
  .trace-row .tact { color:#607080; }
  /* Refactor watch-list — high-betweenness symbols. Click jumps the
   * camera to the node and selects it in the detail panel. */
  .bridge-row { display:flex; align-items:baseline; gap:6px; padding:3px 6px; font-family:'SF Mono', monospace; font-size:10px; cursor:pointer; border-radius:3px; border-left:2px solid transparent; }
  .bridge-row:hover { background:#1a1a2a; border-left-color:#00bceb; }
  .bridge-row .bname { color:#d0d8e0; flex:1; text-overflow:ellipsis; overflow:hidden; white-space:nowrap; }
  .bridge-row .bscope { color:#607080; }
  .bridge-row .bscore { color:#ffaa00; min-width:46px; text-align:right; }
</style>
</head>
<body>
<header>
  <h1>AetherSDR Codegraph</h1>
  <a class="back" href="/">&larr; Dashboard</a>
  <div class="controls">
    <label>min degree: <input type="range" id="min-degree" min="0" max="50" value="5"><span id="min-degree-val">5</span></label>
    <label>search: <input type="text" id="search" placeholder="symbol name..."></label>
  </div>
  <span id="stats"><span class="loading-spinner"></span> loading...</span>
</header>
<div id="sigma-container"></div>
<aside id="side">
  <h3>Node detail</h3>
  <div id="node-info"><div id="empty-state">Click a node to inspect.<br>Drag to pan, scroll to zoom.</div></div>
  <h3>Live activity <span id="live-status"><span class="live-dot" id="live-dot"></span><span id="live-text">offline</span></span></h3>
  <div id="trace-list"><div id="empty-state" style="padding:8px 0">Idle. Symbol pulses appear here when claude runs touch the codebase.</div></div>
  <h3>Refactor watch-list <span style="color:#607080;font-weight:normal">(high betweenness)</span></h3>
  <div id="bridge-list">—</div>
  <h3>Top communities</h3>
  <div id="community-list">—</div>
  <h3>Metadata</h3>
  <div id="meta">—</div>
</aside>

<script src="/codegraph/assets/graphology.umd.min.js"></script>
<script src="/codegraph/assets/graphology-library.min.js"></script>
<script src="/codegraph/assets/sigma.min.js"></script>
<script>
'use strict';

// Sigma.js WebGL node program parses hex/rgb, NOT hsl(). Convert.
function hslToHex(h, s, l) {
  s /= 100; l /= 100;
  const k = n => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = n => l - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1));
  const toHex = x => Math.round(255 * x).toString(16).padStart(2, '0');
  return `#${toHex(f(0))}${toHex(f(8))}${toHex(f(4))}`;
}

// Add alpha to a #rrggbb color — used for edge tinting so edges
// pick up the source community color but at reduced opacity, so
// they sit behind the nodes visually instead of competing.
function hexWithAlpha(hex, alpha) {
  if (!hex || hex[0] !== '#' || hex.length < 7) return hex;
  const a = Math.round(alpha * 255).toString(16).padStart(2, '0');
  return hex.slice(0, 7) + a;
}

// Deterministic color-per-community via HSL hash → hex.
function communityColor(cid) {
  const h = ((cid * 137) % 360 + 360) % 360;
  return hslToHex(h, 65, 60);
}

const _state = {
  sigma: null,
  graph: null,
  minDegree: 5,
  rawNodes: [],
  rawEdges: [],
  meta: {},
  highlightedId: null,
  searchMatches: new Set(),  // node IDs matching the current search query
};

function setStats(text) { document.getElementById('stats').textContent = text; }

async function fetchData(minDegree) {
  const r = await fetch('/api/codegraph/data?min_degree=' + minDegree);
  if (!r.ok) throw new Error('fetch failed: ' + r.status);
  return r.json();
}

async function fetchMeta() {
  const r = await fetch('/api/codegraph/meta');
  if (!r.ok) return {};
  return r.json();
}

async function fetchBridges(limit) {
  const r = await fetch('/api/codegraph/bridges?limit=' + (limit || 20));
  if (!r.ok) return [];
  return r.json();
}

function renderBridgeList(bridges) {
  const el = document.getElementById('bridge-list');
  if (!el) return;
  if (!bridges.length) {
    el.innerHTML = '<div id="empty-state" style="padding:8px 0">No betweenness data — re-run codegraph-analyze.py.</div>';
    return;
  }
  const maxScore = bridges[0].betweenness || 1;
  el.innerHTML = bridges.map(b => {
    const pct = ((b.betweenness / maxScore) * 100).toFixed(0);
    const score = (b.betweenness * 1000).toFixed(2);
    return `<div class="bridge-row" data-node="${b.id}" title="${escapeHtml(b.qualified_name)} · ${escapeHtml(b.file)}:${b.line} · degree ${b.degree}">
      <span class="bscore">${score}</span>
      <span class="bname">${escapeHtml(b.name)}</span>
      <span class="bscope">${escapeHtml(b.community_label || '')}</span>
    </div>`;
  }).join('');
  // Click → jump to node + select. Only works if the node is in the
  // current graph (some bridge nodes may be filtered out by min-degree).
  el.querySelectorAll('.bridge-row').forEach(row => {
    row.addEventListener('click', () => {
      const nid = row.dataset.node;
      if (!_state.graph || !_state.graph.hasNode(nid)) return;
      _state.sigma.getCamera().animate(
        { x: _state.graph.getNodeAttribute(nid, 'x'),
          y: _state.graph.getNodeAttribute(nid, 'y'),
          ratio: 0.15 },
        { duration: 400 }
      );
      selectNode(nid);
    });
  });
}

function rebuildGraph(data) {
  if (_state.sigma) { _state.sigma.kill(); _state.sigma = null; }
  // The old graph and its node IDs are gone — drop any active pulses so
  // stale origColor/origSize references don't bleed into the new graph.
  if (typeof _live !== 'undefined') { _live.pulses.clear(); }
  const g = new graphology.Graph({ type: 'undirected', multi: false });
  for (const n of data.nodes) {
    g.addNode(n.id, {
      label: n.label,
      kind: n.kind,
      file: n.file,
      line: n.line,
      community: n.community,
      community_label: n.community_label,
      degree: n.degree,
      x: (Math.random() - 0.5) * 1000,
      y: (Math.random() - 0.5) * 1000,
      // Tiny dots — match Martin's reference: most nodes 1-2 px,
      // hubs ~3 px. The structure comes from edge density, not size.
      size: Math.max(1, Math.min(3, Math.log2(n.degree + 1) * 0.5)),
      color: communityColor(n.community || 0),
    });
  }
  // Edges inherit a desaturated form of the source node's community
  // color — same approach as the reference viz. Visually you see the
  // cluster colour bleed along its internal edges, while inter-cluster
  // edges get a mixed look. Plain monochrome edges hide the structure.
  for (const e of data.edges) {
    if (g.hasNode(e.source) && g.hasNode(e.target) && !g.hasEdge(e.source, e.target)) {
      const srcColor = g.getNodeAttribute(e.source, 'color');
      g.addEdge(e.source, e.target, {
        kind: e.kind,
        size: 0.2,
        color: hexWithAlpha(srcColor, 0.18),
      });
    }
  }
  _state.graph = g;
  _state.rawNodes = data.nodes;
  _state.rawEdges = data.edges;

  setStats(`${g.order} nodes · ${g.size} edges · running layout…`);

  // Layout: classic ForceAtlas2 (no linLog, no strongGravity) with
  // very high scalingRatio so communities push hard against each
  // other and end up as visually distinct regions, then a noverlap
  // pass so individual nodes within a cluster don't sit on top of
  // each other. Matches the reference viz's "exploded archipelago"
  // shape rather than the dense ball linLog produces.
  const layoutFa2 = graphologyLibrary.layoutForceAtlas2;
  const t0 = performance.now();
  layoutFa2.assign(g, {
    iterations: 600,
    settings: {
      barnesHutOptimize: true,
      gravity: 1,
      scalingRatio: 50,
      slowDown: 10,
      strongGravityMode: false,
      linLogMode: false,
    },
  });
  if (graphologyLibrary.layoutNoverlap) {
    graphologyLibrary.layoutNoverlap.assign(g, {
      maxIterations: 100,
      settings: { ratio: 3, margin: 2, expansion: 1.1, speed: 3 },
    });
  }
  const layoutMs = performance.now() - t0;

  const container = document.getElementById('sigma-container');
  _state.sigma = new Sigma(g, container, {
    renderEdgeLabels: false,
    // Labels off by default — only show on selection / hover / search.
    // Reference viz hides all labels at this zoom level too.
    renderLabels: false,
    // Sigma renders highlighted-node labels on a near-white pill —
    // pale text on a pale background was unreadable. Dark text + a
    // tighter font weight gives strong contrast against the pill
    // while keeping the cyan selection ring readable.
    labelColor: { color: '#0a0a1a' },
    labelFont: 'SF Mono, monospace',
    labelSize: 11,
    labelWeight: '600',
    minCameraRatio: 0.05,
    maxCameraRatio: 10,
    // Selection emphasis: when a node is selected via click,
    // highlight it and its neighbors + their edges; dim the rest.
    nodeReducer: (node, data) => {
      const g = _state.graph;
      if (!g) return data;
      // Search mode takes precedence: matches get a label + size
      // boost, non-matches dim. This is the only feedback the search
      // gives in renderLabels=false mode.
      if (_state.searchMatches.size > 0) {
        if (_state.searchMatches.has(node)) {
          return { ...data, size: (data.size || 2) * 2.5, label: data.label, forceLabel: true, zIndex: 2 };
        }
        return { ...data, color: '#1a2030', label: '', zIndex: 0 };
      }
      const sel = _state.highlightedId;
      if (!sel) return data;
      const isSel = (node === sel);
      const isNeighbor = g.hasEdge(sel, node) || g.hasEdge(node, sel);
      if (isSel) return { ...data, size: (data.size || 2) * 2.2, label: data.label, forceLabel: true, zIndex: 2 };
      if (isNeighbor) return { ...data, label: data.label, forceLabel: true, zIndex: 1 };
      return { ...data, color: '#1a2030', label: '', zIndex: 0 };
    },
    edgeReducer: (edge, data) => {
      const g = _state.graph;
      if (!g) return data;
      // Hide edges in search mode — fewer visual distractions.
      if (_state.searchMatches.size > 0) {
        const ext = g.extremities(edge);
        const both = _state.searchMatches.has(ext[0]) && _state.searchMatches.has(ext[1]);
        if (!both) return { ...data, hidden: true };
        return { ...data, color: '#00bceb', size: 0.8, zIndex: 1 };
      }
      const sel = _state.highlightedId;
      if (!sel) return data;
      const ext = g.extremities(edge);
      const touches = (ext[0] === sel || ext[1] === sel);
      if (touches) return { ...data, color: '#00bceb', size: 0.8, zIndex: 1 };
      return { ...data, hidden: true };
    },
  });
  _state.sigma.on('clickNode', e => selectNode(e.node));
  _state.sigma.on('clickStage', () => selectNode(null));

  setStats(`${g.order} nodes · ${g.size} edges · layout in ${(layoutMs/1000).toFixed(1)}s`);

  // Build community list
  renderCommunityList();
}

function renderCommunityList() {
  const counts = {};
  const labels = {};
  for (const n of _state.rawNodes) {
    const c = n.community || 0;
    counts[c] = (counts[c] || 0) + 1;
    labels[c] = n.community_label || ('cid:'+c);
  }
  const sorted = Object.keys(counts).map(c => [c, counts[c], labels[c]]).sort((a,b) => b[1]-a[1]).slice(0, 20);
  const el = document.getElementById('community-list');
  el.innerHTML = sorted.map(([cid, n, label]) =>
    `<div class="community-row" data-cid="${cid}"><span><span class="community-swatch" style="background:${communityColor(parseInt(cid,10))}"></span>${escapeHtml(label)}</span><span>${n}</span></div>`
  ).join('');
  el.querySelectorAll('.community-row').forEach(row => {
    row.addEventListener('click', () => highlightCommunity(parseInt(row.dataset.cid, 10)));
  });
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function selectNode(nodeId) {
  _state.highlightedId = nodeId;
  // Force sigma to re-evaluate node/edge reducers (which read
  // _state.highlightedId) so neighbor highlighting paints immediately.
  if (_state.sigma) _state.sigma.refresh();
  if (!nodeId) {
    document.getElementById('node-info').innerHTML = '<div id="empty-state">Click a node to inspect.<br>Drag to pan, scroll to zoom.</div>';
    return;
  }
  const g = _state.graph;
  const attr = g.getNodeAttributes(nodeId);
  const neighborIds = g.neighbors(nodeId).slice(0, 12);
  const neighborsHtml = neighborIds.map(nid => {
    const na = g.getNodeAttributes(nid);
    return `<div class="neighbor" data-node="${nid}">${escapeHtml(na.label)}</div>`;
  }).join('');
  document.getElementById('node-info').innerHTML = `
    <div class="field"><div class="k">name</div><div class="v">${escapeHtml(attr.label)}</div></div>
    <div class="field"><div class="k">kind</div><div class="v">${escapeHtml(attr.kind)}</div></div>
    <div class="field"><div class="k">file</div><div class="v">${escapeHtml(attr.file||'?')}${attr.line?':'+attr.line:''}</div></div>
    <div class="field"><div class="k">degree</div><div class="v">${attr.degree}</div></div>
    <div class="field"><div class="k">community</div><div class="v"><span class="community-swatch" style="background:${attr.color}"></span>${escapeHtml(attr.community_label||'?')}</div></div>
    <h3 style="margin-top:14px">Neighbors (top ${neighborIds.length}/${g.degree(nodeId)})</h3>
    ${neighborsHtml || '<div class="field"><div class="v">(no edges visible at current degree filter)</div></div>'}
  `;
  document.getElementById('node-info').querySelectorAll('.neighbor').forEach(el => {
    el.addEventListener('click', () => {
      const nid = el.dataset.node;
      _state.sigma.getCamera().animate({ x: _state.graph.getNodeAttribute(nid, 'x'), y: _state.graph.getNodeAttribute(nid, 'y'), ratio: 0.3 }, { duration: 400 });
      selectNode(nid);
    });
  });
}

function highlightCommunity(cid) {
  const g = _state.graph;
  g.forEachNode((nid, attr) => {
    const matches = (attr.community === cid);
    g.setNodeAttribute(nid, 'color', matches ? attr.color : '#152035');
  });
  _state.sigma.refresh();
}

let _refetchTimer = null;
document.getElementById('min-degree').addEventListener('input', e => {
  const v = parseInt(e.target.value, 10);
  document.getElementById('min-degree-val').textContent = v;
  _state.minDegree = v;
  if (_refetchTimer) clearTimeout(_refetchTimer);
  _refetchTimer = setTimeout(async () => {
    setStats('<span class="loading-spinner"></span> reloading…');
    try { rebuildGraph(await fetchData(v)); } catch (e) { setStats('error: ' + e.message); }
  }, 250);
});

document.getElementById('search').addEventListener('input', e => {
  const q = e.target.value.toLowerCase().trim();
  _state.searchMatches.clear();
  if (!_state.graph) return;
  const g = _state.graph;
  if (q) {
    let firstMatch = null;
    g.forEachNode((nid, attr) => {
      if (attr.label && attr.label.toLowerCase().includes(q)) {
        _state.searchMatches.add(nid);
        if (!firstMatch) firstMatch = nid;
      }
    });
    // Camera fits all matches when q is specific enough. Fit-to-view
    // bounding box, computed in graph coords; then animate to that
    // center with a ratio chosen to contain the spread.
    if (_state.searchMatches.size && q.length >= 2) {
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
      for (const nid of _state.searchMatches) {
        const x = g.getNodeAttribute(nid, 'x');
        const y = g.getNodeAttribute(nid, 'y');
        if (x < minX) minX = x;
        if (x > maxX) maxX = x;
        if (y < minY) minY = y;
        if (y > maxY) maxY = y;
      }
      const cx = (minX + maxX) / 2;
      const cy = (minY + maxY) / 2;
      // Heuristic: small match set → zoom in; large match set → zoom out.
      const ratio = _state.searchMatches.size <= 2 ? 0.2
                  : _state.searchMatches.size <= 8 ? 0.4 : 0.7;
      _state.sigma.getCamera().animate({ x: cx, y: cy, ratio }, { duration: 400 });
    }
    setStats(`${_state.searchMatches.size} match${_state.searchMatches.size===1?'':'es'} for "${q}"`);
  } else {
    setStats(`${g.order} nodes · ${g.size} edges`);
  }
  _state.sigma.refresh();
});

// ---------------------------------------------------------------
// Phase-3 live agent activity overlay.
// Subscribes to /api/codegraph/stream (Server-Sent Events) and
// pulses graph nodes corresponding to files claude is actively
// reading/editing. One color per trace_id so concurrent runs are
// visually distinguishable.
// ---------------------------------------------------------------

const _live = {
  es: null,
  pulses: new Map(),    // nodeId -> {origColor, origSize, color, expires}
  traces: new Map(),    // trace_id -> {color, lastFile, lastAction, lastTs}
  tickTimer: null,
  retryDelay: 1000,
};

function traceColor(tid) {
  // Stable hash of trace_id (any string) -> hex. Hex (not hsl) because
  // Sigma's WebGL node program only parses hex/rgb.
  let h = 0;
  const s = String(tid || 'unknown');
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) | 0; }
  const hue = ((h % 360) + 360) % 360;
  return hslToHex(hue, 90, 62);
}

const PULSE_MS = 3500;
const MAX_PULSE_SIZE_BOOST = 8;

function pulseNode(nodeId, color) {
  // Don't overwrite the community color — instead set `highlighted`
  // which makes Sigma render a halo ring, AND bump size. Halo is
  // visible against any community color; size is the secondary cue.
  const g = _state.graph;
  if (!g || !g.hasNode(nodeId)) return;
  let p = _live.pulses.get(nodeId);
  if (!p) {
    const origSize = g.getNodeAttribute(nodeId, 'size');
    p = { origSize, color, expires: 0 };
    _live.pulses.set(nodeId, p);
  }
  p.color = color;
  p.expires = performance.now() + PULSE_MS;
  g.setNodeAttribute(nodeId, 'highlighted', true);
  g.setNodeAttribute(nodeId, 'size', Math.min(40, (p.origSize || 4) + MAX_PULSE_SIZE_BOOST));
}

function pulseTick() {
  const g = _state.graph;
  if (!g) return;
  const now = performance.now();
  let dirty = false;
  for (const [nid, p] of _live.pulses) {
    if (now >= p.expires) {
      if (g.hasNode(nid)) {
        g.removeNodeAttribute(nid, 'highlighted');
        g.setNodeAttribute(nid, 'size', p.origSize);
      }
      _live.pulses.delete(nid);
      dirty = true;
    } else {
      // Decay: fade size back toward original linearly with remaining time.
      const remaining = (p.expires - now) / PULSE_MS;  // 1..0
      if (g.hasNode(nid)) {
        const boost = MAX_PULSE_SIZE_BOOST * remaining;
        g.setNodeAttribute(nid, 'size', Math.min(40, (p.origSize || 4) + boost));
      }
      dirty = true;
    }
  }
  // Prune traces idle > 30 s.
  for (const [tid, t] of _live.traces) {
    if (now - t.lastSeen > 30000) {
      _live.traces.delete(tid);
      dirty = true;
    }
  }
  if (dirty) {
    if (_state.sigma) _state.sigma.refresh();
    renderTraceList();
  }
}

function renderTraceList() {
  const el = document.getElementById('trace-list');
  if (!el) return;
  if (_live.traces.size === 0) {
    el.innerHTML = '<div id="empty-state" style="padding:8px 0">Idle. Symbol pulses appear here when claude runs touch the codebase.</div>';
    return;
  }
  const rows = [..._live.traces.entries()]
    .sort((a, b) => b[1].lastSeen - a[1].lastSeen)
    .slice(0, 8)
    .map(([tid, t]) =>
      `<div class="trace-row"><span class="trace-swatch" style="background:${t.color}"></span>` +
      `<span class="tfile">${escapeHtml(t.lastFile || '—')}</span>` +
      `<span class="tact">${escapeHtml(t.lastAction || '')}</span></div>`
    ).join('');
  el.innerHTML = rows;
}

function setLiveStatus(on) {
  const dot = document.getElementById('live-dot');
  const txt = document.getElementById('live-text');
  if (dot) dot.classList.toggle('on', !!on);
  if (txt) txt.textContent = on ? 'live' : 'offline';
}

function connectLiveStream() {
  if (_live.es) { try { _live.es.close(); } catch (e) {} _live.es = null; }
  let es;
  try { es = new EventSource('/api/codegraph/stream'); }
  catch (e) { setLiveStatus(false); return; }
  _live.es = es;
  es.onopen = () => { setLiveStatus(true); _live.retryDelay = 1000; };
  es.onerror = () => {
    setLiveStatus(false);
    try { es.close(); } catch (e) {}
    _live.es = null;
    // Backoff and reconnect.
    setTimeout(connectLiveStream, _live.retryDelay);
    _live.retryDelay = Math.min(_live.retryDelay * 2, 30000);
  };
  es.onmessage = ev => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (!msg || !Array.isArray(msg.symbol_ids)) return;
    // Skip events that didn't resolve to any in-graph symbol. The
    // file isn't in our codebase — pulsing nothing AND showing the
    // file in the side panel is just noise.
    if (msg.symbol_ids.length === 0) return;
    const tid = msg.trace_id || 'unknown';
    const color = traceColor(tid);
    _live.traces.set(tid, {
      color,
      lastFile: msg.file || '',
      lastAction: msg.action || '',
      lastSeen: performance.now(),
    });
    for (const sid of msg.symbol_ids) {
      pulseNode(sid, color);
    }
    if (_state.sigma) _state.sigma.refresh();
    renderTraceList();
  };
}

function startLiveOverlay() {
  if (_live.tickTimer) clearInterval(_live.tickTimer);
  _live.tickTimer = setInterval(pulseTick, 200);
  connectLiveStream();
}

async function init() {
  try {
    _state.meta = await fetchMeta();
    document.getElementById('meta').innerHTML = Object.entries(_state.meta).map(([k,v]) =>
      `<div class="field"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div></div>`
    ).join('');
    rebuildGraph(await fetchData(_state.minDegree));
    startLiveOverlay();
    // Bridges load independently of the graph rebuild so the panel
    // still renders even if a low min-degree filter strips the
    // top-betweenness nodes from the rendered subgraph.
    fetchBridges(20).then(renderBridgeList).catch(() => {});
  } catch (e) {
    setStats('error: ' + e.message);
    document.getElementById('node-info').innerHTML = '<div id="empty-state" style="color:#ff6b6b">' + escapeHtml(e.message) + '<br><br>Has codegraph-extract.py been run? Run:<br><code>bin/codegraph-extract.py; bin/codegraph-analyze.py</code></div>';
  }
}
init();
</script>
</body>
</html>"""

AGENT_WALK_HTML = r"""<!DOCTYPE html>
<html><head><title>AetherClaude Agent Walk</title><meta charset="utf-8">
<style>
body{background:#0a0a1a;color:#c8d8e8;font-family:'SF Mono','Fira Code',monospace;font-size:12px;margin:0;padding:0}
header{background:#0e0e22;padding:10px 20px;border-bottom:1px solid #20304a;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header h1{margin:0;font-family:'CiscoSans',system-ui,sans-serif;font-size:16px;color:#00bceb;font-weight:500;letter-spacing:0.5px}
header .picker{display:flex;align-items:center;gap:6px}
header select,header input{background:#0a0a1a;color:#c8d8e8;border:1px solid #304050;padding:4px 8px;font-family:inherit;font-size:11px;border-radius:3px;min-width:200px}
header select{min-width:340px}
header a.back{color:#607080;font-size:11px;text-decoration:none;margin-left:auto;border:1px solid #304050;padding:4px 10px;border-radius:6px}
header a.back:hover{color:#00bceb;border-color:#00bceb}
.meta{padding:8px 20px;color:#8090a0;font-size:11px;border-bottom:1px solid #20304a;background:#0e0e22}
.meta .label{color:#607080;margin-right:4px}
.meta .val{color:#c8d8e8;margin-right:18px}
#swim{padding:14px 20px;background:#0a0a1a;overflow-x:auto}
.lane-bg{fill:#101025}
.lane-bg.alt{fill:#0c0c1c}
.lane-label{fill:#8090a0;font-size:11px;font-family:'SF Mono',monospace}
.lane-label.num{fill:#607080;font-size:10px}
.lane-divider{stroke:#20304a;stroke-width:1}
.time-axis{stroke:#304050;stroke-width:1}
.time-tick{fill:#607080;font-size:10px}
.event-dot{cursor:pointer;transition:r 0.1s}
.event-dot:hover{stroke:#00bceb;stroke-width:2}
.event-dot.sel{stroke:#00bceb;stroke-width:2}
.color-WEBHOOK{fill:#aa88ff}
.color-SKILL{fill:#00ff88}
.color-SCAN{fill:#00b4d8}
.color-DEFENSE{fill:#6688ff}
.color-MCP{fill:#ffaa00}
.color-EXEC{fill:#607080}
.color-TOOL{fill:#ff6688}
.color-PROMPT{fill:#ff88dd}
.color-RESPONSE{fill:#88ddff}
.color-OTHER{fill:#404060}
/* Bottom row: split into two panes — log stream (B) on the left,
 * event detail (C) on the right. Both fill the remaining vertical
 * space so the swimlane (A) above keeps its natural height. */
#bottom-pane{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:#20304a;border-top:1px solid #20304a;min-height:340px;height:42vh}
#log-stream,#detail{padding:12px 20px;background:#0e0e22;font-size:11px;line-height:1.5;overflow-y:auto}
#log-stream h3,#detail h3{font-family:'CiscoSans',system-ui,sans-serif;margin:0 0 8px 0;font-size:13px;color:#00bceb;font-weight:500;letter-spacing:0.3px;position:sticky;top:0;background:#0e0e22;padding-bottom:6px;border-bottom:1px solid #20304a;z-index:1}
#detail .row{display:flex;margin-bottom:4px}
#detail .k{color:#607080;width:120px;flex-shrink:0}
#detail .v{color:#c8d8e8;font-family:'SF Mono',monospace;word-break:break-all}
#detail .stage-pill{display:inline-block;background:#203040;color:#00bceb;padding:1px 8px;border-radius:10px;font-size:10px;margin-left:6px}
/* Log stream rows. Compact monospace so dense traces stay readable. */
#log-stream .lrow{display:flex;gap:8px;padding:2px 4px 2px 6px;font-family:'SF Mono',monospace;font-size:10px;border-radius:2px;cursor:pointer;align-items:baseline;border-left:3px solid #303040;background:#0e0e22}
#log-stream .lrow:hover{filter:brightness(1.4)}
#log-stream .lrow.cur{box-shadow:inset 0 0 0 1px #00bceb;color:#fff}
#log-stream .lrow .lt{color:#505060;width:80px;flex-shrink:0}
#log-stream .lrow .lstage{color:#607080;width:30px;flex-shrink:0;text-align:right}
#log-stream .lrow .ltype{width:80px;flex-shrink:0;text-overflow:ellipsis;overflow:hidden;white-space:nowrap}
#log-stream .lrow .larg{flex:1;color:#8090a0;text-overflow:ellipsis;overflow:hidden;white-space:nowrap}
#log-stream .empty-state{color:#607080;padding:30px 0;text-align:center}
/* Source-based coloring — mirrors the main dashboard's .ev.<source> rules
 * so an SE sees the same visual mapping in both places. */
#log-stream .lrow.agent{background:#0a1a0a;border-left-color:#00ff88}
#log-stream .lrow.guard{background:#1a0a10;border-left-color:#ff6688}
#log-stream .lrow.mcp{background:#0f0a1a;border-left-color:#aa88ff}
#log-stream .lrow.nftables{background:#1a0808;border-left-color:#ff4444}
#log-stream .lrow.tinyproxy{background:#081a10;border-left-color:#44ddaa}
#log-stream .lrow.mcp-scan{background:#081018;border-left-color:#00ddff}
#log-stream .lrow.skill-scan{background:#100818;border-left-color:#dd88ff}
#log-stream .lrow.skill-dispatch{background:#181808;border-left-color:#ffdd44}
#log-stream .lrow.webhook{background:#081018;border-left-color:#44aaff}
#log-stream .lrow.defenseclaw{background:#0c0c20;border-left-color:#6688ff}
#log-stream .lrow.claude-code{background:#180818;border-left-color:#ff88cc}
#log-stream .lrow.claude-transcript{background:#180818;border-left-color:#ff88dd}
#log-stream .lrow.prompt-scan{background:#150818;border-left-color:#ff88dd}
.empty{padding:60px 20px;text-align:center;color:#607080}
.legend{display:flex;gap:16px;font-size:10px;color:#607080;padding:6px 20px;background:#0a0a1a;border-bottom:1px solid #20304a}
.legend .swatch{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;vertical-align:middle}
.player{display:flex;align-items:center;gap:10px;padding:8px 20px;background:#0e0e22;border-bottom:1px solid #20304a;font-size:11px}
.player button{background:#101025;color:#c8d8e8;border:1px solid #304050;padding:4px 12px;font-family:inherit;font-size:11px;border-radius:3px;cursor:pointer}
.player button:hover{border-color:#00bceb;color:#00bceb}
.player button.active{background:#203040;color:#00bceb;border-color:#00bceb}
.player .speed-label{color:#607080}
.player .progress{flex:1;height:4px;background:#101025;border-radius:2px;position:relative;overflow:hidden;margin:0 12px}
.player .progress .bar{position:absolute;left:0;top:0;height:100%;background:#00ff88;width:0;transition:width 0.05s linear}
.player .progress .ts-label{color:#607080;font-size:10px;min-width:90px;text-align:right;font-family:'SF Mono',monospace}
.event-dot.hidden{opacity:0}
.event-dot{transition:opacity 0.15s,r 0.1s}
/* Alert dots — events whose args contain 'failed' or 'blocked' pulse
   bright red so failures stand out from background activity on the
   swimlane. Stays on top via :not(.sel) so a selected alert dot still
   gets the cyan selection ring. */
@keyframes alert-pulse{
  0%,100%{r:5;fill:#ff2222;filter:drop-shadow(0 0 2px #ff2222)}
  50%    {r:8;fill:#ff5555;filter:drop-shadow(0 0 7px #ff2222)}
}
.event-dot.alert-pulse{
  fill:#ff2222 !important;
  animation:alert-pulse 1.1s ease-in-out infinite;
}
</style></head><body>
<header>
  <h1>Agent Walk</h1>
  <div class="picker">
    <span style="color:#607080">trace:</span>
    <select id="trace-select"></select>
  </div>
  <div class="picker">
    <span style="color:#607080">or paste:</span>
    <input id="trace-input" placeholder="X-GitHub-Delivery UUID" />
  </div>
  <a href="/" class="back">Main dashboard ↗</a>
</header>
<div class="legend">
  <span><span class="swatch color-WEBHOOK"></span>Webhook</span>
  <span><span class="swatch color-SKILL"></span>Skill</span>
  <span><span class="swatch color-SCAN"></span>Scan</span>
  <span><span class="swatch color-DEFENSE"></span>AI-Defense</span>
  <span><span class="swatch color-MCP"></span>MCP</span>
  <span><span class="swatch color-TOOL"></span>Tool</span>
  <span><span class="swatch color-PROMPT"></span>Prompt</span>
  <span><span class="swatch color-RESPONSE"></span>Response</span>
  <span><span class="swatch color-EXEC"></span>Process</span>
  <span><span class="swatch color-OTHER"></span>Other</span>
</div>
<div class="meta" id="meta">No trace loaded.</div>
<div class="player" id="player" style="display:none">
  <button id="btn-play">▶ Play</button>
  <button id="btn-pause" disabled>⏸ Pause</button>
  <button id="btn-reset">⟲ Reset</button>
  <button id="btn-prev" title="Step back to previous event">◀ Prev</button>
  <button id="btn-next" title="Step forward to next event">Next ▶</button>
  <span class="speed-label">speed:</span>
  <button class="speed-btn" data-speed="1">1×</button>
  <button class="speed-btn active" data-speed="4">4×</button>
  <button class="speed-btn" data-speed="16">16×</button>
  <button class="speed-btn" data-speed="64">64×</button>
  <div class="progress"><div class="bar" id="progress-bar"></div></div>
  <span class="ts-label" id="progress-ts">—</span>
</div>
<div id="swim"></div>
<div id="bottom-pane">
  <div id="log-stream"><h3>Log stream</h3><div id="log-stream-body"><p class="empty-state">Press ▶ Play or step with Next ▶ — events will appear here in time-order.</p></div></div>
  <div id="detail"><h3>Event detail</h3><p style="color:#607080">Click an event in the swimlane above (or in the log stream on the left).</p></div>
</div>

<script>
const STAGES=[
  {n:1,name:'Webhook'},
  {n:2,name:'Orchestrator'},
  {n:3,name:'Skill'},
  {n:4,name:'Scanning (skill / MCP)'},
  {n:5,name:'Claude Code'},
  {n:6,name:'AI-Defense'},
  {n:7,name:'MCP'},
  {n:8,name:'Prompt / Response'},
  {n:9,name:'GitHub publish'},
  {n:10,name:'Cleanup / audit'},
];
const SVG_NS='http://www.w3.org/2000/svg';
const LANE_HEIGHT=40,LANE_LABEL_W=180,RIGHT_PAD=24,TOP_PAD=8,BOTTOM_PAD=28;
let _events=[],_selectedIdx=-1;
// Replay state
let _playTimers=[],_progressInterval=null,_isPlaying=false,_speed=4,_replayStart=0,_replayDuration=0;
// Step state — index of the latest event shown via Prev/Next stepping.
// -1 means "no stepping in progress" (live mode, all dots visible).
let _stepIdx=-1;

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fmtTime(s){if(!s)return '';const dt=new Date(s);if(isNaN(dt))return s;const hms=dt.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});const ms=String(dt.getMilliseconds()).padStart(3,'0');return `${hms}.${ms}`}
function fmtDuration(ms){if(ms<1000)return `${ms}ms`;if(ms<60000)return `${(ms/1000).toFixed(2)}s`;return `${Math.floor(ms/60000)}m${Math.floor((ms%60000)/1000)}s`}

function loadRecentTraces(){
  fetch('/api/agent-walk-traces?limit=25').then(r=>r.json()).then(d=>{
    const sel=document.getElementById('trace-select');
    sel.innerHTML='<option value="">— pick a recent trace —</option>';
    for(const t of (d.traces||[])){
      const opt=document.createElement('option');
      opt.value=t.trace_id;
      const t8=t.trace_id.substring(0,8);
      const ts=t.first_ts?(new Date(t.first_ts)).toLocaleString():'?';
      opt.textContent=`${t8}…  ${ts}  (${t.event_count} events) ${t.summary.substring(0,60)}`;
      sel.appendChild(opt);
    }
    // If URL has ?trace= and matches a known trace, preselect
    const urlTrace=new URLSearchParams(location.search).get('trace');
    if(urlTrace){sel.value=urlTrace;loadTrace(urlTrace)}
  })
}

function loadTrace(traceId){
  if(!traceId){document.getElementById('swim').innerHTML='<div class="empty">No trace selected.</div>';return}
  // Reflect in URL without reloading
  const u=new URL(location.href);u.searchParams.set('trace',traceId);history.replaceState({},'',u);
  fetch('/api/agent-walk?trace='+encodeURIComponent(traceId)).then(r=>r.json()).then(d=>{
    if(d.error){document.getElementById('swim').innerHTML='<div class="empty">'+esc(d.error)+'</div>';return}
    _events=d.events||[];_selectedIdx=-1;
    const meta=document.getElementById('meta');
    if(_events.length===0){meta.textContent='Trace has no events.';document.getElementById('swim').innerHTML='<div class="empty">No events for this trace.</div>';document.getElementById('player').style.display='none';return}
    document.getElementById('player').style.display='flex';
    stopReplay();
    _stepIdx=-1;
    logStreamClear();
    const t0=new Date(_events[0].time),tN=new Date(_events[_events.length-1].time);
    const dur=tN-t0;
    const bg=d.background_dropped||0;
    meta.innerHTML=
      `<span class="label">trace:</span><span class="val">${esc(traceId.substring(0,8))}…</span>`+
      `<span class="label">start:</span><span class="val">${fmtTime(_events[0].time)}</span>`+
      `<span class="label">end:</span><span class="val">${fmtTime(_events[_events.length-1].time)}</span>`+
      `<span class="label">duration:</span><span class="val">${fmtDuration(dur)}</span>`+
      `<span class="label">classified:</span><span class="val">${d.event_count}</span>`+
      (bg>0?`<span class="label">background:</span><span class="val">${bg} (filtered)</span>`:'');
    renderSwimlane();
  })
}

function renderSwimlane(){
  const container=document.getElementById('swim');
  const width=Math.max(900,container.clientWidth-40);
  const innerW=width-LANE_LABEL_W-RIGHT_PAD;
  const height=TOP_PAD+STAGES.length*LANE_HEIGHT+BOTTOM_PAD;
  // Time domain: from first_ts to last_ts (with min 1s padding for tiny traces)
  const t0=new Date(_events[0].time).getTime();
  const tN=new Date(_events[_events.length-1].time).getTime();
  const span=Math.max(tN-t0,1000);
  function x(t){return LANE_LABEL_W+((new Date(t).getTime()-t0)/span)*innerW}

  let svg=`<svg xmlns="${SVG_NS}" width="${width}" height="${height}" style="background:#0a0a1a">`;
  // Lane backgrounds + labels
  for(let i=0;i<STAGES.length;i++){
    const cls=(i%2===0)?'lane-bg':'lane-bg alt';
    const y=TOP_PAD+i*LANE_HEIGHT;
    svg+=`<rect class="${cls}" x="0" y="${y}" width="${width}" height="${LANE_HEIGHT}"/>`;
    svg+=`<text class="lane-label num" x="12" y="${y+LANE_HEIGHT/2-3}">stage ${STAGES[i].n}</text>`;
    svg+=`<text class="lane-label" x="12" y="${y+LANE_HEIGHT/2+12}">${STAGES[i].name}</text>`;
    svg+=`<line class="lane-divider" x1="${LANE_LABEL_W}" y1="${y+LANE_HEIGHT}" x2="${width}" y2="${y+LANE_HEIGHT}"/>`;
  }
  // Time axis
  const axisY=TOP_PAD+STAGES.length*LANE_HEIGHT+12;
  svg+=`<line class="time-axis" x1="${LANE_LABEL_W}" y1="${axisY}" x2="${width-RIGHT_PAD}" y2="${axisY}"/>`;
  // Time ticks: 5 evenly spaced
  for(let i=0;i<=4;i++){
    const tx=LANE_LABEL_W+(i/4)*innerW;
    const tt=t0+(i/4)*span;
    svg+=`<line class="time-axis" x1="${tx}" y1="${axisY-3}" x2="${tx}" y2="${axisY+3}"/>`;
    svg+=`<text class="time-tick" x="${tx}" y="${axisY+16}" text-anchor="middle">${fmtTime(new Date(tt).toISOString())}</text>`;
  }
  // Event dots — uncategorized (stage 0) go in a thin row above the swimlane
  for(let i=0;i<_events.length;i++){
    const e=_events[i];
    const stage=e.stage||0;
    let yCenter;
    if(stage===0){yCenter=2}  // pinned at top, won't display in normal lanes
    else{yCenter=TOP_PAD+(stage-1)*LANE_HEIGHT+LANE_HEIGHT/2}
    if(stage===0)continue;  // hide uncategorized for the demo cleanliness; can toggle on
    const xCenter=x(e.time);
    const colorCls='color-'+(e.type||'OTHER');
    // Failure / blocked markers — surface them as pulsing red dots so
    // validation rejections, blocked tool calls, and orchestrator
    // failures are visible at a glance, regardless of which stage they
    // land in. Case-insensitive substring match on args.
    const haystack=((e.args||'')+' '+(e.policy||'')).toLowerCase();
    const isAlert=haystack.includes('failed')||haystack.includes('blocked');
    const dotCls=isAlert?`event-dot alert-pulse ${colorCls}`:`event-dot ${colorCls}`;
    svg+=`<circle class="${dotCls}" data-i="${i}" cx="${xCenter}" cy="${yCenter}" r="5"><title>${esc(e.type)} · ${esc(e.binary)} · ${esc((e.args||'').substring(0,80))}</title></circle>`;
  }
  svg+='</svg>';
  container.innerHTML=svg;
  // Wire click — selects detail + highlights matching log-stream row
  container.querySelectorAll('.event-dot').forEach(el=>{
    el.addEventListener('click',()=>{
      const idx=parseInt(el.getAttribute('data-i'),10);
      _selectedIdx=idx;
      container.querySelectorAll('.event-dot.sel').forEach(d=>d.classList.remove('sel'));
      el.classList.add('sel');
      renderDetail();
      // Mirror the highlight in the log stream if a row exists for this idx.
      document.querySelectorAll('#log-stream .lrow.cur').forEach(r=>r.classList.remove('cur'));
      const row=document.querySelector('#log-stream .lrow[data-i="'+idx+'"]');
      if(row){row.classList.add('cur');row.scrollIntoView({block:'nearest',behavior:'smooth'})}
    });
  });
}

function renderDetail(){
  const d=document.getElementById('detail');
  if(_selectedIdx<0||_selectedIdx>=_events.length){d.innerHTML='<h3>Event detail</h3><p style="color:#607080">Click an event in the swimlane above.</p>';return}
  const e=_events[_selectedIdx];
  const stage=e.stage||0;
  const stageName=stage>0?STAGES[stage-1].name:'(uncategorized)';
  d.innerHTML='<h3>Event detail <span class="stage-pill">stage '+stage+' · '+esc(stageName)+'</span></h3>'+
    '<div class="row"><div class="k">timestamp</div><div class="v">'+esc(e.time)+'</div></div>'+
    '<div class="row"><div class="k">type</div><div class="v">'+esc(e.type)+'</div></div>'+
    '<div class="row"><div class="k">source</div><div class="v">'+esc(e.source)+'</div></div>'+
    '<div class="row"><div class="k">binary</div><div class="v">'+esc(e.binary)+'</div></div>'+
    '<div class="row"><div class="k">uid</div><div class="v">'+esc(e.uid)+'</div></div>'+
    '<div class="row"><div class="k">policy</div><div class="v">'+esc(e.policy||'(none)')+'</div></div>'+
    '<div class="row"><div class="k">args</div><div class="v">'+esc(e.args)+'</div></div>'+
    '<div class="row"><div class="k">trace_id</div><div class="v">'+esc(e.trace_id)+'</div></div>';
}

// --- Log stream pane (B) ---
// Mirrors the swimlane: each visible-now event gets one row in time order.
// Clicking a row selects that event (highlights its dot in the swimlane and
// populates the detail pane on the right).
//
// Source → CSS class mapping mirrors the main dashboard so SEs see the
// same visual scheme in both views (yellow=skill-dispatch, blue=webhook,
// blue-purple=defenseclaw, pink=claude-code, etc.).
function rowSourceClass(e){
  const s=e.source||'';
  switch(s){
    case 'webhook': return 'webhook';
    case 'skill-dispatch': return 'skill-dispatch';
    case 'defenseclaw': return 'defenseclaw';
    case 'claude-code': return 'claude-code';
    case 'claude-transcript': return 'claude-transcript';
    case 'mcp': return 'mcp';
    case 'mcp-scan': return 'mcp-scan';
    case 'skill-scan': return 'skill-scan';
    case 'prompt-scan': return 'prompt-scan';
    case 'codeguard': return 'guard';
    case 'tinyproxy': return 'tinyproxy';
    case 'nftables': return 'nftables';
    default: return e.is_agent ? 'agent' : '';
  }
}
function logStreamClear(){
  const body=document.getElementById('log-stream-body');
  body.innerHTML='<p class="empty-state">Press ▶ Play or step with Next ▶ — events will appear here in time-order.</p>';
}
function logStreamRenderUpTo(idx){
  // Show all events 0..idx in the log; highlight idx.
  const body=document.getElementById('log-stream-body');
  if(_events.length===0||idx<0){logStreamClear();return}
  let h='';
  for(let i=0;i<=idx&&i<_events.length;i++){
    const e=_events[i];
    const cur=(i===idx)?' cur':'';
    const stage=e.stage||0;
    const srcCls=rowSourceClass(e);
    const colorCls='color-'+(e.type||'OTHER');
    h+=`<div class="lrow ${srcCls}${cur}" data-i="${i}" onclick="logStreamSelect(${i})">`+
       `<span class="lt">${fmtTime(e.time)}</span>`+
       `<span class="lstage" style="color:#00bceb">${stage||'·'}</span>`+
       `<span class="ltype ${colorCls}" style="font-weight:bold">${esc(e.type||'')}</span>`+
       `<span class="larg">${esc((e.binary||'').replace(/^claude:/,'')+' '+(e.args||''))}</span>`+
       `</div>`;
  }
  body.innerHTML=h;
  // Auto-scroll the current row into view.
  const cur=body.querySelector('.lrow.cur');
  if(cur)cur.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function logStreamAppend(idx){
  // Append-only variant for live replay — avoids re-rendering the full
  // list for every event during fast playback. If the log is empty
  // (still showing the empty-state), bootstrap it.
  const body=document.getElementById('log-stream-body');
  if(idx<0||idx>=_events.length)return;
  if(body.querySelector('.empty-state'))body.innerHTML='';
  // Demote any prior 'cur' to plain row.
  body.querySelectorAll('.lrow.cur').forEach(el=>el.classList.remove('cur'));
  const e=_events[idx];
  const stage=e.stage||0;
  const srcCls=rowSourceClass(e);
  const colorCls='color-'+(e.type||'OTHER');
  const div=document.createElement('div');
  div.className=`lrow ${srcCls} cur`;
  div.setAttribute('data-i',String(idx));
  div.setAttribute('onclick',`logStreamSelect(${idx})`);
  div.innerHTML=
    `<span class="lt">${fmtTime(e.time)}</span>`+
    `<span class="lstage" style="color:#00bceb">${stage||'·'}</span>`+
    `<span class="ltype ${colorCls}" style="font-weight:bold">${esc(e.type||'')}</span>`+
    `<span class="larg">${esc((e.binary||'').replace(/^claude:/,'')+' '+(e.args||''))}</span>`;
  body.appendChild(div);
  div.scrollIntoView({block:'nearest',behavior:'smooth'});
}
function logStreamSelect(idx){
  // User clicked a log row — select that event in detail + highlight in
  // both panes. Mirrors a swimlane dot click.
  _selectedIdx=idx;
  document.querySelectorAll('.event-dot.sel').forEach(el=>el.classList.remove('sel'));
  const dot=document.querySelector('.event-dot[data-i="'+idx+'"]');
  if(dot)dot.classList.add('sel');
  document.querySelectorAll('#log-stream .lrow.cur').forEach(el=>el.classList.remove('cur'));
  const row=document.querySelector('#log-stream .lrow[data-i="'+idx+'"]');
  if(row){row.classList.add('cur');row.scrollIntoView({block:'nearest',behavior:'smooth'})}
  renderDetail();
}

// --- Replay player ---
function startReplay(){
  if(_isPlaying||_events.length===0)return;
  _isPlaying=true;
  document.getElementById('btn-play').disabled=true;
  document.getElementById('btn-pause').disabled=false;
  // Hide all dots, schedule each to appear at scaled time. The scaling
  // takes the wall-clock event offset and divides by speed, so a 60s
  // real-time trace plays back in 15s at 4× or 1s at 64×.
  const dots=document.querySelectorAll('.event-dot');
  dots.forEach(d=>d.classList.add('hidden'));
  const t0=new Date(_events[0].time).getTime();
  const tN=new Date(_events[_events.length-1].time).getTime();
  _replayDuration=Math.max(tN-t0,1);
  _replayStart=performance.now();
  // Build an idx→dot lookup by data-i (renderSwimlane only emits dots
  // for stage>0 events, so not every _events index has a corresponding
  // dot — handled by the optional-chain on querySelector).
  // Reset the log stream so it starts empty and gets appended live.
  document.getElementById('log-stream-body').innerHTML='';
  for(let i=0;i<_events.length;i++){
    const e=_events[i];
    const offsetMs=new Date(e.time).getTime()-t0;
    const scaledMs=offsetMs/_speed;
    _playTimers.push(setTimeout(()=>{
      const dot=document.querySelector('.event-dot[data-i="'+i+'"]');
      if(dot)dot.classList.remove('hidden');
      // Append the row to the log stream as the dot lights up.
      logStreamAppend(i);
    },scaledMs));
  }
  // Auto-stop at end + reset UI
  _playTimers.push(setTimeout(()=>{
    _isPlaying=false;
    document.getElementById('btn-play').disabled=false;
    document.getElementById('btn-pause').disabled=true;
    if(_progressInterval){clearInterval(_progressInterval);_progressInterval=null}
    document.getElementById('progress-bar').style.width='100%';
  },_replayDuration/_speed+50));
  // Progress bar tick
  _progressInterval=setInterval(()=>{
    const elapsed=performance.now()-_replayStart;
    const pct=Math.min(100,(elapsed/(_replayDuration/_speed))*100);
    document.getElementById('progress-bar').style.width=pct+'%';
    const tCurrent=new Date(t0+elapsed*_speed);
    document.getElementById('progress-ts').textContent=fmtTime(tCurrent.toISOString());
  },50);
}

function stopReplay(){
  for(const t of _playTimers)clearTimeout(t);
  _playTimers=[];
  if(_progressInterval){clearInterval(_progressInterval);_progressInterval=null}
  _isPlaying=false;
  document.getElementById('btn-play').disabled=false;
  document.getElementById('btn-pause').disabled=true;
  document.getElementById('progress-bar').style.width='0%';
  document.getElementById('progress-ts').textContent='—';
  // Don't unhide — pause keeps the current visible state. Reset does.
}

function resetReplay(){
  stopReplay();
  _stepIdx=-1;
  document.querySelectorAll('.event-dot').forEach(d=>{d.classList.remove('hidden');d.classList.remove('sel')});
  document.getElementById('progress-bar').style.width='0%';
  document.getElementById('progress-ts').textContent='—';
  // Detail panel + log stream back to default
  _selectedIdx=-1;
  renderDetail();
  logStreamClear();
}

// Step to a specific event index. Hides dots after it, shows dots up to
// and including it, selects the target dot, and updates the detail panel
// + progress indicator. If a Play is in flight, pause it first so the
// step doesn't fight the timer queue.
function stepTo(idx){
  if(_events.length===0)return;
  if(_isPlaying)stopReplay();
  if(idx<0)idx=0;
  if(idx>_events.length-1)idx=_events.length-1;
  _stepIdx=idx;
  // Show/hide each dot based on whether its event index is <= idx
  document.querySelectorAll('.event-dot').forEach(d=>{
    const di=parseInt(d.getAttribute('data-i'),10);
    if(di<=idx){d.classList.remove('hidden')}else{d.classList.add('hidden')}
    d.classList.remove('sel');
  });
  // Highlight the current step's dot
  const cur=document.querySelector('.event-dot[data-i="'+idx+'"]');
  if(cur)cur.classList.add('sel');
  // Populate detail panel + redraw log stream up to current step
  _selectedIdx=idx;
  renderDetail();
  logStreamRenderUpTo(idx);
  // Progress indicator
  const t0=new Date(_events[0].time).getTime();
  const tN=new Date(_events[_events.length-1].time).getTime();
  const tCur=new Date(_events[idx].time).getTime();
  const pct=tN>t0?((tCur-t0)/(tN-t0))*100:100;
  document.getElementById('progress-bar').style.width=pct+'%';
  document.getElementById('progress-ts').textContent=fmtTime(_events[idx].time);
}

document.getElementById('btn-play').addEventListener('click',startReplay);
document.getElementById('btn-pause').addEventListener('click',stopReplay);
document.getElementById('btn-reset').addEventListener('click',resetReplay);
document.getElementById('btn-prev').addEventListener('click',()=>{
  // If we haven't started stepping, jump to the LAST event so Prev
  // first goes to the end (intuitive: scrub backward from the end).
  // Otherwise, step back from the current position.
  if(_stepIdx<0)stepTo(_events.length-1);
  else stepTo(_stepIdx-1);
});
document.getElementById('btn-next').addEventListener('click',()=>{
  // If we haven't started stepping, start at the first event.
  // Otherwise, advance.
  if(_stepIdx<0)stepTo(0);
  else stepTo(_stepIdx+1);
});
document.querySelectorAll('.speed-btn').forEach(b=>{
  b.addEventListener('click',()=>{
    _speed=parseInt(b.getAttribute('data-speed'),10);
    document.querySelectorAll('.speed-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    if(_isPlaying){stopReplay();startReplay()}  // restart at new speed
  });
});

// Wire pickers
document.getElementById('trace-select').addEventListener('change',ev=>{loadTrace(ev.target.value)});
document.getElementById('trace-input').addEventListener('change',ev=>{loadTrace(ev.target.value.trim())});
document.getElementById('trace-input').addEventListener('keydown',ev=>{if(ev.key==='Enter')loadTrace(ev.target.value.trim())});

window.addEventListener('resize',()=>{if(_events.length>0)renderSwimlane()});
loadRecentTraces();
</script>
</body></html>"""

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=='/':
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path == '/agent-walk' or self.path.startswith('/agent-walk?'):
            self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
            self.wfile.write(AGENT_WALK_HTML.encode())
        elif self.path == '/codegraph' or self.path.startswith('/codegraph?'):
            # AetherSDR codebase knowledge-graph viz. Loads vendored
            # Sigma.js + graphology from /codegraph/assets/, fetches
            # /api/codegraph/data for nodes+edges, runs ForceAtlas2
            # client-side. See bin/codegraph-extract.py + analyze.py.
            self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
            self.wfile.write(CODEGRAPH_HTML.encode())
        elif self.path.startswith('/codegraph/assets/'):
            # Static-file serve for the vendored Sigma+graphology JS.
            # Tight path-safety: name must be a known JS asset.
            name = self.path[len('/codegraph/assets/'):].split('?', 1)[0]
            ALLOWED = {
                'sigma.min.js': 'application/javascript',
                'graphology.umd.min.js': 'application/javascript',
                'graphology-library.min.js': 'application/javascript',
            }
            if name not in ALLOWED:
                self.send_response(404); self.end_headers(); return
            asset_path = os.path.join(CODEGRAPH_ASSETS_DIR, name)
            try:
                with open(asset_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', ALLOWED[name])
                self.send_header('Cache-Control', 'public, max-age=86400')
                self.end_headers()
                self.wfile.write(data)
            except (FileNotFoundError, OSError):
                self.send_response(404); self.end_headers()
        elif self.path.startswith('/api/codegraph/data'):
            # Returns {nodes, edges} as JSON. Filters by min_degree query
            # param (default 1) so the page doesn't ship the cloud of
            # isolated nodes whose call sites our Phase-1 name-matcher
            # missed.
            from urllib.parse import urlparse, parse_qs
            try:
                qs = parse_qs(urlparse(self.path).query)
                min_degree = max(0, int(qs.get('min_degree', ['1'])[0]))
            except (ValueError, TypeError):
                min_degree = 1
            try:
                conn = sqlite3.connect(CODEGRAPH_DB)
                conn.row_factory = sqlite3.Row
                cur = conn.execute(
                    'SELECT id, qualified_name AS label, kind, file_path AS file, '
                    'line_number AS line, community_id AS community, '
                    'community_label, degree FROM symbols WHERE degree >= ?',
                    (min_degree,),
                )
                nodes = [dict(r) for r in cur.fetchall()]
                node_ids = {n['id'] for n in nodes}
                # Edges where BOTH endpoints survived the degree filter
                edges = []
                for src, dst, kind in conn.execute(
                    'SELECT src_id, dst_id, kind FROM edges'
                ):
                    if src in node_ids and dst in node_ids:
                        edges.append({'source': src, 'target': dst, 'kind': kind})
                conn.close()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(json.dumps({'nodes': nodes, 'edges': edges}).encode())
            except sqlite3.Error as ex:
                self.send_response(503)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': f'codegraph db unavailable: {ex}'}).encode())
        elif self.path == '/api/codegraph/stream':
            # Phase-3 live agent-activity overlay. Server-Sent Events
            # stream of claude:Read/Edit/Write tool events mapped to
            # codegraph symbol IDs via the file_to_symbols table.
            #
            # Mapping is by file basename (e.g. "RadioModel.h") because
            # tail_sessions stores only the basename in args. That works
            # for AetherSDR where each filename is unique. Multiple-symbol
            # matches across files with the same basename would pulse all
            # of them, which is the correct visual.
            #
            # Polls events.db every 500 ms, sends a heartbeat comment
            # every 30 s to keep the connection alive through reverse
            # proxies.
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            self.end_headers()
            try:
                last_seen_id = -1
                last_hb = time.time()
                # Open codegraph.db once and reuse — file_to_symbols
                # only changes on the nightly refresh, no need to reopen.
                try:
                    cg_conn = sqlite3.connect(CODEGRAPH_DB)
                except sqlite3.Error:
                    cg_conn = None
                while True:
                    try:
                        conn = sqlite3.connect(EVENTS_DB)
                        conn.row_factory = sqlite3.Row
                        if last_seen_id < 0:
                            # First poll — seed from now, don't replay history.
                            row = conn.execute('SELECT MAX(id) FROM events').fetchone()
                            last_seen_id = (row[0] or 0)
                        # Only Read/Edit/Write — their args is a file
                        # basename. Grep/Glob args is a regex/glob
                        # pattern; trying to map those to symbols
                        # spams the side panel with garbage like
                        # `^#include` while finding no symbols.
                        rows = conn.execute(
                            "SELECT id, timestamp AS time, trace_id, "
                            "       binary_name, args FROM events "
                            " WHERE id > ? AND source='claude-code' "
                            "   AND (binary_name LIKE 'claude:Read%' "
                            "     OR binary_name LIKE 'claude:Edit%' "
                            "     OR binary_name LIKE 'claude:Write%') "
                            " ORDER BY id ASC LIMIT 50",
                            (last_seen_id,)
                        ).fetchall()
                        conn.close()
                        for r in rows:
                            last_seen_id = r['id']
                            basename = (r['args'] or '').strip()
                            if not basename:
                                continue
                            binary = r['binary_name'] or ''
                            if 'Edit' in binary or 'Write' in binary:
                                action = 'edit'
                            else:
                                action = 'read'
                            sym_ids = []
                            if cg_conn is not None:
                                try:
                                    sym_ids = [
                                        sid for (sid,) in cg_conn.execute(
                                            'SELECT DISTINCT symbol_id '
                                            '  FROM file_to_symbols '
                                            ' WHERE file_path LIKE ? '
                                            ' LIMIT 200',
                                            (f'%/{basename}',)
                                        ).fetchall()
                                    ]
                                except sqlite3.Error:
                                    pass
                            evt = {
                                'trace_id': r['trace_id'] or '',
                                'action': action,
                                'file': basename,
                                'symbol_ids': sym_ids,
                                'ts': r['time'],
                            }
                            self.wfile.write(
                                f'data: {json.dumps(evt)}\n\n'.encode()
                            )
                            self.wfile.flush()
                        if time.time() - last_hb > 30:
                            self.wfile.write(b': hb\n\n')
                            self.wfile.flush()
                            last_hb = time.time()
                        time.sleep(0.5)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        break
                if cg_conn is not None:
                    cg_conn.close()
            except Exception:
                pass
            return
        elif self.path == '/api/codegraph/meta':
            # Returns the metadata table as a flat {key: value} JSON.
            try:
                conn = sqlite3.connect(CODEGRAPH_DB)
                meta = dict(conn.execute('SELECT key, value FROM metadata').fetchall())
                conn.close()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(meta).encode())
            except sqlite3.Error as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
        elif self.path.startswith('/api/codegraph/bridges'):
            # Top-N symbols by betweenness centrality. The "Refactor
            # watch-list" panel: high betweenness = a symbol that sits
            # on many shortest paths between others, so changing it
            # ripples widely. Limit defaults to 20.
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query)
                limit = int(qs.get('limit', ['20'])[0])
                limit = max(1, min(100, limit))
                conn = sqlite3.connect(CODEGRAPH_DB)
                rows = conn.execute(
                    'SELECT id, qualified_name, name, kind, file_path, '
                    '       line_number, community_label, betweenness, degree '
                    '  FROM symbols '
                    ' WHERE betweenness > 0 '
                    ' ORDER BY betweenness DESC LIMIT ?',
                    (limit,)
                ).fetchall()
                conn.close()
                out = [
                    {'id': r[0], 'qualified_name': r[1], 'name': r[2],
                     'kind': r[3], 'file': r[4], 'line': r[5],
                     'community_label': r[6], 'betweenness': r[7], 'degree': r[8]}
                    for r in rows
                ]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(out).encode())
            except (sqlite3.Error, ValueError) as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
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
        elif self.path.startswith('/fonts/'):
            # Serve proprietary/branded fonts from PRIVATE_FONTS_DIR
            # (outside the git tree). 404 if the file is missing — CSS
            # @font-face declarations fall back to the system stack, so
            # an empty dir is a no-op.
            name = self.path[len('/fonts/'):].split('?', 1)[0]
            # Path-safety: reject empty, anything with separators or
            # parent-dir traversal, anything not a recognized font ext.
            font_types = {
                'woff2': 'font/woff2',
                'woff':  'font/woff',
                'otf':   'font/otf',
                'ttf':   'font/ttf',
                'eot':   'application/vnd.ms-fontobject',
            }
            ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
            if not name or '/' in name or '..' in name or ext not in font_types:
                self.send_response(400); self.end_headers()
            else:
                font_path = os.path.join(PRIVATE_FONTS_DIR, name)
                try:
                    if not os.path.isfile(font_path):
                        raise FileNotFoundError(font_path)
                    with open(font_path, 'rb') as ff:
                        data = ff.read()
                    self.send_response(200)
                    self.send_header('Content-Type', font_types[ext])
                    self.send_header('Cache-Control', 'public, max-age=3600')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(data)
                except (FileNotFoundError, OSError):
                    self.send_response(404); self.end_headers()
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
                # Resolve logo relative to this script so it works from any install layout.
                # Follows symlinks (deploy.sh installs bin/ scripts as symlinks into the repo).
                _script = os.path.realpath(__file__)
                _logo_path = os.path.join(os.path.dirname(os.path.dirname(_script)), 'assets', 'logo.png')
                with open(_logo_path, 'rb') as lf:
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
        elif self.path.startswith('/api/prompt-scan'):
            # Return findings from the most recent scan_time per prompt only,
            # so the modal doesn't accumulate stale rows from earlier runs.
            try:
                conn = sqlite3.connect(EVENTS_DB)
                latest_ts = conn.execute(
                    'SELECT MAX(scan_time) FROM prompt_findings'
                ).fetchone()[0]
                if latest_ts is None:
                    rows = []
                else:
                    # Take rows whose scan_time is within ~10s of the latest
                    # (one orchestrator run inserts all rows in one
                    # transaction with CURRENT_TIMESTAMP, but small clock
                    # differences across rows in the same batch are possible).
                    rows = conn.execute(
                        'SELECT scan_time, prompt_name, analyzer, technique_name, severity, summary, is_advisory '
                        'FROM prompt_findings '
                        "WHERE scan_time >= datetime(?, '-10 seconds') "
                        'ORDER BY prompt_name, is_advisory ASC, severity DESC',
                        (latest_ts,)
                    ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM prompt_findings').fetchone()[0]
                conn.close()
                findings = [
                    {'scan_time': r[0], 'prompt_name': r[1], 'analyzer': r[2],
                     'technique_name': r[3], 'severity': r[4], 'summary': r[5],
                     'is_advisory': bool(r[6])}
                    for r in rows
                ]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'findings': findings, 'total': total, 'latest_scan': latest_ts})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'findings': [], 'total': 0, 'error': str(ex)})
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
                # Latest vulns per component: pick the scan_time of the newest row per
                # component_name and return only the vulns from that scan. Avoids
                # surfacing CVEs that were resolved upstream + re-scanned clean.
                vuln_rows = conn.execute('''
                    WITH latest AS (
                        SELECT component_name, MAX(scan_time) AS latest_time
                        FROM aibom_vulnerabilities GROUP BY component_name
                    )
                    SELECT v.component_name, v.vuln_id, v.severity, v.score, v.summary, v.refs_json, v.purl
                    FROM aibom_vulnerabilities v
                    JOIN latest l ON v.component_name = l.component_name AND v.scan_time = l.latest_time
                    ORDER BY v.component_name,
                        CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                                        WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
                        v.vuln_id
                    LIMIT 1000
                ''').fetchall()
                conn.close()
                vulns_by_component: dict = {}
                for v in vuln_rows:
                    refs = []
                    try:
                        refs = json.loads(v[5] or '[]')
                    except Exception:
                        pass
                    vulns_by_component.setdefault(v[0], []).append({
                        'id': v[1], 'severity': v[2], 'score': v[3],
                        'summary': v[4], 'references': refs, 'purl': v[6],
                    })
                components = []
                for r in rows:
                    components.append({
                        'scan_time': r[0], 'name': r[1], 'category': r[2], 'description': r[3],
                        'detection': r[4], 'location': r[5], 'evidence': r[6],
                        'vulnerabilities': vulns_by_component.get(r[1], []),
                    })
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
            # Multi-select type filter: ?types=EXEC,FORK,is_agent — OR semantics
            # within types; AND with `q`. The pseudo-type `is_agent` matches
            # events flagged is_agent=True. Empty `types` = no type filter.
            types_raw = params.get('types', [''])[0].strip()
            selected_types = {t.strip() for t in types_raw.split(',') if t.strip()}
            agent_filter = 'is_agent' in selected_types
            real_types = selected_types - {'is_agent'}

            def _matches(e):
                if selected_types:
                    if not ((agent_filter and e.get('is_agent'))
                            or (e.get('type') in real_types)):
                        return False
                if search:
                    haystack = (e.get('args','') + ' ' + e.get('binary','') + ' '
                                + e.get('source','') + ' ' + e.get('type','') + ' '
                                + e.get('policy','')).lower()
                    if search not in haystack:
                        return False
                return True

            with memory_lock:
                filtered = [e for e in memory_buffer if _matches(e)]
                buf_total = len(memory_buffer)
            # Last 1000, newest first
            display = filtered[-1000:]
            display = list(reversed(display))
            with lock:
                d = {'events': display, 'total': buf_total, 'filtered': len(filtered),
                     'stats':{'total_events':stats['total_events'],'exec_count':stats['exec_count'],'kprobe_count':stats['kprobe_count'],'exit_count':stats['exit_count'],'aetherclaude_events':stats['aetherclaude_events'],'network_connections':stats['network_connections'],'alert_count':len(stats['alerts']),'policy_hits':dict(stats['policy_hits']),'binaries_seen':dict(stats['binaries_seen']),'alerts':list(stats['alerts']),'suppressed':stats['suppressed'],'tokens':{'input':token_stats['input'],'output':token_stats['output'],'cache_read':token_stats['cache_read'],'cache_create':token_stats['cache_create'],'messages':token_stats['messages'],'total':token_stats['input']+token_stats['output'],'estimated_cost_usd':round(token_stats['input']/1e6*15+token_stats['output']/1e6*75,2)},'tools':{'total':tool_stats['total'],'breakdown':tool_stats['breakdown']}},'mcp_scan_details':ring_stats.get('r6_mcp_details',[]),'rings':dict(ring_stats)}
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Access-Control-Allow-Origin','*');self.end_headers()
            self._send_json(d)
        elif self.path.startswith('/api/ring-events'):
            # Per-ring "show me recent events" endpoint backing the
            # showRingEvents() modal. Queries events.db directly (not the
            # in-memory ring buffer) so a dashboard restart doesn't clear
            # the modal contents.
            #
            # Optional filters (added to keep modal focused per ring):
            #   policy=X    exact match on events.policy (e.g. 'domain-filter'
            #               for tinyproxy denials — strips the ALLOWED noise)
            #   type=X      exact match on events.type
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            source = params.get('source', [''])[0].strip()
            policy_filter = params.get('policy', [''])[0].strip()
            type_filter = params.get('type', [''])[0].strip()
            try:
                limit = min(int(params.get('limit', ['100'])[0]), 1000)
            except ValueError:
                limit = 100
            if not source:
                self.send_response(400); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'events': [], 'total': 0, 'error': 'source param required'})
            else:
                try:
                    where_parts = ['source = ?']
                    sql_args = [source]
                    if policy_filter:
                        where_parts.append('policy = ?')
                        sql_args.append(policy_filter)
                    if type_filter:
                        where_parts.append('type = ?')
                        sql_args.append(type_filter)
                    where_sql = ' AND '.join(where_parts)
                    conn = sqlite3.connect(EVENTS_DB)
                    rows = conn.execute(
                        'SELECT timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id '
                        f'FROM events WHERE {where_sql} ORDER BY id DESC LIMIT ?',
                        sql_args + [limit]
                    ).fetchall()
                    total = conn.execute(
                        f'SELECT COUNT(*) FROM events WHERE {where_sql}', sql_args
                    ).fetchone()[0]
                    conn.close()
                    events = [{
                        'time': r[0], 'type': r[1], 'uid': r[2], 'binary': r[3],
                        'args': r[4], 'policy': r[5], 'is_agent': bool(r[6]),
                        'source': r[7], 'trace_id': r[8],
                    } for r in rows]
                    self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Access-Control-Allow-Origin', '*'); self.end_headers()
                    self._send_json({'events': events, 'total': total, 'source': source})
                except Exception as ex:
                    self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                    self._send_json({'events': [], 'total': 0, 'error': str(ex)})
        elif self.path.startswith('/api/agent-walk-traces'):
            # List recent traces for the picker dropdown. One row per
            # distinct trace_id, with summary (event count, time bounds,
            # webhook event type if available).
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            limit = min(int(params.get('limit', ['25'])[0]), 100)
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    "SELECT trace_id, "
                    "       MIN(timestamp) AS first_ts, "
                    "       MAX(timestamp) AS last_ts, "
                    "       COUNT(*) AS event_count, "
                    "       (SELECT args FROM events e2 "
                    "        WHERE e2.trace_id = events.trace_id AND e2.type='WEBHOOK' "
                    "        LIMIT 1) AS webhook_summary, "
                    "       (SELECT binary_name FROM events e3 "
                    "        WHERE e3.trace_id = events.trace_id AND e3.type='WEBHOOK' "
                    "        LIMIT 1) AS webhook_binary "
                    "FROM events "
                    "WHERE trace_id IS NOT NULL AND LENGTH(trace_id) > 8 "
                    "GROUP BY trace_id "
                    "HAVING event_count > 5000 "
                    "ORDER BY first_ts DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                conn.close()
                traces = [{
                    'trace_id': r[0], 'first_ts': r[1], 'last_ts': r[2],
                    'event_count': r[3],
                    'summary': r[4] or '(no webhook event)',
                    'binary': r[5] or '',
                } for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'traces': traces})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'traces': [], 'error': str(ex)})
        elif self.path.startswith('/api/agent-walk'):
            # All events for one trace, ordered by timestamp. Plus a
            # classification of which of the 9 walk stages each event
            # belongs to — done server-side so the JS doesn't have to
            # carry the rules.
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            trace_id = params.get('trace', [''])[0].strip()
            if not trace_id:
                self.send_response(400); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'error': 'trace param required'})
                return

            def classify_stage(typ, src, args, binary):
                """Return 1..10 for the 10 walk stages; 0 if uncategorized.
                Order matters — first match wins. The classifier is keyed
                off observed real-trace shapes (see project_agent_walk_demo
                memory for sample rows). Stage 0 events are filtered out
                of the response below."""
                args = (args or '').lower()
                src = (src or '').lower()
                binary = (binary or '').lower()
                # 1. Webhook arrival
                if typ == 'WEBHOOK':
                    return 1
                # 8. Prompt / Response — actual content of the LLM exchange
                # (claude-transcript PROMPT/RESPONSE). DC's audit rows that
                # describe the prompt/response (llm_prompt, llm_response,
                # userpromptsubmit) stay at Stage 6 with the rest of the
                # DefenseClaw observability stream — caught by the DC
                # catch-all further down.
                if src == 'claude-transcript' and typ in ('PROMPT', 'RESPONSE'):
                    return 8
                # 5. Claude Code — session lifecycle (DC sessionstart) and
                # every action Claude takes after a prompt is in flight:
                # tool calls (Bash, Read, Edit, Write, Grep, Glob, WebFetch,
                # ToolSearch, TodoWrite, Task, Agent, Skill, AskUserQuestion,
                # TaskStop) and claude:MCP read calls. Prompt + response
                # content lives at stage 8 above; DC verdicts at stage 6.
                if src == 'defenseclaw' and (
                        'sessionstart' in args or 'session_start' in args):
                    return 5
                if src == 'claude-code' and typ == 'TOOL' and binary.startswith('claude:'):
                    # claude:MCP write ops are a publish moment (stage 9);
                    # everything else (including claude:MCP reads) is a
                    # Claude action.
                    if binary == 'claude:mcp' and any(t in args for t in (
                            'comment_on_', 'create_pr', 'close_issue',
                            'create_pull_request', 'create_pr_review',
                            'comment_on_discussion', 'create_release',
                            'add_labels', 'remove_label')):
                        return 9
                    return 5
                # 10. Cleanup / audit fan-out — DC lifecycle stop events
                # only (the daemon emits 'gateway completed' for every
                # verdict, which is NOT cleanup; restrict to explicit
                # stop/end markers).
                if src == 'defenseclaw' and any(t in args for t in (
                        'sessionend', 'session_end', 'sidecar stop',
                        'gateway stop', 'sink_health stop')):
                    return 10
                # 9. GitHub publish via MCP — write ops only
                if typ == 'MCP' and any(t in args for t in (
                        'comment_on_', 'create_pr', 'close_issue',
                        'create_pull_request', 'create_pr_review',
                        'comment_on_discussion', 'create_release',
                        ' post ', ' put ', ' patch ', ' delete ',
                        'post /repos', 'put /repos', 'patch /repos',
                        'delete /repos')):
                    return 9
                # 7. MCP — server-side MCP activity (the MCP server itself
                # writing to its audit log when handling a request).
                # Distinct from claude:MCP which is the Claude-side
                # invocation (handled in stage 5 above for reads, stage
                # 9 for writes).
                if typ == 'MCP':
                    return 7
                # 4. Scanning — skill-scanner + mcp-scanner specifically.
                # These are Cisco AI Defense's pre-flight scanners that
                # examine skills and MCP catalogs for malicious patterns
                # (prompt injection, tool poisoning) before any agent
                # activity. Other scanners (codeguard, prompt-scanner)
                # are conceptually different and go elsewhere — codeguard
                # to stage 6 (it's tool-call code validation) and
                # prompt-scanner to stage 5 (it scans the prompt about
                # to be sent to the model). Must come BEFORE stage 6
                # because DC's 'gateway completed' catch-all there
                # would otherwise swallow scan_finding rows.
                # Codeguard is structurally another Cisco AI Defense scanner
                # — it static-analyzes changed source files with the same
                # CG-* rule set (CG-CRED, CG-EXEC, CG-NET, …). Same family
                # as skill-scanner / mcp-scanner / prompt-scanner / vt-scan,
                # so route to Stage 4 alongside them. Its own type='GUARD'
                # is unique to codeguard, so the type check stays safe.
                if src in ('skill-scan', 'mcp-scan', 'vt-scan', 'prompt-scan', 'codeguard'):
                    return 4
                if typ in ('SCAN', 'GUARD') and binary in ('skill-scanner', 'mcp-scanner', 'vt-scan', 'prompt-scanner', 'codeguard'):
                    return 4
                # DC audit rows describing scanner activity (skill/mcp/
                # prompt/codeguard/plugin/scan_finding) stay in Stage 6
                # with the rest of the DefenseClaw observability stream —
                # the canonical scanner-output rows already populate
                # Stage 4 via the source/binary checks above.
                # 6. Tool calls — DC verdict / tool-hook events for
                # non-MCP tools (Bash, Read, Edit, Grep, …). The DC
                # daemon emits 'gateway completed — action=…' per
                # PreToolUse/PostToolUse hook.
                if src == 'defenseclaw' and (
                        'pretooluse' in args or 'posttooluse' in args
                        or 'tool' in args
                        or 'action=' in args or 'verdict' in args
                        or 'gateway completed' in args):
                    return 6
                # 2. Orchestrator — run boundaries (agent-run start/stop)
                # plus the orchestrator's own state-machine and substep
                # work (orch-state, orch-transition, orch-skip, orch-push,
                # orch-pr, orch-validate, orch-claude-start, …). All emit
                # as source='skill-dispatch' with binary='skill:orch-*' or
                # 'skill:agent-run'.
                if src == 'skill-dispatch' and (
                        'agent-run' in binary or 'orch-' in binary):
                    return 2
                # 3. Skill selection — every other skill-dispatch event
                if src == 'skill-dispatch':
                    return 3
                # Uncategorized — eslogger process events, tinyproxy
                # connections, etc. Filtered out of the swimlane below.
                return 0

            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    "SELECT timestamp, type, uid, binary_name, args, policy, "
                    "       is_agent, source, trace_id "
                    "FROM events WHERE trace_id = ? ORDER BY timestamp ASC, id ASC",
                    (trace_id,)
                ).fetchall()
                conn.close()
                # Build the list, then filter to classified-only. Per
                # design: the swimlane shows the canonical 9-stage flow,
                # not raw process noise. Dropped count reported back so
                # the UI can show "filtered N background events" if
                # needed.
                all_events = []
                for r in rows:
                    ts, typ, uid, binary, args, policy, is_agent, source, tid = r
                    all_events.append({
                        'time': ts, 'type': typ, 'uid': uid, 'binary': binary,
                        'args': args, 'policy': policy,
                        'is_agent': bool(is_agent), 'source': source,
                        'trace_id': tid,
                        'stage': classify_stage(typ, source, args, binary),
                    })
                events = [e for e in all_events if e['stage'] > 0]
                dropped = len(all_events) - len(events)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({
                    'trace_id': trace_id,
                    'events': events,
                    'first_ts': events[0]['time'] if events else None,
                    'last_ts': events[-1]['time'] if events else None,
                    'event_count': len(events),
                    'background_dropped': dropped,
                })
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'events': [], 'error': str(ex)})
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
                    SELECT ia.issue_number, ia.action, ia.state, ia.outcome, ia.detail, ia.created_at || '.000Z'
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
        elif self.path == '/defenseclaw-webhook':
            # DefenseClaw audit-sink webhook receiver. The gateway POSTs
            # newline-delimited JSON in v7 schema (one event per line) to
            # this endpoint. Verify the shared bearer (from env), then
            # convert each event into a source=defenseclaw event in the
            # stream — same shape the tail_defenseclaw_audit thread
            # produces, so they merge cleanly.
            try:
                expected = os.environ.get('DEFENSECLAW_DASHBOARD_BEARER', '').strip()
                got = self.headers.get('Authorization', '')
                if expected:
                    if not got.startswith('Bearer '):
                        self.send_response(401); self.end_headers()
                        self.wfile.write(b'Missing bearer'); return
                    if got[7:] != expected:
                        self.send_response(401); self.end_headers()
                        self.wfile.write(b'Invalid bearer'); return
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace')
                count = 0
                for line in body.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = rec.get('ts', rec.get('timestamp', ''))[:19]
                    etype = rec.get('event_type', rec.get('action', 'unknown'))
                    args_text = ''
                    policy = ''
                    if isinstance(rec.get('lifecycle'), dict):
                        lc = rec['lifecycle']
                        args_text = f"{lc.get('subsystem','?')} {lc.get('transition','?')}"
                    elif isinstance(rec.get('verdict'), dict):
                        v = rec['verdict']
                        args_text = f"{v.get('action','?')} — {v.get('reason','')[:80]}"
                        policy = v.get('rule_pack', '')
                    elif isinstance(rec.get('error'), dict):
                        e = rec['error']
                        args_text = f"{e.get('code','ERROR')}: {e.get('subsystem','?')}"
                        policy = e.get('code', '')
                    elif isinstance(rec.get('scan'), dict):
                        s = rec['scan']
                        args_text = f"{s.get('scanner','?')} → {s.get('result','?')}"
                        policy = s.get('scanner', '')
                    else:
                        args_text = etype
                    # See tail_defenseclaw_audit — DC's run_id is the
                    # daemon's lifetime ID, not the orch's trace_id. Skip
                    # extraction; let active-trace fallback handle it.
                    entry = {
                        'time': ts,
                        'type': 'DEFENSE',
                        'uid': 965,
                        'binary': 'defenseclaw-webhook',
                        'args': args_text,
                        'policy': policy,
                        'is_agent': True,
                        'source': 'defenseclaw',
                    }
                    append_event(entry)
                    count += 1
                self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps({'accepted': count}).encode())
            except Exception as ex:
                self.send_response(500); self.end_headers()
                self.wfile.write(f'error: {ex}'.encode())
            return
        elif self.path == '/webhook':
            import hmac, hashlib, uuid
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
            # Parse event payload first — we need the issue/PR number to
            # derive the per-issue lock_key before deciding whether to
            # burst-adopt or mint a fresh trace_id.
            event_type = self.headers.get('X-GitHub-Event', 'unknown')
            try:
                payload = json.loads(body)
            except:
                self.send_response(400); self.end_headers(); self.wfile.write(b'Bad JSON'); return
            action = payload.get('action', '')
            # Compute lock_key — 'issue-N' / 'pr-N' / 'disc-N' / 'global'.
            # Webhooks for the same lock_key serialize via per-issue
            # lockfile in run-agent.sh; webhooks for different keys run
            # in parallel orchestrators. The key is also used to scope
            # per-key state files so parallel orchs don't fight over a
            # single global trace-id / trigger-event / active-trace file.
            lock_key = 'global'
            if event_type in ('issues', 'issue_comment'):
                num = (payload.get('issue') or {}).get('number')
                if num: lock_key = f'issue-{num}'
            elif event_type in ('pull_request', 'pull_request_review'):
                num = (payload.get('pull_request') or {}).get('number')
                if num: lock_key = f'pr-{num}'
            elif event_type in ('discussion', 'discussion_comment'):
                num = (payload.get('discussion') or {}).get('number')
                if num: lock_key = f'disc-{num}'
            # Burst-adopt: if an orchestrator is already running for THIS
            # lock_key, reuse its trace_id rather than minting fresh.
            # Different-key webhooks proceed normally and spawn their own
            # parallel orchestrator (no burst, no adopt).
            trace_id = None
            adopted_running = False
            lockfile = f'/tmp/aetherclaude-{lock_key}.lock'
            active_trace_path = f'/Users/aetherclaude/state/active-trace-id.{lock_key}'
            try:
                with open(lockfile) as _lf:
                    pid = int(_lf.read().strip())
                os.kill(pid, 0)
                with open(active_trace_path) as _tf:
                    running = _tf.read().strip()
                if running and len(running) > 8:
                    trace_id = running
                    adopted_running = True
            except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError):
                pass
            if not trace_id:
                trace_id = self.headers.get('X-GitHub-Delivery') or str(uuid.uuid4())
            # Mark this trace active so events that lack an explicit trace_id
            # but arrive while the orchestrator run is in flight get tagged.
            global _active_trace_id, _active_trace_started_ts
            _active_trace_id = trace_id
            _active_trace_started_ts = time.time()
            _trace_prefix_to_full[trace_id[:8]] = trace_id
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
            elif event_type == 'check_run':
                cr = payload.get('check_run', {}) or {}
                summary = f"Check {cr.get('name','')[:40]} {action}: {cr.get('conclusion','')}"
            elif event_type == 'workflow_run':
                wr = payload.get('workflow_run', {}) or {}
                summary = f"Workflow {wr.get('name','')[:40]} {action}: {wr.get('conclusion','')}"
            elif event_type == 'release':
                rel = payload.get('release', {}) or {}
                summary = f"Release {rel.get('tag_name','')} {action}: {rel.get('name','')[:60]}"
            elif event_type == 'ping':
                self.send_response(200); self.end_headers(); self.wfile.write(b'pong'); return
            with lock:
                entry = {'time': now_utc_iso(), 'type': 'WEBHOOK', 'uid': 0,
                         'binary': f'github:{event_type}', 'args': summary,
                         'policy': '', 'is_agent': True, 'source': 'webhook',
                         'trace_id': trace_id}
                append_event(entry)
            # Skip events from our own bot to avoid loops
            sender = payload.get('sender', {}).get('login', '')
            # Check if the bot was @mentioned in a comment
            comment_body = payload.get('comment', {}).get('body', '') or ''
            is_mention = '@aethersdr-agent' in comment_body.lower() or '@aetherclaude' in comment_body.lower()
            if sender in ('AetherClaude', 'aethersdr-agent[bot]'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (own event)'); return
            # Allow maintainer events through if they @mention the bot
            # Maintainer-skip filter — the maintainer's everyday GitHub
            # activity (closing issues, comments without @mention)
            # shouldn't bounce the bot. Two exceptions: @mentions in
            # comments (handled by is_mention), and the
            # `aetherclaude-eligible` label add — that's the explicit
            # authorization signal for implement-fix and we must NOT
            # filter it out.
            maint_label = (payload.get('label') or {}).get('name', '')
            maint_eligibility_signal = (
                event_type == 'issues' and action == 'labeled'
                and maint_label == 'aetherclaude-eligible'
            )
            if sender == 'ten9876' and not is_mention and not maint_eligibility_signal:
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (maintainer)'); return
            # Skip irrelevant actions
            if event_type == 'issues' and action not in ('opened', 'edited', 'labeled', 'reopened', 'closed'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'issue_comment' and action != 'created':
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'pull_request' and action not in ('opened', 'synchronize', 'reopened', 'closed'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            # CI events: only react when a run has finished AND failed.
            # Started / in_progress / passed runs are noise.
            if event_type in ('check_run', 'workflow_run'):
                if action != 'completed':
                    self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
                conclusion_root = payload.get(event_type, {}) or {}
                if conclusion_root.get('conclusion') != 'failure':
                    self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (CI passed)'); return
            # Releases: only react when a release is actually published.
            if event_type == 'release' and action != 'published':
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            # Debounce — per lock_key so issue-X webhooks don't debounce
            # pr-Y or disc-Z. 60s window per key.
            now = time.time()
            last_for_key = _last_webhook_trigger_per_key.get(lock_key, 0)
            if not is_mention and now - last_for_key < 60:
                self.send_response(200); self.end_headers(); self.wfile.write(b'Debounced'); return
            _last_webhook_trigger_per_key[lock_key] = now
            # All state files are now scoped per lock_key so parallel
            # orchestrators (one per issue/PR) can each read their own
            # without racing on a shared global.
            # Write mention flag for orchestrator
            if is_mention:
                try:
                    mention_issue = payload.get('issue', payload.get('pull_request', {})).get('number', '')
                    with open(f'/Users/aetherclaude/state/mention.{lock_key}', 'w') as mf:
                        mf.write(str(mention_issue))
                except: pass
            # Stash the trigger event type so run-agent.sh can route to only
            # the relevant skills.
            # Format: "<event_type>:<action>" or "<event_type>:<action>:<label>"
            # for issues:labeled events.
            try:
                trigger_str = f"{event_type}:{action}"
                if event_type == 'issues' and action == 'labeled':
                    label_name = (payload.get('label') or {}).get('name', '')
                    if label_name:
                        trigger_str += f":{label_name}"
                with open(f'/Users/aetherclaude/state/trigger-event.{lock_key}', 'w') as tf:
                    tf.write(trigger_str)
            except: pass
            # Skip when adopted_running — the running orchestrator for
            # this same lock_key already has its trace_id, no need to
            # write or spawn again.
            if not adopted_running:
                try:
                    with open(f'/Users/aetherclaude/state/trace-id.{lock_key}', 'w') as tf:
                        tf.write(trace_id)
                except: pass
            # Trigger the orchestrator. Direct subprocess.Popen instead of
            # `launchctl kickstart` because launchd enforces one-instance-
            # per-service, which would block parallelism. Forking
            # run-agent.sh directly lets multiple per-issue orchestrators
            # run concurrently. lock_key is passed as argv so run-agent.sh
            # knows which scoped state files to read.
            if not adopted_running:
                try:
                    import subprocess
                    subprocess.Popen(
                        ['/Users/aetherclaude/bin/run-agent.sh', lock_key],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    with lock:
                        entry = {'time': now_utc_iso(), 'type': 'WEBHOOK', 'uid': 0,
                                 'binary': 'trigger', 'args': f'Agent triggered ({lock_key}) by {event_type}: {summary[:60]}',
                                 'policy': '', 'is_agent': True, 'source': 'webhook',
                                 'trace_id': trace_id}
                        append_event(entry)
                except: pass
                self.send_response(200); self.end_headers(); self.wfile.write(b'Triggered')
            else:
                # Burst-adopted into the same-key orch already running.
                with lock:
                    entry = {'time': now_utc_iso(), 'type': 'WEBHOOK', 'uid': 0,
                             'binary': 'trigger', 'args': f'Burst-adopted into running {lock_key} trace ({event_type}: {summary[:50]})',
                             'policy': '', 'is_agent': True, 'source': 'webhook',
                             'trace_id': trace_id}
                    append_event(entry)
                self.send_response(200); self.end_headers(); self.wfile.write(b'Adopted')
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
    threading.Thread(target=tail_defenseclaw_audit,args=(DEFENSECLAW_AUDIT_LOG,),daemon=True).start()
    threading.Thread(target=tail_claude_transcripts,daemon=True).start()
    threading.Thread(target=tail_tinyproxy_log,daemon=True).start()
    for target,fn in [(a.log,tail_log),(VALIDATION_LOG,tail_validation_log),(MCP_AUDIT_LOG,tail_mcp_audit)]:
        threading.Thread(target=fn,args=(target,),daemon=True).start()
    threading.Thread(target=scan_tokens,daemon=True).start()
    threading.Thread(target=scan_rings,daemon=True).start()
    threading.Thread(target=db_batch_writer,daemon=True).start()
    threading.Thread(target=db_pruner,daemon=True).start()
    threading.Thread(target=db_trace_backfill_correlator,daemon=True).start()
    threading.Thread(target=track_active_trace,daemon=True).start()
    s=ThreadingHTTPServer((a.bind,a.port),H);print(f"Dashboard at http://{a.bind}:{a.port}")
    try:s.serve_forever()
    except KeyboardInterrupt:print("\nShutdown")

if __name__=='__main__':main()
