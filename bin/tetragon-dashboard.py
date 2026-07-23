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
AI-Agent Defense-in-Depth Dashboard v4
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

# Anthropic Max subscription. Bills on day SUBSCRIPTION_BILL_DAY of each
# month for SUBSCRIPTION_AMOUNT_USD. The dashboard's ROI panel shows two
# views: "This Cycle" (since the most-recent bill day) and "Lifetime"
# (since the first bill cycle). Override via env if billing terms change.
SUBSCRIPTION_BILL_DAY    = int(os.environ.get('CLAUDE_MAX_BILL_DAY',    4))
SUBSCRIPTION_AMOUNT_USD  = float(os.environ.get('CLAUDE_MAX_AMOUNT_USD', 200))
# Optional explicit subscription start date (YYYY-MM-DD). When unset,
# auto-discovered as the most-recent bill day on or before the oldest
# session JSONL's mtime.
SUBSCRIPTION_START_DATE  = os.environ.get('CLAUDE_MAX_START_DATE', '')
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
# graphify writes its self-contained viz inside the source tree it
# analyzes. We serve it via /codegraph/graphify so the dashboard's
# "Graphify" view mode can load it in an iframe.
GRAPHIFY_OUT_DIR = '/Users/aetherclaude/workspace/AetherSDR/src/graphify-out'
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

# Set of trace_ids that contain at least one source='claude-code' event.
# Populated lazily by append_event as events stream in, plus a one-time
# startup warm-up from the events DB. Used by /api/agent-walk-traces to
# hide skip-only traces from the picker dropdown — those traces have no
# review/comment to replay, just a flat pre-flight swimlane.
# In-memory cache rather than a correlated subquery on the hot events
# table (the subquery approach caused "database is locked" errors and
# 9s timeouts on every picker request — reverted in f273149).
_claude_active_traces = set()
_claude_active_lock = threading.Lock()

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
_last_antares_mtime = 0.0

# 2-tier ring buffer: memory_buffer is the single source of truth
MEMORY_BUFFER_MAX = 10000
memory_buffer = []  # Ordered by insertion time, newest at end
memory_lock = threading.Lock()

# Rate-limited logger for swallowed exceptions on structural paths (DB
# writes, background-thread outer loops, webhook state writes). A silent
# failure in one of these is the class of bug behind the events.db
# corruption crash-loop and the dropped-CI-webhook regression. Logged to
# stderr (-> dashboard-error.log), at most once per `every` seconds per
# call-site so a recurring fault surfaces without flooding the log. Hot
# per-line parse skips are deliberately left silent (expected + noisy).
_err_log_last = {}
_err_log_lock = threading.Lock()

def _log_exc(where, exc=None, every=60.0):
    now = time.monotonic()
    with _err_log_lock:
        if now - _err_log_last.get(where, 0.0) < every:
            return
        _err_log_last[where] = now
    try:
        detail = ('%s: %s' % (type(exc).__name__, exc)) if exc is not None else ''
        print('[dash-err] %s %s' % (where, detail), file=sys.stderr, flush=True)
    except Exception:
        pass

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
    # Webhook secret. Guard against an unset/empty secret: re.compile('') is a
    # zero-width pattern that matches at EVERY position, turning each event's
    # text into ***a***b***c***… in any environment without the secret (local
    # testing, fresh installs). Skip the pattern entirely when empty.
    *([(_re.compile(_re.escape(WEBHOOK_SECRET)), '***')] if WEBHOOK_SECRET else []),
    # Galileo API key printed alongside its var name (no stable prefix, so scope
    # to the assignment form — matches the run-agent.sh JSONL scrubber).
    (_re.compile(r'(GALILEO_API_KEY["\'= :]*)([A-Za-z0-9_\-]{20,})', _re.IGNORECASE), r'\1***'),
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
    # Mark trace as having claude activity (powers /api/agent-walk-traces
    # picker filter — skip-only traces stay hidden). Cheap: set add +
    # lock acquire on a small hot path.
    if entry.get('source') == 'claude-code':
        tid = entry.get('trace_id')
        if tid:
            with _claude_active_lock:
                _claude_active_traces.add(tid)
    with memory_lock:
        memory_buffer.append(entry)
        if len(memory_buffer) > MEMORY_BUFFER_MAX:
            del memory_buffer[0]
    with db_write_lock:
        db_write_queue.append(entry)
    # Fan out to any live-stream SSE subscribers. Non-blocking;
    # drops on backpressure rather than stalling producers. Wrapped
    # in try/except so a buggy subscriber can't take down the tail_*
    # producer threads — event flow to the DB and dashboard must be
    # preserved above all else.
    try:
        _agent_walk_publish(entry)
    except Exception:
        pass
    # Generate alerts for security events
    etype = entry.get('type', '')
    if etype == 'BLOCK':
        stats['alerts'].append({'time': entry.get('time', ''), 'msg': f"FIREWALL: {entry.get('args', '')}", 'severity': 'high'})
    elif entry.get('policy') == 'domain-filter':
        stats['alerts'].append({'time': entry.get('time', ''), 'msg': f"PROXY: {entry.get('args', '')}", 'severity': 'high'})
token_stats = {
    'input': 0, 'output': 0, 'cache_read': 0, 'cache_create': 0, 'messages': 0,
    'cycle_input': 0, 'cycle_output': 0, 'cycle_cache_read': 0,
    'cycle_cache_create': 0, 'cycle_messages': 0,
    'cycle_start_iso': '', 'subscription_amount_usd': SUBSCRIPTION_AMOUNT_USD,
    'subscription_cycles_paid': 1, 'subscription_start_iso': '',
    'cost': 0.0, 'cycle_cost': 0.0,
}
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

# ── Agent Walk live-stream subscribers ──────────────────────────────────
# Server-Sent-Events fan-out for /api/agent-walk-stream. Each subscriber
# holds a bounded Queue; append_event() pushes new entries into matching
# queues without blocking (put_nowait drops on backpressure). The
# endpoint thread drains its queue and writes to the client socket.
# Heartbeat-driven, per Foundry-security-spec Principle III ("Liveness
# By Heartbeat, Never By Clock") — the previous polling implementation
# violated this by re-fetching every 2s regardless of whether anything
# had changed.
import queue as _queue_mod
_agent_walk_subscribers = []  # list of {trace_id, q}
_agent_walk_sub_lock = threading.Lock()
_agent_walk_known_traces = set()  # trace_ids we've seen at least once
_agent_walk_known_lock = threading.Lock()

def _agent_walk_publish(entry):
    """Push a freshly-appended event to any matching SSE subscribers.
    Called from inside append_event(); MUST be non-blocking — the
    producers are tail_* threads + the orchestrator's webhook path and
    cannot afford to wait on a slow client. Uses put_nowait; drops on
    backpressure."""
    tid = entry.get('trace_id')
    if not tid:
        return
    # First time we've seen this trace_id? Capture for related-trace
    # notifications to other subscribers.
    with _agent_walk_known_lock:
        is_new_trace = tid not in _agent_walk_known_traces
        if is_new_trace:
            _agent_walk_known_traces.add(tid)
            # Cap the set to prevent unbounded growth — drop oldest
            # half (heuristic, not strictly LRU; good enough for traces
            # which rotate naturally).
            if len(_agent_walk_known_traces) > 10000:
                # Keep half — set iteration order is insertion order in
                # CPython 3.7+, so popping from the front drops oldest.
                to_drop = len(_agent_walk_known_traces) // 2
                it = iter(_agent_walk_known_traces)
                for _ in range(to_drop):
                    _agent_walk_known_traces.discard(next(it))
    stage = _classify_agent_walk_stage(
        entry.get('type'), entry.get('source'),
        entry.get('args'), entry.get('binary'))
    with _agent_walk_sub_lock:
        for sub in _agent_walk_subscribers:
            if sub['trace_id'] == tid:
                if stage > 0:
                    payload = {
                        'kind': 'event',
                        'entry': dict(entry, stage=stage),
                    }
                    try:
                        sub['q'].put_nowait(payload)
                    except _queue_mod.Full:
                        pass
            elif is_new_trace:
                payload = {
                    'kind': 'related',
                    'trace_id': tid,
                    'first_ts': entry.get('time', ''),
                    'summary': (entry.get('args') or '')[:120],
                }
                try:
                    sub['q'].put_nowait(payload)
                except _queue_mod.Full:
                    pass

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
        # Posture snapshots: keep 30 days regardless of DB size (tiny table,
        # cheap indexed DELETE each interval).
        try:
            conn = sqlite3.connect(EVENTS_DB)
            conn.execute("DELETE FROM posture_snapshots WHERE ts < datetime('now','-30 days')")
            conn.commit(); conn.close()
        except Exception:
            pass
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
            try:
                conn.execute('PRAGMA synchronous=NORMAL')
            except sqlite3.Error:
                pass
            conn.executemany(
                'INSERT INTO events (timestamp, type, uid, binary_name, args, policy, is_agent, source, trace_id) VALUES (?,?,?,?,?,?,?,?,?)',
                [(e.get('time',''), e.get('type',''), e.get('uid',''),
                  e.get('binary',''), e.get('args',''), e.get('policy',''),
                  e.get('is_agent', False), e.get('source',''), e.get('trace_id')) for e in batch]
            )
            conn.commit()
            conn.close()
        except Exception as _e: _log_exc('db_batch_writer', _e)

def init_db():
    conn = sqlite3.connect(EVENTS_DB)
    # WAL lets the batch writer and the many read endpoints proceed
    # concurrently instead of serializing on a single-writer lock; the
    # mode is a persistent property of the DB file, so every later
    # connection inherits it. synchronous=NORMAL is the standard
    # durable-enough pairing for WAL.
    try:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
    except sqlite3.Error:
        pass
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
    conn.execute('''CREATE TABLE IF NOT EXISTS trace_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id TEXT,
        timestamp TEXT,
        input INTEGER, output INTEGER,
        cache_read INTEGER, cache_create INTEGER,
        model TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_tt_trace ON trace_tokens(trace_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_tt_ts ON trace_tokens(timestamp)')
    try:
        conn.execute('ALTER TABLE trace_tokens ADD COLUMN model TEXT')
    except sqlite3.OperationalError as e:
        if 'duplicate column' not in str(e).lower():
            raise
    conn.execute('''CREATE TABLE IF NOT EXISTS codeguard_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT,
        rule_id TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        location TEXT,
        remediation TEXT,
        source TEXT DEFAULT 'agent',
        ref TEXT
    )''')
    # Migrate DBs created before the source/ref tagging (agent vs PR scans).
    _cg_cols = {r[1] for r in conn.execute('PRAGMA table_info(codeguard_findings)')}
    if 'source' not in _cg_cols:
        conn.execute("ALTER TABLE codeguard_findings ADD COLUMN source TEXT DEFAULT 'agent'")
    if 'ref' not in _cg_cols:
        conn.execute('ALTER TABLE codeguard_findings ADD COLUMN ref TEXT')
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
    # Antares Detector candidate files (Foundry Detector stage). One row per
    # candidate file the local Antares-1B model localized for an issue/PR.
    conn.execute('''CREATE TABLE IF NOT EXISTS detector_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        issue_number TEXT,
        cwe TEXT,
        verdict TEXT,
        file_path TEXT,
        rank INTEGER,
        rationale TEXT,
        commands_used INTEGER,
        trace_id TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_detector_scan_time ON detector_findings(scan_time)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_detector_issue ON detector_findings(issue_number)')
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
    # Galileo eval results — one row per live agent run (kind='run', forwarded to
    # Galileo as a trace) or per experiment aggregate (kind='experiment', scored
    # against a curated dataset by bin/run-eval.sh). trace_id joins to events for
    # deep-linking a score to the Agent Walk swimlane.
    conn.execute('''CREATE TABLE IF NOT EXISTS eval_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        trace_id TEXT,
        flow TEXT,
        ref TEXT,
        status TEXT,
        kind TEXT,
        galileo_trace_url TEXT,
        scores_json TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_eval_trace_id ON eval_results(trace_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_eval_ts ON eval_results(ts)')
    # Defense Posture history — one snapshot every ~300s from scan_rings
    # (288 rows/day, pruned >30d by db_pruner). Powers the exec view's
    # delta-vs-24h and the /api/trends posture series. ts uses the same
    # UTC 'YYYY-MM-DD HH:MM:SS' format as events.created_at so datetime()
    # comparisons work without normalization.
    conn.execute('''CREATE TABLE IF NOT EXISTS posture_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        score INTEGER,
        components_json TEXT
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_posture_ts ON posture_snapshots(ts)')
    conn.commit()
    conn.close()

# --- Galileo forwarding (dashboard-only; the sandboxed agent never does this) ---
# The dashboard is the ONLY component that holds GALILEO_API_KEY and reaches
# galileo.ai (it bypasses tinyproxy). The agent POSTs a run record to
# /api/eval-ingest over localhost and we forward it here as a Galileo trace.
GALILEO_PROJECT = os.environ.get('GALILEO_PROJECT', 'aetherclaude')
GALILEO_LOG_STREAM = os.environ.get('GALILEO_LOG_STREAM', 'agent-runs')

def _parse_claude_trace(path, max_chars=4000, max_spans=60):
    """Parse a Claude Code session transcript into an ordered agent trace.
    Returns {input, output, spans, in_tokens, out_tokens} where spans is an
    ordered list of per-turn LLM spans and tool spans:
      {'kind':'llm', input, output, model, in_tok, out_tok}
      {'kind':'tool', name, input, output, id}
    The transcript is newline-delimited JSON: {type: user|assistant,
    message: {role, model, content:[...], usage:{input_tokens,output_tokens}}}.
    tool_result blocks (in user messages) are matched back to their tool_use by
    id. Best-effort — returns a minimal structure on any problem so trace
    logging never breaks the ingest path."""
    first_user, last_assistant = '', ''
    spans, tool_results = [], {}
    in_tokens = out_tokens = 0
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
        # Pass 1: collect tool_result outputs keyed by tool_use_id
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            content = (rec.get('message') or {}).get('content')
            if isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and p.get('type') == 'tool_result' and p.get('tool_use_id'):
                        c = p.get('content')
                        txt = c if isinstance(c, str) else (json.dumps(c) if c is not None else '')
                        tool_results[p['tool_use_id']] = (txt or '')[:max_chars]
        # Pass 2: build ordered spans
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            msg = rec.get('message') or {}
            role = rec.get('type') or msg.get('role')
            content = msg.get('content')
            parts = content if isinstance(content, list) else ([{'type': 'text', 'text': content}] if isinstance(content, str) else [])
            if role == 'user':
                for p in parts:
                    if isinstance(p, dict) and p.get('type') == 'text' and p.get('text') and not first_user:
                        first_user = p['text'][:max_chars]
            elif role == 'assistant':
                usage = msg.get('usage') or {}
                it = int(usage.get('input_tokens', 0) or 0)
                ot = int(usage.get('output_tokens', 0) or 0)
                in_tokens += it
                out_tokens += ot
                model = msg.get('model') or 'claude-opus'
                texts = [p['text'] for p in parts if isinstance(p, dict) and p.get('type') == 'text' and p.get('text')]
                atext = ('\n'.join(texts))[:max_chars]
                if atext:
                    last_assistant = atext
                    if len(spans) < max_spans:
                        spans.append({'kind': 'llm', 'input': first_user or '(context)', 'output': atext,
                                      'model': model, 'in_tok': it, 'out_tok': ot})
                for p in parts:
                    if isinstance(p, dict) and p.get('type') == 'tool_use' and len(spans) < max_spans:
                        tid = p.get('id')
                        spans.append({'kind': 'tool', 'name': p.get('name', 'tool'),
                                      'input': json.dumps(p.get('input', {}))[:max_chars],
                                      'output': tool_results.get(tid, ''), 'id': tid})
    except Exception:
        pass
    return {'input': first_user, 'output': last_assistant, 'spans': spans,
            'in_tokens': in_tokens, 'out_tokens': out_tokens}

def galileo_forward(entry):
    """Log one agent run to Galileo as a multi-span trace. Returns a console URL
    or None. Swallows all errors (missing key, SDK not installed, network) so
    eval logging never blocks the ingest path — mirrors eslogger-bridge's
    fail-open. Follows the manual GalileoLogger pattern the Galileo quickstart
    prescribes for Anthropic: start_trace -> add_llm_span/add_tool_span per
    turn -> conclude -> flush."""
    if not os.environ.get('GALILEO_API_KEY') or os.environ.get('GALILEO_LOGGING_DISABLED'):
        return None
    try:
        from galileo import GalileoLogger
    except Exception as e:
        print(f'galileo_forward: SDK unavailable ({e})', file=sys.stderr)
        return None
    try:
        flow = entry.get('flow', 'other')
        ref = entry.get('ref', '')
        status = entry.get('status', 'ok')
        trace_id = entry.get('trace_id', '')
        t = _parse_claude_trace(entry.get('jsonl_path', ''))
        name = f'{flow}#{ref}' if ref else flow
        tags = [f'flow:{flow}', f'status:{status}'] + ([f'trace:{trace_id[:16]}'] if trace_id else [])
        meta = {'flow': flow, 'ref': str(ref), 'status': status, 'aether_trace_id': trace_id or '',
                'total_input_tokens': t['in_tokens'], 'total_output_tokens': t['out_tokens']}
        logger = GalileoLogger(project=GALILEO_PROJECT, log_stream=GALILEO_LOG_STREAM)
        logger.start_trace(input=(t['input'] or name), name=name, tags=tags, metadata=meta)
        step = 0
        for s in t['spans']:
            step += 1
            if s['kind'] == 'llm':
                logger.add_llm_span(input=(s['input'] or name), output=(s['output'] or '(no text)'),
                                    model=s['model'], num_input_tokens=s['in_tok'], num_output_tokens=s['out_tok'],
                                    total_tokens=(s['in_tok'] + s['out_tok']), name=f'turn-{step}', step_number=step)
            else:
                logger.add_tool_span(input=(s['input'] or '{}'), output=(s['output'] or ''),
                                     name=s['name'], tool_call_id=s.get('id'), step_number=step)
        if not t['spans']:
            # No transcript captured (e.g. run failed before writing JSONL) —
            # still log a one-span trace so the run is visible in Galileo.
            logger.add_llm_span(input=(t['input'] or name), output=f'[{status}] no transcript captured',
                                model='claude-opus', num_input_tokens=0, num_output_tokens=0)
        logger.conclude(output=(t['output'] or f'[{status}]'))
        logger.flush()
        # Best-effort console deep-link to the project/log-stream. The exact
        # per-trace URL isn't reliably returned by flush(); the log stream is
        # a stable, useful landing spot for the demo.
        return f'https://app.galileo.ai/project/{GALILEO_PROJECT}?logStream={GALILEO_LOG_STREAM}'
    except Exception as e:
        print(f'galileo_forward: log failed ({e})', file=sys.stderr)
        return None

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
    except Exception as _e: _log_exc('db_insert_event', _e)

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
    except Exception as _e:
        _log_exc('db_query_events', _e)
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
    except Exception as _e: _log_exc('db_purge_if_needed', _e)

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

# ── Defense Posture (exec view hero metric) ──────────────────────────────
# Composite 0–100 score over the nine defense controls. Unlike the ops-view
# tile colors (client-side rules on cumulative counters — sticky forever),
# these statuses are re-derived every cycle from 24h windows, so the score
# heals when the underlying condition clears. Weights favor the gates that
# actually block bad output (scanners, validation) over passive telemetry.
_posture_cache = {'ts': 0.0, 'data': {}}
_posture_last_snapshot = [0.0]
_trends_cache = {'ts': 0.0, 'data': None}  # /api/trends 60s server cache
_ci_last_fetch = [0.0]  # GitHub Actions runs fetch throttle (60s)

_POSTURE_WEIGHTS = {'r1': 1, 'r2': 1, 'r3': 1, 'r4': 1, 'r5': 1,
                    'r6': 3, 'r7': 2, 'r8': 3, 'r9': 2}
_STATUS_SCORE = {'green': 100, 'yellow': 60, 'red': 0}

def _posture_window_counts():
    """24h-window SQL counts feeding compute_posture. 60s TTL cache so the
    15s scan_rings cadence doesn't hammer the DB; all queries are indexed
    range scans except tiny-table scans (validation_runs)."""
    now = time.time()
    if _posture_cache['ts'] > now - 60 and _posture_cache['data']:
        return _posture_cache['data']
    data = {'r2_denied_24h': 0, 'r7_blocked_24h': 0,
            'guard_blocks_24h': 0, 'val_failed_24h': 0}
    try:
        conn = sqlite3.connect(EVENTS_DB, timeout=10)
        data['r2_denied_24h'] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE source='tinyproxy' "
            "AND policy='domain-filter' AND created_at>=datetime('now','-1 day')"
        ).fetchone()[0]
        data['r7_blocked_24h'] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE source='mcp' AND type='BLOCK' "
            "AND created_at>=datetime('now','-1 day')").fetchone()[0]
        data['guard_blocks_24h'] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE type='GUARD' "
            "AND created_at>=datetime('now','-1 day')").fetchone()[0]
        # run_time may be ISO ('T' separator) — normalize before comparing
        # against datetime()'s space-separated format. Tiny table, no index
        # concern.
        data['val_failed_24h'] = conn.execute(
            "SELECT COUNT(*) FROM validation_runs WHERE result='FAILED' "
            "AND replace(run_time,'T',' ')>=datetime('now','-1 day')").fetchone()[0]
        conn.close()
    except Exception:
        pass
    _posture_cache['ts'] = now
    _posture_cache['data'] = data
    return data

def compute_posture():
    """Score the nine controls (green=100 / yellow=60 / red=0, each with a
    human-readable reason), weighted-mean them into one 0–100 posture score,
    snapshot every ~300s, and return the payload the exec view renders.
    Call under `lock` (reads ring_stats)."""
    w = _posture_window_counts()
    rs = ring_stats
    rings = {}
    def st(key, status, reason):
        rings[key] = {'status': status, 'reason': reason}

    # r1 firewall: the control being ALIVE is the signal — blocked packets
    # are it working, never a penalty.
    try:
        with open('/Users/aetherclaude/logs/pf-blocked-count') as f:
            f.read()
        st('r1', 'green', 'pf active, counter readable')
    except Exception:
        st('r1', 'yellow', 'pf blocked-count unreadable')

    d = w['r2_denied_24h']
    if d == 0: st('r2', 'green', 'no proxy denials in 24h')
    elif d <= 10: st('r2', 'yellow', f'{d} proxy denial(s) in 24h')
    else: st('r2', 'red', f'{d} proxy denials in 24h (agent probing?)')

    if rs.get('agent_running') and not rs.get('r3_es_events'):
        st('r3', 'yellow', 'agent running but no OS telemetry')
    else:
        st('r3', 'green', 'OS telemetry flowing' if rs.get('r3_es_events') else 'agent idle')

    if rs.get('r4_protect_system') and rs.get('r4_no_new_privs') and rs.get('r4_private_tmp'):
        st('r4', 'green', 'sandbox flags enforced')
    else:
        st('r4', 'red', 'sandbox flag(s) missing')

    if rs.get('r5_denied_tools', 0) > 0:
        st('r5', 'green', f"{rs.get('r5_denied_tools')} tools deny-listed")
    else:
        st('r5', 'yellow', 'tool deny list not loaded')

    threats = rs.get('r6_mcp_threats', 0)
    skill_bad = 'threat' in str(rs.get('r6_skill_status', '')).lower() or \
                'unsafe' in str(rs.get('r6_skill_status', '')).lower()
    if threats > 0 or skill_bad:
        st('r6', 'red', f'{threats} MCP threat(s)' if threats else 'skill scanner findings')
    elif w['guard_blocks_24h'] > 0 or rs.get('r6_findings', 0) > 0:
        st('r6', 'yellow', f"{w['guard_blocks_24h']} guard block(s) 24h, "
                           f"{rs.get('r6_findings', 0)} finding(s)")
    else:
        st('r6', 'green', 'scanners clean')

    b = w['r7_blocked_24h']
    st('r7', 'green' if b == 0 else 'yellow',
       'no MCP blocks in 24h' if b == 0 else f'{b} MCP op(s) blocked in 24h')

    vf = w['val_failed_24h']
    if vf == 0: st('r8', 'green', 'no validation failures in 24h')
    elif vf <= 2: st('r8', 'yellow', f'{vf} validation failure(s) in 24h')
    else: st('r8', 'red', f'{vf} validation failures in 24h')

    # r9 human review: informational in v1 (cumulative GH counters can't
    # give a clean 24h signal); components_json preserves data to refine.
    st('r9', 'green', 'human review active')

    total_w = sum(_POSTURE_WEIGHTS.values())
    score = round(sum(_STATUS_SCORE[rings[k]['status']] * _POSTURE_WEIGHTS[k]
                      for k in _POSTURE_WEIGHTS) / total_w)

    # Snapshot every ~300s; delta vs the newest snapshot ≥24h old ("—" when
    # no history yet — never fake it).
    now = time.time()
    delta = None
    try:
        conn = sqlite3.connect(EVENTS_DB, timeout=10)
        if now - _posture_last_snapshot[0] >= 300:
            conn.execute('INSERT INTO posture_snapshots (ts, score, components_json) VALUES (?,?,?)',
                         (time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), score,
                          json.dumps(rings)))
            conn.commit()
            _posture_last_snapshot[0] = now
        row = conn.execute(
            "SELECT score FROM posture_snapshots WHERE ts<=datetime('now','-1 day') "
            "ORDER BY ts DESC LIMIT 1").fetchone()
        if row is not None:
            delta = score - row[0]
        conn.close()
    except Exception:
        pass

    return {'score': score, 'delta_24h': delta,
            'computed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'rings': rings}

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

                # Antares Detector: read the latest localization verdict.
                try:
                    ant_file = '/Users/aetherclaude/logs/antares-latest.json'
                    if os.path.exists(ant_file):
                        with open(ant_file) as af:
                            ant = json.load(af)
                        cands = ant.get('candidates', []) or []
                        ring_stats['r6_antares_candidates'] = len(cands)
                        ring_stats['r6_antares_verdict'] = ant.get('verdict', '')
                        ring_stats['r6_antares_last_issue'] = ant.get('issue', '')
                        global _last_antares_mtime
                        ant_mtime = os.path.getmtime(ant_file)
                        if ant_mtime != _last_antares_mtime:
                            _last_antares_mtime = ant_mtime
                            try:
                                dbc = sqlite3.connect(EVENTS_DB)
                                if cands:
                                    for i, fp in enumerate(cands):
                                        dbc.execute(
                                            'INSERT INTO detector_findings (issue_number, cwe, verdict, file_path, rank, rationale, commands_used, trace_id) '
                                            'VALUES (?,?,?,?,?,?,?,?)',
                                            (str(ant.get('issue', '')), ant.get('cwe', ''),
                                             ant.get('verdict', ''), fp, i + 1,
                                             ant.get('rationale', ''), ant.get('commands_used', 0),
                                             ant.get('trace_id', '')))
                                else:
                                    # record clean/no-candidate runs too (file_path NULL)
                                    dbc.execute(
                                        'INSERT INTO detector_findings (issue_number, cwe, verdict, commands_used, trace_id) '
                                        'VALUES (?,?,?,?,?)',
                                        (str(ant.get('issue', '')), ant.get('cwe', ''),
                                         ant.get('verdict', ''), ant.get('commands_used', 0),
                                         ant.get('trace_id', '')))
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
                                'https://api.github.com/repos/aethersdr/AetherSDR/pulls?state=open&per_page=100', headers=hdrs)
                            open_prs = json.loads(opener.open(req_open, timeout=10).read().decode())
                        except: pass
                        # Fetch closed/merged PRs
                        closed_prs = []
                        try:
                            req_closed = urllib.request.Request(
                                'https://api.github.com/repos/aethersdr/AetherSDR/pulls?state=closed&sort=updated&direction=desc&per_page=100', headers=hdrs)
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
                        # GitHub Actions CI runs (Run Success modal). Throttled
                        # to every ~60s — the r9 PR fetch above already rides
                        # each 15s cycle; CI results don't change faster than
                        # this. Compact fields only; rides /api/events via
                        # ring_stats like r9_pr_details.
                        if time.time() - _ci_last_fetch[0] >= 60:
                            try:
                                req_ci = urllib.request.Request(
                                    'https://api.github.com/repos/aethersdr/AetherSDR/actions/runs?per_page=40', headers=hdrs)
                                wf = json.loads(opener.open(req_ci, timeout=10).read().decode()).get('workflow_runs', [])
                                ring_stats['ci_runs'] = [{
                                    'name': w.get('name', ''),
                                    'title': (w.get('display_title') or '')[:80],
                                    'branch': w.get('head_branch', ''),
                                    'status': w.get('status', ''),
                                    'conclusion': w.get('conclusion'),
                                    'created_at': w.get('created_at', ''),
                                    'url': w.get('html_url', ''),
                                } for w in wf[:30]]
                                _ci_last_fetch[0] = time.time()
                            except: pass
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
                        gql_body = json.dumps({'query': 'query{repository(owner:"aethersdr",name:"AetherSDR"){discussions(first:20,orderBy:{field:UPDATED_AT,direction:DESC}){nodes{number title category{name} comments{totalCount}}}}}'}).encode()
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
                            # Legacy format ("Processing issue #N: <title>").
                            m = re.search(r'Processing issue #(\d+): (.+)', oline)
                            if m:
                                issue_titles[m.group(1)] = m.group(2)
                            # Current format ("Issue #N (<title>) — state: …").
                            m = re.search(r'Issue #(\d+) \(([^)]+)\)', oline)
                            if m:
                                issue_titles[m.group(1)] = m.group(2)
                            m = re.search(r'Responding to discussion #(\d+): (.+)', oline)
                            if m:
                                issue_titles['d' + m.group(1)] = m.group(2)
                            # PR review lines carry the PR title too (shared by
                            # number space with issues for the activity markers).
                            m = re.search(r'Reviewing PR #(\d+): (.+?) by @', oline)
                            if m:
                                issue_titles[m.group(1)] = m.group(2)
                    ring_stats['issue_titles'] = issue_titles
                except:
                    pass

                # Defense Posture — computed last so it sees this cycle's
                # fresh ring_stats; rides the /api/events payload via
                # 'rings': dict(ring_stats).
                try:
                    ring_stats['posture'] = compute_posture()
                except Exception as _pe:
                    _log_exc('compute_posture', _pe)

        except Exception as _e: _log_exc('scan_rings', _e)
        db_purge_if_needed(250)
        time.sleep(RING_REFRESH_SECS)

# ── Claude-active-trace cache warm-up ─────────────────────────────────────
# One-shot at startup: scan the events DB for trace_ids that have at
# least one claude-code event, seed _claude_active_traces. After warm-up
# the cache stays current via append_event. Bounded to recent 7 days to
# keep the warm-up bounded; the picker orders by first_ts DESC and shows
# recent traces, so older ones fall off the list naturally.
# Anthropic API-equivalent cost for an opus run. Mirrors bot-cost.py's
# PRICING (opus-4-8 / 4-7 — same rates). Includes cache_read and
# cache_create which the prior formula ignored — that under-attributed
# the lifetime API-equivalent cost by ~25% for typical agent workloads.
# Cache_create uses the 1-hour ephemeral rate (2.0x base input) — Claude
# Code defaults to 1h cache, confirmed by inspecting JSONL records
# (ephemeral_1h_input_tokens populated, 5m always 0).
# Per-model API rates -- ($/MTok: input, output, cache_read, cache_create),
# mirroring bot-cost.py PRICING. Used to price each agent-walk turn at the
# model it actually ran on (the corpus spans fable-5 / opus-4-7 / opus-4-8).
# Unknown or synthetic models fall back to Fable 5 (the current default).
_MODEL_RATES = {
    'claude-fable-5':    (10.0, 50.0, 1.00, 20.00),
    'claude-opus-4-8':   ( 5.0, 25.0, 0.50, 10.00),
    'claude-opus-4-7':   ( 5.0, 25.0, 0.50, 10.00),
    'claude-sonnet-4-6': ( 3.0, 15.0, 0.30,  6.00),
    'claude-haiku-4-5':  ( 1.0,  5.0, 0.10,  2.00),
}
_MODEL_RATES_DEFAULT = _MODEL_RATES['claude-fable-5']

def _turn_cost(model, inp, out, cr, cc):
    ri, ro, rcr, rcc = _MODEL_RATES.get(model or '', _MODEL_RATES_DEFAULT)
    return round(inp / 1e6 * ri + out / 1e6 * ro + cr / 1e6 * rcr + cc / 1e6 * rcc, 6)


def _api_equivalent_cost(inp, out, cache_read, cache_create):
    # API-equivalent cost at Fable 5 rates (model in use since the
    # 2026-06-10 cutover): input $10 / output $50 / cache-read $1.00 /
    # cache-write $20.00 per MTok.
    return round(
        inp/1e6 * 10.0 + out/1e6 * 50.0
      + cache_read/1e6 * 1.00 + cache_create/1e6 * 20.0, 2)

def warmup_claude_active_traces():
    time.sleep(2)  # let init_db / load_memory_buffer finish first
    try:
        conn = sqlite3.connect(EVENTS_DB, timeout=15.0)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)
                  ).strftime('%Y-%m-%dT%H:%M:%S')
        rows = conn.execute(
            "SELECT DISTINCT trace_id FROM events "
            "WHERE source = 'claude-code' "
            "  AND trace_id IS NOT NULL AND LENGTH(trace_id) > 8 "
            "  AND timestamp >= ?",
            (cutoff,)
        ).fetchall()
        conn.close()
        with _claude_active_lock:
            for r in rows:
                _claude_active_traces.add(r[0])
        print(f"warmup_claude_active_traces: seeded {len(rows)} trace_ids")
    except Exception as ex:
        # Warm-up failure is non-fatal — picker just shows fewer traces
        # initially and refills as new events come in.
        print(f"warmup_claude_active_traces failed: {ex}")

# ── Anthropic Max billing cycle helpers ───────────────────────────────────
# All math is in local time (the user's billing date is wall-clock local).
def _current_cycle_start(now=None):
    """Datetime of the most recent bill day at midnight local time. If
    today's day-of-month is >= SUBSCRIPTION_BILL_DAY the cycle started
    this month; otherwise it started on the bill day of the prior month."""
    now = now or datetime.now()
    if now.day >= SUBSCRIPTION_BILL_DAY:
        return now.replace(day=SUBSCRIPTION_BILL_DAY, hour=0, minute=0,
                           second=0, microsecond=0)
    prev_month_last = now.replace(day=1) - timedelta(days=1)
    return prev_month_last.replace(day=SUBSCRIPTION_BILL_DAY, hour=0, minute=0,
                                   second=0, microsecond=0)

def _discover_subscription_start():
    """Honor CLAUDE_MAX_START_DATE if set. Otherwise: walk session JSONLs,
    find the oldest mtime, round back to the most recent bill day on or
    before it. Cached for the process lifetime — bill-day boundary moves
    once a month, far slower than the dashboard's restart cadence."""
    if SUBSCRIPTION_START_DATE:
        try:
            d = datetime.strptime(SUBSCRIPTION_START_DATE, '%Y-%m-%d')
            return d.replace(hour=0, minute=0, second=0, microsecond=0)
        except ValueError:
            pass  # malformed — fall through to discovery
    oldest = None
    for f in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
        try:
            m = os.path.getmtime(f)
        except OSError:
            continue
        if oldest is None or m < oldest:
            oldest = m
    if oldest is None:
        return _current_cycle_start()
    dt = datetime.fromtimestamp(oldest)
    if dt.day >= SUBSCRIPTION_BILL_DAY:
        return dt.replace(day=SUBSCRIPTION_BILL_DAY, hour=0, minute=0,
                          second=0, microsecond=0)
    prev_month_last = dt.replace(day=1) - timedelta(days=1)
    return prev_month_last.replace(day=SUBSCRIPTION_BILL_DAY, hour=0, minute=0,
                                   second=0, microsecond=0)

def _bill_cycles_paid(start_date, now=None):
    """Number of $200 charges since start_date (inclusive of the first
    one on start_date). If today hasn't yet reached this month's bill
    day, this month's charge hasn't happened yet so subtract one."""
    now = now or datetime.now()
    months = (now.year - start_date.year) * 12 + (now.month - start_date.month) + 1
    if now.day < SUBSCRIPTION_BILL_DAY:
        months -= 1
    return max(1, months)

# Parse the JSONL record's top-level `timestamp` ("2026-04-13T23:32:33.178Z")
# into a naive local datetime so we can compare it to _current_cycle_start
# (also local-naive). Returns None on any parse failure — caller decides.
def _parse_record_ts(ts_str):
    if not ts_str:
        return None
    try:
        # Strip Z and fractional seconds for fromisoformat compat across
        # Python versions, then convert UTC → local naive.
        s = ts_str.rstrip('Z')
        if '.' in s:
            s = s.split('.', 1)[0]
        dt_utc = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        return dt_utc.astimezone().replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


TOKENOMICS_EPOCH_FILE = os.environ.get(
    'TOKENOMICS_EPOCH_FILE', '/Users/aetherclaude/data/tokenomics-epoch')

def _tokenomics_epoch():
    """Optional reset baseline. If data/tokenomics-epoch holds an ISO
    timestamp (naive local time), the token/cost counters - lifetime AND
    cycle - only sum session records at/after it. Lets us zero the
    tokenomics for a fresh tracking period (e.g. the Fable 5 cutover)
    without deleting any session data; clear the file to restore full
    history."""
    try:
        raw = open(TOKENOMICS_EPOCH_FILE).read().strip()
    except OSError:
        return None
    if not raw:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


# ── Session-transcript retention ─────────────────────────────────────────────
# The Claude Code session JSONLs under SESSION_DIR are append-only and never
# pruned — they grow without bound (the corpus that scan_tokens and the tail
# threads enumerate). This archiver MOVES (reversibly — not deletes) files
# whose newest record is older than SESSION_RETENTION_DAYS out to
# SESSION_ARCHIVE_DIR, bounding the live corpus and future growth. Age is read
# from in-file content timestamps, NOT mtime: a crash recovery reset every
# file's mtime to a single day, so mtime is useless for age here. The cutoff
# is far older than the tokenomics epoch, so archived files contribute nothing
# to the displayed token/cost totals, and their events are already persisted in
# events.db, so the dashboard loses no data.
SESSION_ARCHIVE_DIR = os.environ.get(
    'SESSION_ARCHIVE_DIR', '/Users/aetherclaude/.claude/projects-archive')
SESSION_RETENTION_DAYS = int(os.environ.get('SESSION_RETENTION_DAYS', '30'))
SESSION_ARCHIVE_INTERVAL_SECS = 86400  # daily


def _newest_record_ts(path):
    """Newest record timestamp in an append-only session JSONL, read from the
    file's tail so multi-MB files aren't read in full. Naive-local datetime
    (matches _parse_record_ts), or None."""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as fh:
            if size > 65536:
                fh.seek(size - 65536)
                fh.readline()  # discard the partial first line after the seek
            tail = fh.read().decode('utf-8', 'replace')
    except OSError:
        return None
    newest = None
    for line in tail.splitlines():
        if '"timestamp"' not in line:
            continue
        try:
            ts = json.loads(line).get('timestamp')
        except ValueError:
            continue
        dt = _parse_record_ts(ts)
        if dt is not None and (newest is None or dt > newest):
            newest = dt
    return newest


def session_archiver():
    time.sleep(120)  # let startup warm-ups finish before the first sweep
    while True:
        try:
            cutoff = datetime.now() - timedelta(days=SESSION_RETENTION_DAYS)
            moved = 0
            moved_bytes = 0
            for f in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
                if '/subagents/' in f:
                    continue
                newest = _newest_record_ts(f)
                # Never touch files newer than the cutoff, or whose age we
                # couldn't determine (fail safe — keep it).
                if newest is None or newest >= cutoff:
                    continue
                rel = os.path.relpath(f, SESSION_DIR)
                dest = os.path.join(SESSION_ARCHIVE_DIR, rel)
                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    sz = os.path.getsize(f)
                    os.replace(f, dest)  # same volume -> atomic rename
                    moved += 1
                    moved_bytes += sz
                except OSError as _e:
                    _log_exc('session_archiver.move', _e)
            if moved:
                print('[session-archiver] archived %d files (%.1f MB) with newest '
                      'record older than %dd -> %s'
                      % (moved, moved_bytes / 1e6, SESSION_RETENTION_DAYS, SESSION_ARCHIVE_DIR),
                      file=sys.stderr, flush=True)
        except Exception as _e:
            _log_exc('session_archiver', _e)
        time.sleep(SESSION_ARCHIVE_INTERVAL_SECS)


# Incremental per-file aggregate cache for scan_tokens. Session JSONLs
# are append-only, so a file whose (mtime,size) is unchanged since the
# last scan contributes the same token/tool totals — no need to re-read
# it. Previously scan_tokens re-read the ENTIRE ~700MB corpus TWICE every
# 30s (a usage pass + a separate tool-count pass), which pegged a core
# for ~3s each cycle and grew with history. Now only changed/new files
# are read, once, computing lifetime + cycle + tool aggregates together.
# Each entry: {'sig':(mtime,size), 'life':[in,out,cr,cc,msgs],
#              'cyc':[in,out,cr,cc,msgs], 'tools':(total,{name:count})}.
_tok_cache = {}
_tok_cache_key = None  # (epoch_ts|None, cycle_start_ts) the cache was built under

def scan_tokens():
    global _tok_cache, _tok_cache_key
    while True:
        try:
            # Cycle boundary recomputed each scan tick — when the bill day
            # rolls over at midnight, the next refresh picks it up.
            cycle_start = _current_cycle_start()
            sub_start   = _discover_subscription_start()
            epoch = _tokenomics_epoch()
            if epoch is not None and epoch > cycle_start:
                cycle_start = epoch
            cycles_paid = _bill_cycles_paid(sub_start)

            epoch_ts = epoch.timestamp() if epoch is not None else None
            cyc_ts = cycle_start.timestamp()
            # Per-file 'cyc' and epoch-filtered 'life' aggregates are only
            # valid for the (epoch, cycle_start) they were computed under.
            # When either rolls over (monthly bill day, or an operator
            # tokenomics reset), rebuild the cache from scratch.
            cache_key = (epoch_ts, cyc_ts)
            if cache_key != _tok_cache_key:
                _tok_cache = {}
                _tok_cache_key = cache_key

            seen = set()
            for f in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
                if '/subagents/' in f:
                    continue
                try:
                    stt = os.stat(f)
                except OSError:
                    continue
                # File untouched since the epoch reset → contributes nothing.
                if epoch_ts is not None and stt.st_mtime < epoch_ts:
                    continue
                seen.add(f)
                sig = (stt.st_mtime, stt.st_size)
                ent = _tok_cache.get(f)
                if ent is not None and ent['sig'] == sig:
                    continue  # unchanged — reuse cached aggregate
                # Cache miss / changed file: read ONCE, computing lifetime,
                # cycle, and tool aggregates in a single pass.
                life = defaultdict(lambda: [0, 0, 0, 0, 0])
                cyc  = defaultdict(lambda: [0, 0, 0, 0, 0])
                t_total = 0
                t_bd = defaultdict(int)
                file_in_cycle = stt.st_mtime >= cyc_ts
                try:
                    with open(f) as fh:
                        for line in fh:
                            has_usage = '"usage"' in line
                            has_tool  = '"tool_use"' in line
                            if not has_usage and not has_tool:
                                continue
                            try:
                                d = json.loads(line)
                            except ValueError:
                                continue
                            msg = d.get('message', {})
                            if has_usage:
                                u = msg.get('usage', {})
                                if u:
                                    inp = u.get('input_tokens', 0)
                                    out = u.get('output_tokens', 0)
                                    cr  = u.get('cache_read_input_tokens', 0)
                                    cc  = u.get('cache_creation_input_tokens', 0)
                                    mdl = msg.get('model') or ''
                                    rec_dt = (_parse_record_ts(d.get('timestamp'))
                                              if (epoch is not None or file_in_cycle)
                                              else None)
                                    # Tokenomics reset: drop pre-epoch records.
                                    if epoch is not None and rec_dt is not None and rec_dt < epoch:
                                        pass
                                    else:
                                        L = life[mdl]
                                        L[0] += inp; L[1] += out
                                        L[2] += cr;  L[3] += cc; L[4] += 1
                                        if file_in_cycle and (rec_dt is None or rec_dt >= cycle_start):
                                            C = cyc[mdl]
                                            C[0] += inp; C[1] += out
                                            C[2] += cr;  C[3] += cc; C[4] += 1
                            if has_tool:
                                for c in msg.get('content', []):
                                    if c.get('type') == 'tool_use':
                                        t_total += 1
                                        t_bd[c.get('name', '?')] += 1
                except OSError:
                    continue
                _tok_cache[f] = {'sig': sig, 'life': dict(life), 'cyc': dict(cyc),
                                 'tools': (t_total, dict(t_bd))}

            # Evict entries for files that disappeared (deleted/pruned).
            if len(_tok_cache) > len(seen):
                for gone in [k for k in _tok_cache if k not in seen]:
                    del _tok_cache[gone]

            # Aggregate across all cached per-file totals, bucketed by model so
            # cost can be priced per model (the corpus spans fable-5 + opus).
            life_by_model = defaultdict(lambda: [0, 0, 0, 0, 0])
            cyc_by_model  = defaultdict(lambda: [0, 0, 0, 0, 0])
            tool_total = 0
            tool_bd = defaultdict(int)
            for ent in _tok_cache.values():
                for _m, lf in ent['life'].items():
                    L = life_by_model[_m]
                    L[0] += lf[0]; L[1] += lf[1]; L[2] += lf[2]; L[3] += lf[3]; L[4] += lf[4]
                for _m, cy in ent['cyc'].items():
                    C = cyc_by_model[_m]
                    C[0] += cy[0]; C[1] += cy[1]; C[2] += cy[2]; C[3] += cy[3]; C[4] += cy[4]
                tt, bd = ent['tools']
                tool_total += tt
                for nm, ct in bd.items():
                    tool_bd[nm] += ct
            total_in  = sum(L[0] for L in life_by_model.values())
            total_out = sum(L[1] for L in life_by_model.values())
            total_cr  = sum(L[2] for L in life_by_model.values())
            total_cc  = sum(L[3] for L in life_by_model.values())
            total_msgs = sum(L[4] for L in life_by_model.values())
            cyc_in  = sum(C[0] for C in cyc_by_model.values())
            cyc_out = sum(C[1] for C in cyc_by_model.values())
            cyc_cr  = sum(C[2] for C in cyc_by_model.values())
            cyc_cc  = sum(C[3] for C in cyc_by_model.values())
            cyc_msgs = sum(C[4] for C in cyc_by_model.values())
            life_cost = round(sum(_turn_cost(_m, L[0], L[1], L[2], L[3])
                                  for _m, L in life_by_model.items()), 4)
            cyc_cost  = round(sum(_turn_cost(_m, C[0], C[1], C[2], C[3])
                                  for _m, C in cyc_by_model.items()), 4)

            with lock:
                token_stats['input'] = total_in
                token_stats['output'] = total_out
                token_stats['cache_read'] = total_cr
                token_stats['cache_create'] = total_cc
                token_stats['messages'] = total_msgs
                token_stats['cost'] = life_cost
                # Cycle-scoped + billing-meta fields. Read by /api/events
                # to render Cycle ROI alongside Lifetime ROI.
                token_stats['cycle_input']      = cyc_in
                token_stats['cycle_output']     = cyc_out
                token_stats['cycle_cache_read'] = cyc_cr
                token_stats['cycle_cache_create'] = cyc_cc
                token_stats['cycle_messages']   = cyc_msgs
                token_stats['cycle_cost'] = cyc_cost
                token_stats['cycle_start_iso']  = cycle_start.strftime('%Y-%m-%d')
                token_stats['subscription_amount_usd'] = SUBSCRIPTION_AMOUNT_USD
                token_stats['subscription_cycles_paid'] = cycles_paid
                token_stats['subscription_start_iso']   = sub_start.strftime('%Y-%m-%d')
                tool_stats['total'] = tool_total
                tool_stats['breakdown'] = dict(tool_bd)
        except Exception as _e: _log_exc('scan_tokens', _e)
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
                # ALLOWED connections are counted in the Ring 2 stat (so the
                # totals/ring view stay accurate) but are NOT emitted as feed
                # events: the agent opens many connections to allowlisted hosts
                # (api.github.com dominates), which floods the activity feed.
                # Only DENIED proxy events — actual policy violations — surface
                # in the live feed.
                ring_stats['r2_allowed'] += 1

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

SESSION_TOKEN_RECONCILE_SECS = 120

def session_token_reconciler():
    """Populate trace_tokens (powers the agent-walk playback token counter)
    by mapping session transcripts to their trace_id via the authoritative
    claude-code event timestamps in events.db, then inserting per-turn usage.

    Why not record inline at ingestion: a session's trace_id is NOT encoded in
    its file path for workspace runs (the common case) -- _session_trace_lookup
    returns None and the events get their trace_id from append_event's
    _active_trace_id fallback. So the file path can't be mapped directly, but
    the claude-code events events.db carries ARE keyed by the real trace_id and
    their timestamps equal the file's assistant-message timestamps. That join
    is exact and drift-proof (it's what the one-time backfill used).

    Incremental (only re-reads changed files via an mtime/size signature) and
    idempotent (per-trace timestamp watermark: only inserts usage newer than
    what's already recorded, so growing/re-read files don't duplicate)."""
    time.sleep(60)
    seen_sig = {}
    while True:
        try:
            conn = sqlite3.connect(EVENTS_DB)
            ts_map = {}
            for _ts, _tid in conn.execute(
                    "SELECT timestamp, trace_id FROM events "
                    "WHERE source='claude-code' AND trace_id IS NOT NULL "
                    "AND timestamp IS NOT NULL"):
                ts_map[_ts] = _tid
            watermark = {}
            for _tid, _mx in conn.execute(
                    'SELECT trace_id, MAX(timestamp) FROM trace_tokens GROUP BY trace_id'):
                watermark[_tid] = _mx
            by_trace = {}
            for f in glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True):
                if '/subagents/' in f:
                    continue
                try:
                    st = os.stat(f)
                except OSError:
                    continue
                sig = (st.st_mtime, st.st_size)
                if seen_sig.get(f) == sig:
                    continue
                seen_sig[f] = sig
                usage = []
                map_ts = []
                try:
                    with open(f) as fh:
                        for line in fh:
                            if '"usage"' not in line and '"tool_use"' not in line:
                                continue
                            try:
                                d = json.loads(line)
                            except ValueError:
                                continue
                            ts = d.get('timestamp')
                            if not ts:
                                continue
                            msg = d.get('message') or {}
                            u = msg.get('usage') or {}
                            if u:
                                usage.append((ts, u.get('input_tokens', 0),
                                              u.get('output_tokens', 0),
                                              u.get('cache_read_input_tokens', 0),
                                              u.get('cache_creation_input_tokens', 0),
                                              msg.get('model')))
                            c = msg.get('content')
                            if isinstance(c, list) and any(
                                    isinstance(b, dict) and b.get('type') == 'tool_use' for b in c):
                                map_ts.append(ts)
                except OSError:
                    continue
                if not usage:
                    continue
                tid = None
                for ts in (map_ts or [u[0] for u in usage]):
                    tid = ts_map.get(ts)
                    if tid:
                        break
                if not tid:
                    continue
                by_trace.setdefault(tid, []).extend(usage)
            inserts = []
            for tid, rows in by_trace.items():
                mx = watermark.get(tid)
                for u in rows:
                    if mx is None or u[0] > mx:
                        inserts.append((tid, u[0], u[1], u[2], u[3], u[4], u[5]))
            if inserts:
                conn.executemany(
                    'INSERT INTO trace_tokens (trace_id,timestamp,input,output,'
                    'cache_read,cache_create,model) VALUES (?,?,?,?,?,?,?)', inserts)
                conn.commit()
            conn.close()
        except Exception as _e:
            _log_exc('session_token_reconciler', _e)
        time.sleep(SESSION_TOKEN_RECONCILE_SECS)


def tail_sessions():
    """Watch Claude Code session files for tool_use events."""
    import glob, re
    last_positions = {}
    startup_ts = time.time()

    while True:
        try:
            # Find all session files
            files = glob.glob(os.path.join(SESSION_DIR, '**', '*.jsonl'), recursive=True)
            files = [f for f in files if '/subagents/' not in f]

            for filepath in files:
                try:
                    size = os.path.getsize(filepath)
                    # First sighting of this file. Same semantics as
                    # tail_claude_transcripts: a file last modified before
                    # the dashboard started is pre-existing history — skip
                    # to EOF instead of replaying it. Replaying re-inserted
                    # every historical tool_use into events.db on every
                    # dashboard restart (the DB hit 915MB of duplicates).
                    if filepath not in last_positions:
                        try:
                            mtime = os.path.getmtime(filepath)
                        except OSError:
                            continue
                        last_positions[filepath] = 0 if mtime > startup_ts else size
                    last_pos = last_positions[filepath]

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
        except Exception as _e: _log_exc('tail_sessions', _e)
        time.sleep(2)

DEFENSECLAW_AUDIT_LOG = '/Users/aetherclaude/.defenseclaw/gateway.jsonl'

def tail_defenseclaw_audit(logfile):
    """Tail the DefenseClaw v7 OTel-schema gateway audit log and surface
    each entry as a DEFENSE event in the stream. Schema reference:
    docs/OBSERVABILITY-CONTRACT.md in the upstream repo.

    Rotation-aware: the DC daemon rotates gateway.jsonl when it hits ~50MB
    (renaming to gateway-<ts>.jsonl and creating a fresh file at the same
    path). Without inode tracking, our open handle stays pinned to the
    renamed file and we silently stop ingesting forever. Trace 36ad8318
    on 2026-05-17 lost its entire Stage 6 swimlane this way: rotation
    fired at 08:13:37 UTC, the trace ran at 10:09 UTC, no DEFENSE events
    surfaced. Now we re-stat the path on each EOF cycle and reopen if
    the inode changed."""
    def _open_and_seek_end(path):
        fh = open(path, 'r')
        fh.seek(0, 2)
        return fh, os.fstat(fh.fileno()).st_ino

    while not os.path.exists(logfile):
        time.sleep(5)
    f, current_inode = _open_and_seek_end(logfile)
    try:
        while True:
            line = f.readline()
            if not line:
                # Check for rotation: if the path now resolves to a
                # different inode than our open handle, the daemon
                # rotated under us. Reopen at end-of-file on the new
                # file (don't replay old content — that would
                # mis-attribute historical events to whatever trace is
                # currently active).
                try:
                    path_inode = os.stat(logfile).st_ino
                    if path_inode != current_inode:
                        try: f.close()
                        except: pass
                        f, current_inode = _open_and_seek_end(logfile)
                        continue
                except FileNotFoundError:
                    # File temporarily gone during rotation — wait and retry.
                    time.sleep(2)
                    continue
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
    finally:
        try: f.close()
        except Exception as _e: _log_exc('tail_defenseclaw_audit', _e)


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
<html><head><title>AI-Agent Defense-In-Depth Dashboard</title><meta charset="utf-8">
<style>
/* ── AetherSDR design tokens (aethersdr.com) ─────────────────────────────
   Surfaces + chrome come from the brand stylesheet; the cat-* and status
   tokens are the dataviz-validated palettes (colorblind-checked on both
   --bg and --bg-2, dark mode) — data marks use cat-*, state uses
   good/warn/crit (always with an icon or label, never color alone). */
:root{
  --bg:#060b13; --bg-1:#0a121e; --bg-2:#0e1a2a; --bg-3:#12233a;
  --panel:rgba(18,34,56,.55); --panel-hi:rgba(28,52,84,.65);
  --ink:#eaf2fb; --ink-soft:#c4d4e8; --muted:#8598b4; --muted-dim:#5f708a;
  --line:rgba(120,165,210,.12); --line-hi:rgba(120,190,230,.28);
  --accent:#3aa7ff; --accent-bright:#5de3ff; --teal:#7bf2dc;
  --grad:linear-gradient(100deg,#3aa7ff 0%,#5de3ff 42%,#8ef7e6 100%);
  --good:#27a86f; --warn:#b3831c; --crit:#e8506a;
  --cat-blue:#2f96ea; --cat-teal:#21a184; --cat-violet:#a878e0;
  --cat-amber:#bd7c20; --cat-rose:#e85578;
  --radius:16px; --radius-sm:11px;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,'Helvetica Neue',Arial,sans-serif;
  --mono:'SF Mono','JetBrains Mono','Fira Code',ui-monospace,Menlo,Consolas,monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--ink-soft);font-family:var(--mono);font-size:13px}
.header{background:var(--bg-1);padding:12px 24px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.header h1{font-family:var(--sans);font-size:20px;color:var(--accent-bright);letter-spacing:1px;font-weight:400}
.header .sub{font-family:var(--sans);color:var(--muted-dim);font-size:11px}
.header .live{color:var(--good);font-size:12px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.rings{display:grid;grid-template-columns:repeat(9,1fr);gap:8px;padding:12px 24px}
.ring{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:10px;text-align:center;position:relative}
.ring .num{font-size:10px;color:var(--muted-dim);position:absolute;top:4px;left:8px}
.ring .name{font-family:var(--sans);font-size:10px;font-weight:500;color:var(--muted);margin-bottom:4px}
.ring .value{font-family:var(--sans);font-size:26px;font-weight:300;color:var(--accent-bright);letter-spacing:0}
.ring .detail{font-size:10px;color:var(--muted);margin-top:2px}
.ring.ok{border-color:var(--line)}
.ring.warn{border-color:var(--warn)}
.ring.alert{border-color:var(--crit)}
.ring .status{width:8px;height:8px;border-radius:50%;display:inline-block;position:absolute;top:6px;right:8px}
.ring .status.green{background:var(--good)}
.ring .status.yellow{background:var(--warn)}
.ring .status.red{background:var(--crit)}

.filter-bar{padding:6px 24px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filter-bar label{color:var(--muted-dim);font-size:11px}
.fbtn{background:var(--bg-3);border:1px solid var(--line-hi);color:var(--ink-soft);padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-family:inherit}
.fbtn.active{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.fbtn:hover{border-color:var(--accent)}
.fbtn.guard{border-color:#e85578}.fbtn.mcp-f{border-color:#a878e0}
.finput{background:var(--bg-1);border:1px solid var(--line-hi);color:var(--ink-soft);padding:3px 8px;border-radius:6px;font-size:11px;font-family:inherit;width:130px}

.main{display:grid;grid-template-columns:2fr 1fr;gap:10px;padding:0 24px 12px;height:calc(100vh - 310px)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);overflow:hidden;display:flex;flex-direction:column}
.phdr{font-family:var(--sans);padding:6px 10px;background:var(--bg-2);border-bottom:1px solid var(--line);font-size:11px;color:var(--accent-bright);font-weight:600;letter-spacing:0.3px;display:flex;justify-content:space-between}
.pbody{overflow-y:auto;flex:1;padding:2px}

.ev{padding:2px 8px;border-bottom:1px solid var(--line);display:flex;gap:6px;font-size:11px}
.ev:hover{background:var(--bg-2)}
.ev.agent{background:#0a1a0a;border-left:3px solid #27a86f}
.ev.guard{background:#1a0a10;border-left:3px solid #e85578}
.ev.mcp{background:#0f0a1a;border-left:3px solid #a878e0}
.ev .tp{width:50px;font-weight:bold}
.tp.EXEC{color:#5de3ff}.tp.KPROBE{color:#b3831c}.tp.EXIT{color:#607080}.tp.GUARD{color:#e85578}.tp.MCP{color:#a878e0}.tp.BLOCK{color:#e8506a;font-weight:bold}.tp.PROXY{color:#21a184}
.ev.nftables{background:#1a0808;border-left:3px solid #e8506a}
.ev.tinyproxy{background:#081a10;border-left:3px solid #21a184}
.stag.nftables{background:#301010;color:#e8506a}
.stag.mcp-scan{background:#102030;color:#45c8e8}
.stag.skill-scan{background:#201030;color:#dd88ff}
.ev.mcp-scan{background:#081018;border-left:3px solid #45c8e8}
.ev.skill-scan{background:#100818;border-left:3px solid #dd88ff}
.tp.SCAN{color:#45c8e8}
.tp.TOOL{color:#e88fc0}
.tp.SKILL{color:#e0b83c}
.ev.skill-dispatch{background:#181808;border-left:3px solid #e0b83c}
.ev.webhook{background:#081018;border-left:3px solid #2f96ea}
.ev.defenseclaw{background:#0c0c20;border-left:3px solid #7a8cf0}
.stag.defenseclaw{background:#181830;color:#7a8cf0}
.tp.DEFENSE{color:#7a8cf0}
.stag.skill-dispatch{background:#202010;color:#e0b83c}
.ev.claude-code{background:#180818;border-left:3px solid #e88fc0}
.stag.claude-code{background:#201020;color:#e88fc0}
.stag.tinyproxy{background:#103020;color:#21a184}
.ev .uid{width:40px;color:var(--muted)}
.ev .bin{width:150px;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .args{flex:1;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev .pol{color:var(--warn);font-size:10px}
.ev .tm{width:96px;color:var(--muted-dim);font-size:10px}
.stag{font-size:8px;padding:1px 3px;border-radius:2px;margin-left:3px}
.stag.tetragon{background:#203040;color:#5de3ff}
.stag.codeguard{background:#301020;color:#e85578}
.stag.mcp{background:#1a1030;color:#a878e0}

.si{padding:5px 10px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;font-size:11px}
.si .n{color:var(--ink-soft)}.si .c{color:var(--accent-bright);font-weight:bold}
.ai{padding:6px 10px;border-bottom:1px solid var(--line)}
.ai.critical{border-left:3px solid var(--crit);background:rgba(232,80,106,.08)}
.ai.high{border-left:3px solid var(--warn);background:rgba(179,131,28,.08)}
.ai .msg{font-size:11px}.ai .at{font-size:9px;color:var(--muted-dim)}
.rpanels{display:flex;flex-direction:column;gap:8px;overflow:hidden}
.rpanels .pbody{max-height:25vh}
.muted{color:var(--muted-dim)}
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg-1);border:1px solid var(--line-hi);border-radius:var(--radius);padding:20px;max-width:700px;width:90%;max-height:80vh;overflow-y:auto;color:var(--ink-soft)}
.modal h2{font-family:var(--sans);color:var(--accent-bright);margin-bottom:12px;font-size:17px;letter-spacing:0.5px;font-weight:500}
.modal-close{float:right;cursor:pointer;color:var(--muted-dim);font-size:20px;border:none;background:none}
.modal-close:hover{color:var(--crit)}
.modal-finding{padding:8px 12px;margin:6px 0;border-radius:6px;font-size:12px}
.modal-finding.HIGH{background:rgba(232,80,106,.08);border-left:3px solid var(--crit)}
.modal-finding.MEDIUM{background:rgba(179,131,28,.08);border-left:3px solid var(--warn)}
.modal-finding.LOW{background:rgba(39,168,111,.08);border-left:3px solid var(--good)}
.modal-finding.SAFE{background:var(--bg);border-left:3px solid var(--line-hi)}
.modal-finding .sev{font-weight:bold;margin-right:8px}
.modal-finding .sev.HIGH{color:var(--crit)}.modal-finding .sev.MEDIUM{color:var(--warn)}.modal-finding .sev.SAFE{color:var(--good)}
.modal-finding .tool-name{color:var(--accent-bright)}
.modal-finding .detail{color:var(--muted);font-size:11px;margin-top:4px}
.modal-overlay.wp .modal{max-width:900px;max-height:90vh}
.wp-content{line-height:1.7;font-family:var(--sans);font-size:13px;color:var(--ink-soft)}
.wp-content h1{color:var(--accent-bright);font-size:22px;margin:24px 0 8px;letter-spacing:1px;text-align:center}
.wp-content h2{font-family:var(--sans);color:var(--accent-bright);font-size:17px;font-weight:600;margin:20px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.wp-content h3{color:var(--accent);font-size:14px;margin:16px 0 6px}
.wp-content p{margin:8px 0}
.wp-content ul,ol{margin:8px 0 8px 20px}
.wp-content li{margin:4px 0}
.wp-content strong{color:var(--ink)}
.wp-content table{border-collapse:collapse;width:100%;margin:12px 0;font-size:12px}
.wp-content th{background:var(--bg-2);color:var(--accent-bright);padding:8px 10px;text-align:left;border:1px solid var(--line-hi)}
.wp-content td{padding:6px 10px;border:1px solid var(--line)}
.wp-content tr:nth-child(even){background:var(--bg-1)}
.wp-content code{background:var(--bg-2);padding:1px 4px;border-radius:3px;font-family:var(--mono);font-size:12px;color:var(--teal)}
.wp-content .cisco{color:#00bceb}
.wp-content .highlight{background:var(--bg-2);border-left:3px solid var(--accent);padding:8px 12px;margin:10px 0;border-radius:4px}
.wp-content .meta{color:var(--muted-dim);font-size:11px;text-align:center;margin:8px 0 20px}
.clickable{cursor:pointer;transition:background .2s}.clickable:hover{background:var(--bg-2)}

/* ── Exec/Ops view shell ──────────────────────────────────────────────────
   One DOM, two sibling sections; body class picks the visible one (hash
   routing: default view vs #ops / #exec). Flex column replaces the old
   height:calc(100vh - 310px) magic number so the header can change freely;
   the ops section keeps its viewport-locked feel via flex:1 + min-height:0,
   the exec view scrolls naturally. */
html,body{height:100%}
body{display:flex;flex-direction:column}
#view-ops{flex:1;display:flex;flex-direction:column;min-height:0}
#view-ops .main{flex:1;min-height:0;height:auto}
body.view-exec #view-ops{display:none}
body.view-ops #view-exec{display:none}
#view-exec{flex:1;overflow-y:auto}
.vtoggle{display:flex;border:1px solid var(--line-hi);border-radius:8px;overflow:hidden}
.vtoggle button{background:transparent;border:none;color:var(--muted);padding:4px 12px;font-size:11px;font-family:inherit;cursor:pointer}
.vtoggle button.active{background:var(--accent);color:var(--bg)}
.hmenu{position:relative}
.hmenu summary{list-style:none;cursor:pointer;border:1px solid var(--line-hi);border-radius:8px;padding:4px 12px;font-size:11px;color:var(--muted);white-space:nowrap;user-select:none}
.hmenu summary::-webkit-details-marker{display:none}
.hmenu summary:hover{color:var(--ink-soft);border-color:var(--accent)}
.hmenu[open] summary{color:var(--ink-soft);border-color:var(--accent)}
.hmenu-list{position:absolute;right:0;top:calc(100% + 6px);background:var(--bg-2);border:1px solid var(--line-hi);border-radius:10px;padding:6px;display:flex;flex-direction:column;gap:2px;z-index:600;min-width:230px;box-shadow:0 8px 24px rgba(0,0,0,.45)}
.hmenu-list a{color:var(--ink-soft);font-size:12px;text-decoration:none;padding:6px 10px;border-radius:6px;white-space:nowrap}
.hmenu-list a:hover{background:var(--bg-3);color:var(--accent-bright)}

/* ── Executive view ──────────────────────────────────────────────────────
   Calm, sans-serif, generous spacing. One hero figure, control chips,
   KPI stat tiles (label/value/delta/sparkline per the dataviz contract),
   one area chart, condensed rows. Data marks use the validated palette;
   status always ships icon+label alongside color. */
#view-exec{font-family:var(--sans);padding:20px 32px 40px;max-width:1440px;margin:0 auto;width:100%}
.x-hero{display:flex;align-items:center;gap:30px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:20px 26px;margin-bottom:14px}
.x-hero-left{flex:1.1;display:flex;align-items:center;gap:28px;min-width:0}
.x-gauge-wrap{position:relative;flex:0 0 auto}
.x-score{position:absolute;top:50%;left:50%;transform:translate(-50%,-52%);font-size:52px;font-weight:600;color:var(--ink);line-height:1}
.x-hero-info{flex:1;min-width:0}
.x-hero-info .x-title{font-size:13px;font-weight:600;letter-spacing:.4px;color:var(--muted);text-transform:uppercase;margin-bottom:6px}
.x-hero-line{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.x-chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:3px 10px;border-radius:100px;border:1px solid var(--line-hi)}
.x-reasons{font-size:11.5px;color:var(--muted);line-height:1.5}
.x-reasons b{color:var(--ink-soft);font-weight:600}
.x-reasons>div{margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.x-controls{flex:1;display:grid;grid-template-columns:repeat(3,1fr);gap:8px;min-width:0}
.x-ctl{display:flex;align-items:center;gap:7px;background:var(--bg-2);border:1px solid var(--line);border-radius:var(--radius-sm);padding:8px 11px;cursor:pointer;transition:border-color .15s,background .15s;min-width:0}
.x-ctl:hover{border-color:var(--accent);background:var(--panel-hi)}
.x-ctl .dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.x-ctl .nm{font-size:12px;color:var(--ink-soft);white-space:nowrap}
.x-ctl .ct{font-size:10.5px;color:var(--muted-dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-left:auto}
.x-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:14px}
.x-tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:14px 16px;cursor:pointer;transition:border-color .15s}
.x-tile:hover{border-color:var(--accent)}
.x-tile .lbl{font-size:11px;color:var(--muted);letter-spacing:.3px;text-transform:uppercase;margin-bottom:6px}
.x-tile .val{font-size:27px;font-weight:600;color:var(--ink);line-height:1.1}
.x-tile .sub{font-size:11px;color:var(--muted-dim);margin-top:4px;display:flex;align-items:center;gap:8px}
.x-tile .spark{margin-top:8px;height:30px}
.x-delta{font-weight:600}
.x-panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:16px 20px;margin-bottom:14px}
.x-duo{display:flex;gap:14px;align-items:flex-start;margin-bottom:14px}
.x-duo .x-panel{flex:1;min-width:0;margin-bottom:0}
.x-duo .x-rows span{overflow-wrap:anywhere}
.x-panel .x-ph{font-size:12px;font-weight:600;letter-spacing:.4px;color:var(--muted);text-transform:uppercase;margin-bottom:10px;display:flex;justify-content:space-between;align-items:baseline}
.x-rows .x-row{display:flex;align-items:center;gap:10px;padding:6px 2px;border-bottom:1px solid var(--line);font-size:12px}
.x-rows .x-row:last-child{border-bottom:none}
.x-rows .tm{color:var(--muted-dim);font-size:11px;width:88px;flex:0 0 auto;font-family:var(--mono)}
.x-rows a{color:var(--ink-soft);text-decoration:none}
.x-rows a:hover{color:var(--accent-bright)}
#x-tt{position:fixed;display:none;background:var(--bg-2);border:1px solid var(--line-hi);border-radius:8px;padding:6px 10px;font-size:11px;color:var(--ink-soft);pointer-events:none;z-index:500;white-space:nowrap}
#x-alerts.empty{display:none}
</style></head><body>

<div class="header">
<img src="/logo.png" style="height:48px;margin-right:16px;border-radius:50%">
<div style="flex:1"><h1>AI-Agent Defense-In-Depth Dashboard</h1>
<div class="sub">Cisco Isovalent (Tetragon) &middot; Cisco DefenseClaw CodeGuard &middot; Cisco AI Defense &middot; MCP Token Isolation</div></div>
<!-- Compact header controls (C5): secondary links collapse into a native
     <details> menu so the exec landing view leads with the data, not nav.
     Toggle + LIVE stay visible; everything else is one click away. -->
<div style="display:flex;align-items:center;gap:10px">
  <details class="hmenu" id="hmenu">
    <summary>Links &#9662;</summary>
    <div class="hmenu-list">
      <a href="/agent-walk" target="_blank">Agent Walk &#x2197;</a>
      <a href="/codegraph" target="_blank">Codegraph &#x2197;</a>
      <a href="/cartographer" target="_blank">Cartographer &#x2197;</a>
      <a href="#" onclick="openOperatorTui();document.getElementById('hmenu').removeAttribute('open');return false">Operator TUI &#x2197;</a>
      <a href="#" onclick="showConstitution();document.getElementById('hmenu').removeAttribute('open');return false">Foundry Security Spec</a>
      <a href="#" onclick="showWhitepaper();document.getElementById('hmenu').removeAttribute('open');return false">Defense-in-Depth Whitepaper</a>
    </div>
  </details>
  <div class="vtoggle"><button id="vt-exec" onclick="location.hash='exec'">Exec</button><button id="vt-ops" onclick="location.hash='ops'">Ops</button></div>
  <div class="live" id="agent-status">&#9679; LIVE</div>
</div>
</div>

<section id="view-exec">
<!-- Shared SVG gradient defs (gauge arc). Kept 0x0 but rendered (display:none
     would drop the defs in some engines). -->
<svg style="position:absolute;width:0;height:0" aria-hidden="true"><defs>
<linearGradient id="pgrad" x1="0" y1="0" x2="1" y2="0">
<stop offset="0" stop-color="#3aa7ff"/><stop offset=".42" stop-color="#5de3ff"/><stop offset="1" stop-color="#8ef7e6"/>
</linearGradient></defs></svg>

<!-- Hero row, two columns: gauge + posture readout (reasons as a vertical
     list) on the left; the nine control chips as a 3x3 grid on the right.
     Replaces the separate full-width chips row — one screen on 1080p. -->
<div class="x-hero">
  <div class="x-hero-left">
    <div class="x-gauge-wrap"><div id="x-gauge"></div><div class="x-score" id="x-score">&mdash;</div></div>
    <div class="x-hero-info">
      <div class="x-title">Defense Posture</div>
      <div class="x-hero-line" id="x-hero-line"></div>
      <div class="x-reasons" id="x-reasons"></div>
    </div>
  </div>
  <div class="x-controls" id="x-controls"></div>
</div>

<div class="x-kpis" id="x-kpis"></div>

<div class="x-panel">
  <div class="x-ph"><span>Activity &middot; last 24 hours</span><span id="x-trend-total" style="text-transform:none;letter-spacing:0"></span></div>
  <div id="x-trend"></div>
</div>

<!-- Alerts + activity share a row — each holds narrow rows, so stacking
     them full-width doubled the page height for no benefit. When Alerts is
     empty (hidden), Activity flexes to the full width. -->
<div class="x-duo">
<div class="x-panel" id="x-alerts" style="border-color:var(--crit)">
  <div class="x-ph"><span style="color:var(--crit)">&#9888; Alerts</span></div>
  <div class="x-rows" id="x-alert-rows"></div>
</div>

<div class="x-panel">
  <div class="x-ph"><span>Recent agent activity</span><a href="/agent-walk" target="_blank" style="color:var(--accent);text-transform:none;letter-spacing:0;font-weight:400;text-decoration:none">Agent Walk &#x2197;</a></div>
  <div class="x-rows" id="x-activity"></div>
</div>
</div>

<div id="x-tt"></div>
</section>

<section id="view-ops">
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
<button class="fbtn" data-types="BLOCK" style="border-color:#e8506a" onclick="toggleFilter(this)">Firewall</button>
<button class="fbtn" data-types="PROXY" style="border-color:#21a184" onclick="toggleFilter(this)">Proxy</button>
<button class="fbtn" data-types="SCAN" style="border-color:#45c8e8" onclick="toggleFilter(this)">Scan</button>
<button class="fbtn" data-types="GUARD" style="border-color:#e85578" onclick="toggleFilter(this)">CodeGuard</button>
<button class="fbtn" data-types="TOOL" style="border-color:#e88fc0" onclick="toggleFilter(this)">Claude</button>
<button class="fbtn" data-types="MCP" style="border-color:#a878e0" onclick="toggleFilter(this)">MCP</button>
<button class="fbtn" data-types="SKILL" style="border-color:#e0b83c" onclick="toggleFilter(this)">Skills</button>
<button class="fbtn" data-types="WEBHOOK" style="border-color:#2f96ea" onclick="toggleFilter(this)">Webhook</button>
<button class="fbtn" data-types="DEFENSE" style="border-color:#7a8cf0" onclick="toggleFilter(this)">AI-Defense</button>
<label style="margin-left:8px">Search:</label>
<input class="finput" id="search" placeholder="grep pattern..." oninput="debouncedRefresh()" style="width:250px">
</div>

<div class="main">
<div class="panel">
<div class="phdr"><span><span style="margin-right:16px">Event Stream &middot;</span><span style="margin-right:4px"><span style="color:#27a86f">&#9632;</span> Agent</span> <span style="margin-right:4px"><span style="color:#e8506a">&#9632;</span> Firewall</span> <span style="margin-right:4px"><span style="color:#21a184">&#9632;</span> Proxy</span> <span style="margin-right:4px"><span style="color:#e85578">&#9632;</span> CodeGuard</span> <span style="margin-right:4px"><span style="color:#a878e0">&#9632;</span> MCP</span> <span style="margin-right:4px"><span style="color:#45c8e8">&#9632;</span> Scanners</span> <span style="margin-right:4px"><span style="color:#e0b83c">&#9632;</span> Skills</span> <span><span style="color:#e88fc0">&#9632;</span> Claude</span></span><span class="muted" id="sup"></span></div>
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
<div class="panel" style="flex:.9">
<div class="phdr">Eval &middot; Galileo</div>
<div class="pbody" id="eval-panel"></div>
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
</section>

<script>
// ── View routing (Exec ⇄ Ops) ──────────────────────────────────────────────
// Hash-based: '#ops' / '#exec' deep-link; no hash = DEFAULT_VIEW. The server
// root route is an exact '/' match, so query params are not an option; the
// hash never reaches the server and toggles without a reload.
const DEFAULT_VIEW='exec';  // C5 (2026-07-22, Jeremy-approved): exec is the landing view; #ops deep-links the dense layout
let curView=DEFAULT_VIEW;
function applyView(){
  const h=location.hash.replace('#','');
  curView=(h==='ops'||h==='exec')?h:DEFAULT_VIEW;
  document.body.classList.toggle('view-exec',curView==='exec');
  document.body.classList.toggle('view-ops',curView==='ops');
  document.getElementById('vt-exec').classList.toggle('active',curView==='exec');
  document.getElementById('vt-ops').classList.toggle('active',curView==='ops');
  // Re-render the newly visible view immediately from cache — no fetch wait.
  if(curView==='ops'&&lastData&&lastData.stats){renderOps(lastData);renderEvents(lastData.events,lastData.total,lastData.filtered||lastData.total);renderEval();}
  else if(curView==='exec'&&typeof renderExec==='function'&&lastData&&lastData.stats){renderExec(lastData);}
}
window.addEventListener('hashchange',applyView);
// Switch to ops with filter buttons preselected (exec tiles drill into the
// event stream through this).
function gotoOps(opts){
  if(opts&&opts.types){
    document.querySelectorAll('.filter-bar .fbtn').forEach(b=>b.classList.remove('active'));
    const want=new Set(opts.types.split(','));
    document.querySelectorAll('.filter-bar .fbtn').forEach(b=>{
      const t=(b.dataset.types||'').split(',');
      if(t.some(x=>want.has(x)))b.classList.add('active');
    });
  }
  location.hash='ops';
}

// ── Exec-view chart components (vanilla SVG strings, dataviz mark specs:
// 2px lines, hairline solid grid, ~10-18% area wash, no number-on-every-point)
function fmtCompact(n){if(n==null)return '—';if(n>=1e6)return (n/1e6).toFixed(1)+'M';if(n>=1e4)return Math.round(n/1e3)+'K';if(n>=1e3)return (n/1e3).toFixed(1)+'K';return String(n)}
function deltaHtml(cur,prev,upIsGood){
  if(cur==null||prev==null)return '<span class="x-delta" style="color:var(--muted-dim)">—</span>';
  const d=cur-prev;
  if(d===0)return '<span class="x-delta" style="color:var(--muted-dim)">±0</span>';
  const up=d>0,good=(up===!!upIsGood);
  return `<span class="x-delta" style="color:${good?'var(--good)':'var(--crit)'}">${up?'▲':'▼'} ${up?'+':''}${d}</span>`;
}
const REDUCED_MOTION=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function svgSparkline(pts,w,h,dur){
  w=w||110;h=h||30;
  if(!pts||pts.length<2)return '';
  const mx=Math.max.apply(null,pts),mn=Math.min.apply(null,pts),pad=3,rng=(mx-mn)||1;
  const xs=pts.map((v,i)=>[pad+i*(w-2*pad)/(pts.length-1),h-pad-((v-mn)/rng)*(h-2*pad)]);
  const line=xs.map(p=>p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');
  const last=xs[xs.length-1];
  let dot;
  if(dur&&!REDUCED_MOTION){
    // SMIL motion: the end-dot traverses the line for ~45% of each cycle,
    // then rests on the endpoint (the 'latest value' marker) for the rest.
    // Each tile passes a slightly different dur so the row doesn't march
    // in lockstep. Static under prefers-reduced-motion.
    const path='M '+xs.map(p=>p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' L ');
    dot=`<circle r="2.5" fill="#5de3ff"><animateMotion dur="${dur}s" repeatCount="indefinite" calcMode="linear" keyPoints="0;1;1" keyTimes="0;0.45;1" path="${path}"/></circle>`;
  }else{
    dot=`<circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.5" fill="#5de3ff"/>`;
  }
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline points="${line}" fill="none" stroke="#2f96ea" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>${dot}</svg>`;
}
function svgRingGauge(score,size,sw){
  size=size||132;sw=sw||10;
  const c=size/2,r=c-sw/2,circ=2*Math.PI*r,frac=Math.max(0,Math.min(100,score))/100;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">`+
    `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="rgba(120,165,210,.12)" stroke-width="${sw}"/>`+
    `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="url(#pgrad)" stroke-width="${sw}" stroke-linecap="round" stroke-dasharray="${(circ*frac).toFixed(1)} ${circ.toFixed(1)}" transform="rotate(-90 ${c} ${c})"/></svg>`;
}
function svgAreaChart(buckets,w,h,opts){
  h=h||160;opts=opts||{};
  const cid=opts.id||'x-trend-svg';
  const get=opts.val||(b=>b.events);
  if(!buckets||buckets.length<2)return '<div style="color:var(--muted-dim);font-size:12px">No activity data yet</div>';
  const padL=8,padR=8,padT=10,padB=20,iw=w-padL-padR,ih=h-padT-padB;
  const vals=buckets.map(get),mx=Math.max.apply(null,vals.concat([1]));
  const xs=buckets.map((b,i)=>padL+i*iw/(buckets.length-1));
  const ys=vals.map(v=>padT+ih-(v/mx)*ih);
  const line=xs.map((x,i)=>x.toFixed(1)+','+ys[i].toFixed(1)).join(' ');
  const area=`${padL},${(padT+ih).toFixed(1)} ${line} ${(padL+iw).toFixed(1)},${(padT+ih).toFixed(1)}`;
  let grid='';for(let g=1;g<=3;g++){const gy=(padT+ih-g*ih/3).toFixed(1);grid+=`<line x1="${padL}" y1="${gy}" x2="${(padL+iw).toFixed(1)}" y2="${gy}" stroke="rgba(120,165,210,.12)" stroke-width="1"/>`}
  const stride=Math.max(1,Math.round(buckets.length/8));
  let labels='';for(let i=0;i<buckets.length;i+=stride){const dt=new Date(buckets[i].t);if(!isNaN(dt))labels+=`<text x="${xs[i].toFixed(1)}" y="${h-6}" font-size="10" fill="#8598b4" text-anchor="middle" font-family="inherit">${dt.toLocaleTimeString([],{hour:'2-digit'})}</text>`}
  let hits='';for(let i=0;i<buckets.length;i++){
    const x0=i===0?padL:(xs[i-1]+xs[i])/2, x1=i===buckets.length-1?padL+iw:(xs[i]+xs[i+1])/2;
    hits+=`<rect x="${x0.toFixed(1)}" y="0" width="${(x1-x0).toFixed(1)}" height="${h}" fill="transparent" data-i="${i}" data-x="${xs[i].toFixed(1)}"/>`}
  // Same traveling-dot treatment as the tile sparklines (opts.dur), scaled up.
  let adot='';
  if(opts.dur&&!REDUCED_MOTION){
    const mpath='M '+xs.map((x,i)=>x.toFixed(1)+' '+ys[i].toFixed(1)).join(' L ');
    adot=`<circle r="3.5" fill="#5de3ff"><animateMotion dur="${opts.dur}s" repeatCount="indefinite" calcMode="linear" keyPoints="0;1;1" keyTimes="0;0.45;1" path="${mpath}"/></circle>`;
  }
  // Event markers (opts.markers: [{t,...}]) — dots riding the line at their
  // timestamp, 2px surface ring so they read over the stroke, plus an
  // oversized transparent hit circle (rendered LAST so it wins hover over
  // the bucket rects). Marker index rides data-m for the hover card.
  let marks='',markHits='';
  if(opts.markers&&opts.markers.length){
    const t0=new Date(buckets[0].t).getTime(),t1=new Date(buckets[buckets.length-1].t).getTime();
    const span=(t1-t0)||1;
    opts.markers.forEach((m,mi)=>{
      const tm=new Date(m.t).getTime();if(isNaN(tm))return;
      let frac=(tm-t0)/span;frac=Math.max(0,Math.min(1,frac));
      const mxp=padL+frac*iw;
      const fi=frac*(buckets.length-1),i0=Math.floor(fi),i1=Math.min(i0+1,buckets.length-1);
      const myp=ys[i0]+(ys[i1]-ys[i0])*(fi-i0);
      marks+=`<circle cx="${mxp.toFixed(1)}" cy="${myp.toFixed(1)}" r="${m.r||4.5}" fill="${m.color||opts.markerColor||'#d94fd4'}" stroke="#0e1a2a" stroke-width="2"/>`;
      markHits+=`<circle cx="${mxp.toFixed(1)}" cy="${myp.toFixed(1)}" r="11" fill="transparent" data-m="${mi}" style="cursor:pointer"/>`;
    });
  }
  return `<svg id="${cid}" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">`+
    `<defs><linearGradient id="${cid}-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2f96ea" stop-opacity=".18"/><stop offset="1" stop-color="#2f96ea" stop-opacity="0"/></linearGradient></defs>`+
    grid+`<polygon points="${area}" fill="url(#${cid}-grad)"/>`+
    `<polyline points="${line}" fill="none" stroke="#2f96ea" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`+
    adot+
    `<line id="${cid}-cross" y1="${padT}" y2="${(padT+ih).toFixed(1)}" x1="0" x2="0" stroke="rgba(120,190,230,.28)" stroke-width="1" visibility="hidden"/>`+
    labels+hits+marks+markHits+`</svg>`;
}
// Edge-aware tooltip placement: default to the right of the cursor, but flip
// to the left when the card would overflow the viewport's right edge, and
// clamp vertically so tall cards (many findings) never render offscreen.
function placeTip(tt,ev){
  tt.style.display='block';
  tt.style.left='-9999px';tt.style.top='0px';   // measure offscreen first
  const rc=tt.getBoundingClientRect();
  const vw=window.innerWidth,vh=window.innerHeight,pad=14,edge=8;
  let left=ev.clientX+pad;
  if(left+rc.width>vw-edge)left=ev.clientX-rc.width-pad;   // flip to the left
  if(left<edge)left=edge;
  let top=ev.clientY-10;
  if(top+rc.height>vh-edge)top=vh-rc.height-edge;          // lift up if tall
  if(top<edge)top=edge;
  tt.style.left=left+'px';tt.style.top=top+'px';
}
function wireTrendHover(buckets,opts){
  opts=opts||{};
  const cid=opts.id||'x-trend-svg';
  const tip=opts.tip||(b=>`<b>${b.events}</b> events · ${b.blocked} blocked`);
  const svg=document.getElementById(cid),tt=document.getElementById('x-tt');
  if(!svg)return;
  const cross=svg.querySelector('#'+cid+'-cross');
  svg.addEventListener('mousemove',ev=>{
    const r=ev.target;
    // Marker hover wins: rich data card, no crosshair.
    if(r.dataset&&r.dataset.m!==undefined&&opts.markers&&opts.mtip){
      const m=opts.markers[+r.dataset.m];if(!m)return;
      cross.setAttribute('visibility','hidden');
      tt.innerHTML=opts.mtip(m);
      placeTip(tt,ev);
      return;
    }
    if(!r.dataset||r.dataset.i===undefined){tt.style.display='none';cross.setAttribute('visibility','hidden');return}
    const b=buckets[+r.dataset.i];if(!b)return;
    cross.setAttribute('x1',r.dataset.x);cross.setAttribute('x2',r.dataset.x);cross.setAttribute('visibility','visible');
    const dt=new Date(b.t);
    tt.innerHTML=`${isNaN(dt)?b.t:dt.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} — ${tip(b)}`;
    placeTip(tt,ev);
  });
  svg.addEventListener('mouseleave',()=>{tt.style.display='none';cross.setAttribute('visibility','hidden')});
}

// ── Executive view render ─────────────────────────────────────────────────
const X_STATUS={green:{col:'var(--good)',glyph:'●',word:'Strong'},
                yellow:{col:'var(--warn)',glyph:'▲',word:'Degraded'},
                red:{col:'var(--crit)',glyph:'✖',word:'At risk'}};
let lastTrends=null;
let lastKpisHtml='';
function renderExec(d){
  const s=d.stats||{},r=d.rings||{},t=(s.tokens)||{},p=r.posture;
  // Hero — score, delta, status chip, reasons from non-green controls
  if(p){
    document.getElementById('x-gauge').innerHTML=svgRingGauge(p.score);
    document.getElementById('x-score').textContent=p.score;
    const lvl=p.score>=85?'green':(p.score>=60?'yellow':'red'),st=X_STATUS[lvl];
    const dh=(p.delta_24h==null)?'<span style="color:var(--muted-dim)">— vs 24h ago</span>'
      :deltaHtml(p.score,p.score-p.delta_24h,true)+' <span style="color:var(--muted-dim)">vs 24h ago</span>';
    document.getElementById('x-hero-line').innerHTML=
      `<span class="x-chip" style="color:${st.col};border-color:${st.col}">${st.glyph} ${st.word}</span><span style="font-size:12px">${dh}</span>`;
    // Reasons as a vertical list (was an inline ·-joined line — wrapped badly
    // and stretched the hero); cap at 5 with a +N-more line.
    const bad=Object.entries(p.rings||{}).filter(([,v])=>v.status!=='green');
    document.getElementById('x-reasons').innerHTML = bad.length
      ? bad.slice(0,5).map(([,v])=>`<div><span style="color:${X_STATUS[v.status].col}">${X_STATUS[v.status].glyph}</span> <b>${esc(v.reason)}</b></div>`).join('')
        +(bad.length>5?`<div style="color:var(--muted-dim)">+${bad.length-5} more</div>`:'')
      : 'All nine defense controls reporting healthy.';
  }
  // Control chips — server-derived posture statuses, existing drill-down modals
  const tools=s.tools||{};
  const ctls=[
    ['r1','Firewall',(r.r1_packets_blocked||0)+' blocked',"showRingEvents('nftables','Firewall','Kernel-level packet filtering by UID — blocked outbound connections')"],
    ['r2','Web Proxy',(r.r2_denied||0)+' denied',"showRingEvents('tinyproxy','Web Proxy — denied connections','HTTPS connections rejected by the domain allowlist',{policy:'domain-filter'})"],
    ['r3','OS Isolation',fmtCompact(r.r3_es_events||0)+' events',"showRingEvents('eslogger','OS Isolation','Process executions under the agent UID',{type:'EXEC'})"],
    ['r4','Agent Sandbox',(r.r4_sandboxed_runs||0)+' runs','showRing4()'],
    ['r5','Claude Code',fmtCompact(tools.total||0)+' tool calls',"showRingEvents('claude-code','Claude Code Permissions','Tool calls tracked — per-tool breakdown')"],
    ['r6','CodeGuard',fmtCompact((r.r6_files_scanned||0)+(r.r6_mcp_tools_scanned||0))+' scanned',"showRingEvents('codeguard','Cisco AI Defense','CodeGuard, MCP Scanner, Skill Scanner events')"],
    ['r7','MCP Isolation',fmtCompact(r.r7_mcp_ops||0)+' ops',"showRingEvents('mcp','MCP Token Isolation','GitHub API operations, validation, rate limiting')"],
    ['r8','Validation Gate',(r.r8_validation_failed||0)+' failed','showValidation()'],
    ['r9','Human Review',(r.r9_prs_open||0)+' open PRs','showRing9()']];
  document.getElementById('x-controls').innerHTML=ctls.map(([k,nm,ct,fn])=>{
    const stt=(p&&p.rings&&p.rings[k])?p.rings[k]:{status:'green',reason:''};
    const st=X_STATUS[stt.status]||X_STATUS.green;
    return `<div class="x-ctl" onclick="${esc(fn)}" title="${esc(stt.reason||nm)}"><span class="dot" style="background:${st.col}"></span><span class="nm">${nm}</span><span class="ct">${ct}</span></div>`;
  }).join('');
  // KPI tiles
  const tr=lastTrends||{},ev=tr.eval||{},ac=tr.actions||{},an=tr.antares||{};
  const runsArr=(tr.daily_runs||[]).map(x=>x.runs);
  const runsToday=runsArr.length?runsArr[runsArr.length-1]:null;
  const runsYest=runsArr.length>1?runsArr[runsArr.length-2]:null;
  const blockedArr=(tr.activity||[]).map(x=>x.blocked);
  const blocked24=blockedArr.length?blockedArr.reduce((a,b)=>a+b,0):null;
  const cyc=t.cycle||{};
  const cost=(cyc.estimated_cost_usd!=null)?cyc.estimated_cost_usd:(t.estimated_cost_usd!=null?t.estimated_cost_usd:null);
  const sub=cyc.subscription_amount_usd||200;
  const roi=(cost!=null&&sub)?Math.round(100*cost/sub):null;
  const tok48=(tr.tokens_48h||[]).map(x=>x.total);
  const evalPct=(ev.pass_rate_24h!=null)?ev.pass_rate_24h+'%':'—';
  const tiles=[
    {lbl:'Agent runs · 24h',val:runsToday==null?'—':runsToday,
     sub:deltaHtml(runsToday,runsYest,true)+' vs prior day',
     spark:svgSparkline(runsArr,110,30,6.5),click:"window.open('/agent-walk','_blank')"},
    {lbl:'Issues &amp; PRs handled · 24h',val:ac.handled_24h==null?'—':ac.handled_24h,
     sub:deltaHtml(ac.handled_24h,ac.handled_prev_24h,true)+' vs prior day',
     spark:svgSparkline((ac.handled_7d||[]).map(x=>x.handled),110,30,7.3),click:'showRing9()'},
    {lbl:'Antares vulns · 24h',val:(an.candidates_24h==null)?'—':an.candidates_24h,
     sub:deltaHtml(an.candidates_24h,an.candidates_prev_24h,false)+` · ${an.runs_24h||0} scan${an.runs_24h===1?'':'s'}`,
     spark:svgSparkline((an.cand_7d||[]).map(x=>x.n),110,30,5.6),click:'showAntares()'},
    {lbl:'Run success · 24h',val:evalPct,
     sub:deltaHtml(ev.pass_rate_24h,ev.pass_rate_prev_24h,true)+` · ${ev.runs_24h||0} runs`,
     spark:svgSparkline((ev.success_7d||[]).filter(x=>x.pass_rate!=null).map(x=>x.pass_rate),110,30,8.1),
     click:'showRunSuccess()'},
    {lbl:'Eval quality',val:(ev.score_mean!=null)?ev.score_mean+'%':'—',
     sub:(ev.score_mean!=null)?`scored across ${ev.score_flows} flow${ev.score_flows===1?'':'s'} · daily eval`:'no scored evals yet',
     spark:svgSparkline((ev.quality_48h||[]).map(x=>x.score),110,30,6.9),click:'showEvalQuality()'},
    {lbl:'Cycle API cost avoided',val:cost==null?'—':'$'+Number(cost).toFixed(0),
     sub:roi==null?'Claude MAX subscription':`breakeven ${roi}% · MAX $${sub}/cycle`,
     spark:svgSparkline(tok48,110,30,5.1),click:'showApiCost()'}];
  // Rewrite the tiles only when their content actually changed — an innerHTML
  // replacement restarts the SMIL sparkline animations, and the 3s poll would
  // otherwise reset them before a single traversal completes.
  const kpisHtml=tiles.map(x=>
    `<div class="x-tile" onclick="${esc(x.click)}"><div class="lbl">${x.lbl}</div><div class="val">${x.val}</div><div class="sub">${x.sub}</div>${x.spark?`<div class="spark">${x.spark}</div>`:''}</div>`).join('');
  if(kpisHtml!==lastKpisHtml){
    lastKpisHtml=kpisHtml;
    document.getElementById('x-kpis').innerHTML=kpisHtml;
  }
  // Trend chart — re-rendered only when trends refresh (cheap guard: cache key)
  const tw=document.getElementById('x-trend');
  const key=tr.generated_at||'';
  if(tw.dataset.key!==key&&tr.activity){
    tw.dataset.key=key;
    const w=Math.max(tw.clientWidth||0,320);
    const titles=(lastData&&lastData.rings&&lastData.rings.issue_titles)||{};
    const fT=s=>{const d=new Date(s);return isNaN(d)?'':d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})};
    // Workflow-kind styling: color + label + issue/PR prefix.
    const WF={triage:{c:'#21a184',l:'Triage',p:'#'},implement:{c:'#bd7c20',l:'Implement',p:'#'},
              review:{c:'#a878e0',l:'PR review',p:'PR #'},detect:{c:'#e85578',l:'Antares',p:'#'}};
    // CodeGuard OS-telemetry run markers (clustered server-side, magenta).
    const cg=(tr.codeguard_24h||[]).map(m=>({...m,kind:'codeguard',color:'#d94fd4',r:4}));
    // Workflow markers (triage / implement / review / antares passes).
    const wf=(tr.workflow_24h||[]).map(m=>({...m,color:(WF[m.kind]||{}).c||'#5de3ff'}));
    // One merged, time-sorted marker array; per-marker color drives the dot.
    const marks=cg.concat(wf).sort((a,b)=>new Date(a.t)-new Date(b.t));
    // Unified hover card — dispatches on kind.
    const card=m=>{
      if(m.kind==='codeguard'){
        const t0=fT(m.t),t1=fT(m.t_end);
        let s=`<div style="white-space:normal;max-width:380px">`+
          `<div style="font-weight:600;color:#eaf2fb;margin-bottom:5px"><span style="color:#d94fd4">&#9679;</span> CodeGuard run &middot; ${t0}${(t1&&t1!==t0)?'&ndash;'+t1:''} &middot; ${m.count} event${m.count===1?'':'s'}</div>`;
        for(const e of (m.events||[]).slice(0,8)){
          s+=`<div style="display:flex;gap:6px;margin-top:2px;font-size:11px">`+
             `<span style="color:#d94fd4;font-weight:600;flex:0 0 auto">${esc(e.type||'EVENT')}</span>`+
             `<span style="color:#c4d4e8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.args||e.policy||'')}</span></div>`;
        }
        if(m.count>(m.events||[]).length)s+=`<div style="color:#8598b4;margin-top:4px;font-size:10px">+${m.count-(m.events||[]).length} more &middot; full detail in the CodeGuard modal</div>`;
        return s+'</div>';
      }
      // Workflow card: kind · #/PR # + title, then the sweep finding line(s).
      const wk=WF[m.kind]||{c:'#5de3ff',l:m.kind,p:'#'};
      const title=titles[m.num]||'';
      let s=`<div style="white-space:normal;max-width:400px">`+
        `<div style="font-weight:600;color:#eaf2fb;margin-bottom:2px"><span style="color:${wk.c}">&#9679;</span> ${wk.l} &middot; ${wk.p}${esc(m.num)} &middot; ${fT(m.t)}</div>`;
      if(title)s+=`<div style="color:#c4d4e8;font-size:12px;margin-bottom:5px">${esc(title)}</div>`;
      // Antares finding (verdict + rationale/candidates).
      if(m.antares){
        s+=`<div style="display:flex;gap:6px;margin-top:3px;font-size:11px">`+
           `<span style="color:#e85578;font-weight:600;flex:0 0 auto">Antares</span>`+
           `<span style="color:#d7e2f2">${esc(m.antares)}</span></div>`;
      }else if(m.antares_verdict){
        s+=`<div style="font-size:11px;margin-top:3px"><span style="color:#e85578;font-weight:600">Antares</span> <span style="color:#8598b4">${esc(m.antares_verdict)}</span></div>`;
      }else if(m.kind==='detect'&&m.detail){
        s+=`<div style="font-size:11px;margin-top:3px"><span style="color:#e85578;font-weight:600">Antares</span> <span style="color:#d7e2f2">${esc(m.detail)}</span></div>`;
      }
      // CodeGuard PR finding.
      if(m.codeguard){
        s+=`<div style="display:flex;gap:6px;margin-top:3px;font-size:11px">`+
           `<span style="color:#d94fd4;font-weight:600;flex:0 0 auto">CodeGuard</span>`+
           `<span style="color:#d7e2f2">${esc(m.codeguard)}${m.codeguard_more>0?` <span style="color:#8598b4">+${m.codeguard_more} more</span>`:''}</span></div>`;
      }
      if(!m.antares&&!m.antares_verdict&&!m.codeguard&&!(m.kind==='detect'&&m.detail))
        s+=`<div style="color:#8598b4;font-size:10px;margin-top:3px">no sweep findings</div>`;
      return s+'</div>';
    };
    tw.innerHTML=svgAreaChart(tr.activity,w,160,{dur:10.7,markers:marks,mtip:card});
    wireTrendHover(tr.activity,{markers:marks,mtip:card});
    const tot=tr.activity.reduce((a,b)=>a+b.events,0);
    // Legend — count by kind, then total events.
    const kc={};wf.forEach(m=>{kc[m.kind]=(kc[m.kind]||0)+1});
    let leg=Object.keys(WF).filter(k=>kc[k]).map(k=>`<span style="color:${WF[k].c}">&#9679;</span> ${kc[k]} ${WF[k].l.toLowerCase()}`).join(' &nbsp; ');
    if(cg.length)leg+=`${leg?' &nbsp; ':''}<span style="color:#d94fd4">&#9679;</span> ${cg.length} CodeGuard`;
    document.getElementById('x-trend-total').innerHTML=
      `${leg?leg+' &nbsp;&middot;&nbsp; ':''}${fmtCompact(tot)} events`;
  }
  // Alerts — section hidden entirely when quiet
  const alerts=s.alerts||[];
  document.getElementById('x-alerts').classList.toggle('empty',!alerts.length);
  if(alerts.length){
    document.getElementById('x-alert-rows').innerHTML=alerts.slice(-5).reverse().map(a=>
      `<div class="x-row"><span class="tm">${fmtTime(a.time)}</span><span>${esc(a.msg)}</span></div>`).join('');
  }
  // Latest 5 agent activities. NOTE: recent_activity lives on d.rings
  // (ring_stats), NOT d.stats — reading s.recent_activity left this section
  // permanently empty. Items carry {op, time, url}; the issue/PR number is
  // extracted from the url (same convention as the ops panel).
  const titlesX=r.issue_titles||{};
  const acts=(r.recent_activity||[]).slice(-5).reverse();
  document.getElementById('x-activity').innerHTML=acts.length?acts.map(a=>{
    let num='';
    if(a.url){const m2=a.url.match(/\/(\d+)/g);if(m2)num=m2[m2.length-1].substring(1)}
    const ttl=titlesX[num]||titlesX['d'+num]||titlesX['pr'+num]||'';
    return `<div class="x-row"><span class="tm">${fmtTime(a.time)}</span><span>${esc(a.op||'')}</span>${a.url?`<a href="${a.url}" target="_blank">#${esc(num)}${ttl?' — '+esc(ttl.substring(0,40)):''}</a>`:''}</div>`;
  }).join(''):'<div class="x-row" style="color:var(--muted-dim)">No agent activity yet</div>';
}
// Trends poll — slow cadence (server caches 60s anyway). NOTE: identifier must
// not contain the templated refresh-interval token name (string-replaced at
// serve time).
const TREND_POLL_MS=60000;
function pollTrends(){
  fetch('/api/trends').then(r=>r.json()).then(d=>{
    lastTrends=d;
    if(curView==='exec'&&lastData&&lastData.stats)renderExec(lastData);
  }).catch(()=>{});
}
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
storeData(d);   // ALWAYS first — every modal renders from lastData
updateHeaderStatus(d.rings);
if(curView==='ops'){renderOps(d);renderEvents(d.events,d.total,d.filtered||d.total);}
else if(typeof renderExec==='function'){renderExec(d);}
}).catch(()=>{})
if(curView==='ops')renderEval();
}
function updateHeaderStatus(r){
const asi=document.getElementById('agent-status');if(r.agent_running){asi.innerHTML='&#9679; LIVE';asi.style.color='#27a86f'}else{asi.innerHTML='&#9679; IDLE';asi.style.color='#e8506a'}
}
function renderOps(d){
const s=d.stats,r=d.rings,t=d.stats.tokens||{};
// Rings
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
if(r.r8_validation_failed>0){document.querySelector('#ring8 .status').className='status red';document.getElementById('r8v').style.color='#e8506a';}
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
th+=`<div class="si"><span class="n" style="color:#27a86f">API Cost (avoided)</span><span class="c" style="color:#27a86f">$${t.estimated_cost_usd||0}</span></div>`;
// Two ROI views: current billing cycle (resets on the subscription bill
// day each month) and lifetime (cumulative since the first cycle).
// Server-provided so the JS doesn't need its own date math.
const cyc=t.cycle||{},life=t.lifetime||{};
const cycCost=cyc.estimated_cost_usd||0;
const cycSub=cyc.subscription_amount_usd||200;
const cycRoi=cycCost-cycSub;
const cycRoiColor=cycRoi>=0?'#27a86f':'#b3831c';
const cycRoiLabel=cycRoi>=0?'Cycle ROI (profit)':'Cycle ROI (building)';
const cycPct=Math.round((cycCost/cycSub)*100);
const lifeCost=life.estimated_cost_usd||0;
const lifeSub=life.subscription_total_usd||cycSub;
const cycles=life.subscription_cycles_paid||1;
const lifeRoi=lifeCost-lifeSub;
const lifeRoiColor=lifeRoi>=0?'#27a86f':'#b3831c';
const lifeRoiLabel=lifeRoi>=0?'Lifetime ROI (profit)':'Lifetime ROI (building)';
const lifePct=Math.round((lifeCost/lifeSub)*100);
th+=`<div class="si"><span class="n">— This Cycle (since ${cyc.cycle_start_iso||'?'}) —</span><span class="c"></span></div>`;
th+=`<div class="si"><span class="n">MAX Subscription</span><span class="c">$${cycSub}</span></div>`;
th+=`<div class="si"><span class="n">Cycle API Cost</span><span class="c">$${cycCost.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n" style="color:${cycRoiColor}">${cycRoiLabel}</span><span class="c" style="color:${cycRoiColor}">${cycRoi>=0?'+':''}$${cycRoi.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n">Cycle Breakeven</span><span class="c">${cycPct}%</span></div>`;
th+=`<div class="si"><span class="n">— Lifetime (since ${life.subscription_start_iso||'?'}, ${cycles} cycle${cycles===1?'':'s'}) —</span><span class="c"></span></div>`;
th+=`<div class="si"><span class="n">Lifetime Subscription</span><span class="c">$${lifeSub.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n">Lifetime API Cost</span><span class="c">$${lifeCost.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n" style="color:${lifeRoiColor}">${lifeRoiLabel}</span><span class="c" style="color:${lifeRoiColor}">${lifeRoi>=0?'+':''}$${lifeRoi.toFixed(2)}</span></div>`;
th+=`<div class="si"><span class="n">Lifetime Breakeven</span><span class="c">${lifePct}%</span></div>`;
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
gh+=`<div class="si"><span class="n" style="color:#21a184">Total Reads</span><span class="c">${tr}</span></div>`;
gh+=`<div class="si"><span class="n" style="color:#b3831c">Total Writes</span><span class="c">${tw}</span></div>`;
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
cs+=`<div class="si clickable" onclick="showTetragon()"><span class="n"><span class="stag tetragon">ebpf</span> Tetragon</span><span class="c" style="color:#27a86f">active</span></div>`;
cs+=`<div class="si clickable" onclick="showAibom()"><span class="n"><span class=\"stag codeguard\">scan</span> AIBOM (C++)</span><span class="c">${r.r6_aibom_components||0} components · ${r.r6_aibom_models||0} models</span></div>`;
cs+=`<div class="si clickable" onclick="showAntares()"><span class="n"><span class="stag mcp">detect</span> Antares Detector</span><span class="c">${(r.r6_antares_candidates||0)} candidates${r.r6_antares_last_issue?` · #${r.r6_antares_last_issue}`:''}</span></div>`;
cs+=`<div class="si"><span class="n muted">AI Defense SDK</span><span class="c muted">pending license</span></div>`;
cs+=`<div class="si"><span class="n muted">A2A Scanner</span><span class="c muted">single agent (N/A)</span></div>`;
cs+=`<div class="si"><span class="n">Project SBOM</span><span class="c"><a href="/sbom.json" target="_blank" style="color:#5de3ff;text-decoration:none">View</a></span></div>`;
cs+=`<div class="si"><span class="n">Agent SBOM</span><span class="c"><a href="/agent-sbom.json" target="_blank" style="color:#5de3ff;text-decoration:none">View</a></span></div>`;
cs+=`<div class="si" id="carto-row"><span class="n"><span class="stag tetragon">map</span> Cartographer</span><span class="c muted" id="carto-val">…</span></div>`;
document.getElementById('cisco-scanners').innerHTML=cs;
// Cartographer repo-pack summary — own fetch (published on the codegraph
// cadence, not the /api/events poll). Fill the row once loaded.
fetch('/api/cartographer').then(r=>r.json()).then(cd=>{
  const el=document.getElementById('carto-val');if(!el)return;
  if(!cd.available){el.textContent='no pack yet';return}
  const tot=Object.values(cd.categories||{}).reduce((a,b)=>a+b,0);
  el.classList.remove('muted');
  el.innerHTML=`${tot} sites · ${cd.open_cve_count} CVEs · <a href="/cartographer" target="_blank" style="color:#5de3ff;text-decoration:none">view</a>`;
  const row=document.getElementById('carto-row');
  if(row)row.title=`HEAD ${(cd.head_sha||'').slice(0,12)} · ${cd.subsystems} subsystems · generated ${cd.generated_at}`;
}).catch(()=>{});
// Policies
// Recent Agent Activity
let ph='';
const activity=r.recent_activity||[];
const titles=r.issue_titles||{};
const opColors={'Commented on issue':'#5de3ff','Created PR':'#27a86f','Replied to discussion':'#a878e0','Read discussion':'#607080','Reviewed PR':'#b3831c','Checked CI':'#21a184','Searched issues':'#607080'};
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
else{const ghUrl=a.num?`https://github.com/aethersdr/AetherSDR/issues/${a.num}`:'';const numTitle=titles[a.num]||'';const numTitleStr=numTitle?` — ${numTitle.substring(0,40)}`:'';if(a.num)ph+=`<div class="si"><span class="n"><span style="color:#505060;font-size:10px">${t}</span> <span style="color:${col}">${label}</span> <a href="${ghUrl}" target="_blank" style="color:#c8d8e8;text-decoration:none">#${a.num}${numTitleStr}</a></span></div>`;else ph+=`<div class="si"><span class="n"><span style="color:#505060;font-size:10px">${t}</span> <span style="color:${col}">${label}</span></span></div>`;}
}
document.getElementById('pols').innerHTML=ph||'<div class="si"><span class="n muted">Waiting for agent activity...</span></div>';

// Alerts
let ah='';for(const a of(s.alerts||[]).reverse())ah+=`<div class="ai ${a.severity}"><div class="msg">${esc(a.msg)}</div><div class="at">${fmtTime(a.time)}</div></div>`;
document.getElementById('als').innerHTML=ah||'<div class="si"><span class="n muted">No alerts</span></div>';
}
// Eval panel — per-flow Galileo scores + recent runs deep-linking to the
// Agent Walk swimlane (trace) and to the Galileo trace. Own fetch so it stays
// decoupled from the /api/events payload.
let lastEval=null;   // cached for the exec view's eval KPI tile (C4)
function renderEval(){
fetch('/api/eval').then(r=>r.json()).then(d=>{
lastEval=d;
const flows=d.flows||[],recent=d.recent||[];
const flabel={triage:'Triage',implement:'Implement',review:'Review',ci:'CI',duplicate:'Dup',mention:'Mention',other:'Other'};
let h='';
if(!flows.length){h='<div class="si"><span class="n muted">No eval runs yet</span></div>';}
else{for(const f of flows){
const pr=(f.pass_rate==null)?'&mdash;':f.pass_rate+'%';
const col=(f.pass_rate==null)?'#607080':(f.pass_rate>=80?'#27a86f':(f.pass_rate>=50?'#b3831c':'#e8506a'));
let sc='';if(f.scores){const ks=Object.keys(f.scores).slice(0,3);sc=ks.map(k=>`${k} ${Math.round(f.scores[k]*100)}%`).join(' · ');}
h+=`<div class="si"><span class="n"><span style="color:#c8d8e8">${flabel[f.flow]||esc(f.flow)}</span> <span style="color:${col};font-weight:bold">${pr}</span> <span style="color:#505060;font-size:10px">${f.ok||0}/${f.runs||0} ok${sc?' · '+esc(sc):''}</span></span></div>`;
}}
if(recent.length){
h+='<div style="margin-top:6px;border-top:1px solid #1a2230;padding-top:4px">';
for(const e of recent.slice(0,6)){
const scol=e.status==='ok'?'#27a86f':'#e8506a';
const ref=e.ref?('#'+esc(String(e.ref))):'';
const walk=e.trace_id?`onclick="window.open('/agent-walk?trace='+encodeURIComponent('${e.trace_id}'),'_blank')" style="cursor:pointer"`:'';
const gal=e.galileo_trace_url?` <a href="${e.galileo_trace_url}" target="_blank" style="color:#5de3ff;text-decoration:none;font-size:10px">&#8599;G</a>`:'';
h+=`<div class="si" ${walk}><span class="n"><span style="color:#505060;font-size:10px">${fmtTime(e.ts)}</span> <span style="color:${scol}">&#9679;</span> <span style="color:#c8d8e8">${esc(e.flow)}${ref}</span>${gal}</span></div>`;
}
h+='</div>';}
document.getElementById('eval-panel').innerHTML=h;
}).catch(()=>{document.getElementById('eval-panel').innerHTML='<div class="si"><span class="n muted">Eval unavailable</span></div>';})}
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
if(t.threat_name)fh+=`<div class="detail" style="margin-top:2px;color:#e85578">Threat: ${esc(t.threat_name)}</div>`;
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
    fh+=`<div class="detail" style="margin-top:4px;color:#e85578">⚠ ${esc(f.severity||'')} ${esc(f.technique_name||'')}: ${esc(f.summary||'')}</div>`;
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
function showAntares(){
const cands=lastData.rings?.r6_antares_candidates||0;
const verdict=lastData.rings?.r6_antares_verdict||'';
const lastIssue=lastData.rings?.r6_antares_last_issue||'';
let h='<p style="color:#8598b4;margin-bottom:12px">Cisco Foundation AI <strong>Antares-1B</strong> — a local 1B vulnerability-localization model. On every issue/PR it explores the repo via a sandboxed terminal loop (grep/find/cat/ls only, ≤15 commands), seeded by the Cartographer security overlay, and reports candidate vulnerable files. Advisory (the Foundry Detector stage).</p>';
const sev=cands>0?'HIGH':'SAFE';
h+=`<div class="modal-finding ${sev}"><span class="sev ${sev}">${cands>0?'CANDIDATES':'CLEAN'}</span> latest run${lastIssue?` (#${esc(String(lastIssue))})`:''}: ${cands} candidate file${cands===1?'':'s'}${verdict?` · verdict ${esc(verdict)}`:''}</div>`;
h+=`<div id="antares-list" style="margin-top:12px"><p style="color:#8598b4">Loading detector findings…</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#8598b4">Model served locally via Ollama (loopback) · sandboxed allowlist-jail loop (bin/antares-detector.py) · seeded by the <a href="/cartographer" target="_blank" style="color:#5de3ff;text-decoration:none">Cartographer</a> --cwe overlay</div>`;
document.getElementById('modal-title').textContent='Antares Detector — Vulnerability Localization';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/antares').then(r=>r.json()).then(d=>{
let fh='';
if(!d.findings.length){document.getElementById('antares-list').innerHTML='<p style="color:#8598b4">No detector runs recorded yet.</p>';return}
fh+=`<p style="color:#8598b4;margin-bottom:8px">${d.runs} run${d.runs===1?'':'s'} · ${d.total} candidate row${d.total===1?'':'s'} in database</p>`;
// group by run (scan_time)
const byRun={};
for(const f of d.findings){(byRun[f.scan_time]=byRun[f.scan_time]||[]).push(f)}
for(const [ts,rows] of Object.entries(byRun).slice(0,20)){
const r0=rows[0],hasCand=rows.some(x=>x.file);
const sc=hasCand?'HIGH':'SAFE';
fh+=`<div class="modal-finding ${sc}" style="margin-bottom:8px">`;
fh+=`<span class="sev ${sc}">${hasCand?'CANDIDATES':esc((r0.verdict||'clean').toUpperCase())}</span> `;
fh+=`<strong>${r0.issue?'#'+esc(String(r0.issue)):'(no issue)'}</strong>${r0.cwe?` · ${esc(r0.cwe)}`:''}`;
fh+=`<span style="color:#5f708a;font-size:10px;margin-left:6px">${esc(ts)} · ${r0.commands_used||0} cmds</span>`;
if(hasCand){fh+='<div style="margin-top:4px">';
for(const f of rows){if(!f.file)continue;
fh+=`<div class="detail" style="margin-top:2px"><span style="color:#e85578;font-weight:600">${f.rank}.</span> <code>${esc(f.file)}</code></div>`;}
fh+='</div>';
if(r0.rationale)fh+=`<div class="detail" style="margin-top:4px;color:#c4d4e8">${esc(r0.rationale)}</div>`;}
fh+='</div>';}
document.getElementById('antares-list').innerHTML=fh;
}).catch(()=>{document.getElementById('antares-list').innerHTML='<p style="color:#604040">Failed to load detector findings.</p>'})}
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
    const link=(v.references&&v.references[0])?` <a href="${esc(v.references[0])}" target="_blank" style="color:#5de3ff;text-decoration:none">[advisory]</a>`:'';
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
if(e.type)fh+=`<span style="color:#b3831c;margin-right:6px;font-weight:bold">${esc(e.type)}</span>`;
if(bin)fh+=`<span style="color:#5de3ff;margin-right:6px">${esc(bin)}</span>`;
fh+=`${esc(args)}`;
if(e.policy)fh+=` <span style="color:#e85578;font-size:10px">[${esc(e.policy)}]</span>`;
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
fh+=`<span style="color:#b3831c;margin-right:6px">${(t.event_count||0).toLocaleString()} ev</span>`;
if(evType)fh+=`<span style="color:#5de3ff;margin-right:6px">${esc(evType)}</span>`;
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
for(const p of d.open)fh+=`<div class="modal-finding MEDIUM" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/aethersdr/AetherSDR/pull/${p.number}" target="_blank" style="color:#5de3ff;text-decoration:none">#${p.number}</a> ${esc(p.title)}${p.draft?' <span style="color:#607080;font-size:10px">(draft)</span>':''}</div>`}
if(d.merged&&d.merged.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Recently merged:</p>';
for(const p of d.merged)fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/aethersdr/AetherSDR/pull/${p.number}" target="_blank" style="color:#5de3ff;text-decoration:none">#${p.number}</a> ${esc(p.title)}</div>`}
if(d.rejected&&d.rejected.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Rejected:</p>';
for(const p of d.rejected)fh+=`<div class="modal-finding HIGH" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/aethersdr/AetherSDR/pull/${p.number}" target="_blank" style="color:#5de3ff;text-decoration:none">#${p.number}</a> ${esc(p.title)}</div>`}
if(d.issues&&d.issues.length>0){
const stateColors={done:'#27a86f',failed:'#e8506a',declined:'#607080',implement:'#b3831c',waiting:'#21a184',triage:'#5de3ff','new':'#c8d8e8'};
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Issue pipeline (from DB):</p>';
for(const i of d.issues){
const col=stateColors[i.state]||'#c8d8e8';
const det=i.detail?` <span style="color:#607080;font-size:10px">— ${esc(i.detail.substring(0,60))}</span>`:'';
const ts=fmtTime(i.last_seen);
fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px;display:flex;align-items:center;gap:8px"><a href="https://github.com/aethersdr/AetherSDR/issues/${i.number}" target="_blank" style="color:#5de3ff;text-decoration:none;min-width:40px">#${i.number}</a><span style="color:${col};font-weight:bold;min-width:70px">${i.state}</span><span style="color:#8090a0;font-size:10px;min-width:90px">${esc(i.last_action||'')}</span>${det}<span style="color:#505060;font-size:9px;margin-left:auto">${ts}</span></div>`}}
if(d.discussions&&d.discussions.length>0){
fh+='<p style="color:#607080;margin-bottom:6px;margin-top:12px;font-weight:bold">Discussions responded to:</p>';
for(const disc of d.discussions)fh+=`<div class="modal-finding SAFE" style="margin-bottom:3px;padding:4px 8px"><a href="https://github.com/aethersdr/AetherSDR/discussions/${disc.number}" target="_blank" style="color:#5de3ff;text-decoration:none">#${disc.number}</a> ${esc(disc.title)} <span style="color:#607080;font-size:10px">${esc(disc.category)} · ${disc.comments} comments</span></div>`}
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
if(reason)fh+=`<div class="detail" style="color:#e8506a;margin-top:2px">&#x2718; ${esc(reason)}</div>`;
}
fh+=`</div>`}
fh+=`</div>`}
document.getElementById('val-list').innerHTML=fh;
}).catch(()=>{document.getElementById('val-list').innerHTML='<p style="color:#604040">Failed to load validation data.</p>'})}
// Eval Quality modal — dedicated breakdown of the agent-decision scoring
// (daily run-eval experiments: per-flow deterministic scorers + Galileo).
// Deliberately distinct from run-success (did claude exit 0).
function showEvalQuality(){
const ev=(lastTrends&&lastTrends.eval)||{};
const flabel={triage:'Triage',implement:'Implement',review:'Review',ci:'CI',duplicate:'Duplicate',mention:'Mention',other:'Other'};
let h='<p style="color:#8598b4;margin-bottom:12px">How good are the agent&#8217;s decisions? Each flow is scored daily against a curated dataset (known-good triage labels, expected fix scope, a seeded stale-code regression the reviewer must catch). Scores come from deterministic scorers over real Claude assessments, logged to Galileo as experiments.</p>';
const sm=ev.score_mean;
const sev=sm==null?'SAFE':(sm>=80?'SAFE':(sm>=50?'MEDIUM':'HIGH'));
const glyph=sm==null?'—':(sm>=80?'&#9679;':(sm>=50?'&#9650;':'&#10008;'));
h+=`<div class="modal-finding ${sev}"><span class="sev ${sev}">${glyph} ${sm==null?'UNSCORED':sm+'%'}</span> overall decision quality — mean of the newest experiment per flow${ev.score_flows?` (${ev.score_flows} flow${ev.score_flows===1?'':'s'})`:''}</div>`;
h+=`<div class="modal-finding SAFE"><span class="sev SAFE">${ev.pass_rate_24h!=null?ev.pass_rate_24h+'%':'—'}</span> run success &middot; 24h (${ev.runs_24h||0} runs) — separate metric: did the agent process complete, not whether its output was good</div>`;
h+=`<div id="evq-list" style="margin-top:12px"><p style="color:#8598b4">Loading per-flow scores...</p></div>`;
h+=`<div class="detail" style="margin-top:12px;color:#8598b4">Scored daily at 05:00 by run-eval &middot; datasets in .galileo/datasets &middot; <a href="https://app.galileo.ai/" target="_blank" style="color:#5de3ff;text-decoration:none">Galileo console &#x2197;</a></div>`;
document.getElementById('modal-title').textContent='Eval Quality — Agent Decision Scoring';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/eval').then(r=>r.json()).then(d=>{
const scored=(d.flows||[]).filter(f=>f.scores);
if(!scored.length){document.getElementById('evq-list').innerHTML='<p style="color:#8598b4">No scored experiments yet — the daily eval job hasn&#8217;t produced results. Run <code style="background:var(--bg-2);padding:1px 4px;border-radius:3px">run-eval.sh</code> or wait for the 05:00 cycle.</p>';return}
let fh='';
for(const f of scored){
const vals=Object.values(f.scores).filter(v=>typeof v==='number');
const mean=vals.length?Math.round(100*vals.reduce((a,b)=>a+b,0)/vals.length):null;
const msev=mean==null?'SAFE':(mean>=80?'SAFE':(mean>=50?'MEDIUM':'HIGH'));
fh+=`<div class="modal-finding ${msev}" style="margin-bottom:8px"><span class="sev ${msev}">${mean==null?'—':mean+'%'}</span> <span class="tool-name">${flabel[f.flow]||esc(f.flow)}</span>`;
for(const [k,v] of Object.entries(f.scores)){
if(typeof v!=='number')continue;
const pct=Math.round(100*v);
const col=pct>=80?'var(--good)':(pct>=50?'var(--warn)':'var(--crit)');
fh+=`<div style="display:flex;align-items:center;gap:8px;margin-top:6px">`+
`<span style="width:170px;font-size:11px;color:#c4d4e8">${esc(k.replace(/_/g,' '))}</span>`+
`<span style="flex:1;max-width:220px;height:6px;background:var(--bg-3);border-radius:3px;overflow:hidden;display:inline-block"><span style="display:block;height:100%;width:${pct}%;background:${col};border-radius:3px"></span></span>`+
`<span style="font-size:11px;color:#c4d4e8;width:36px;text-align:right">${pct}%</span></div>`;
}
fh+=`</div>`;
}
document.getElementById('evq-list').innerHTML=fh;
}).catch(()=>{document.getElementById('evq-list').innerHTML='<p style="color:#604040">Failed to load eval data.</p>'})}
// Run Success modal — execution health of agent runs (did each claude
// invocation complete), with per-flow rates and the recent run list.
// Companion to showEvalQuality (was the output GOOD) — kept deliberately
// separate: this metric is what surfaced the expired-OAuth incident.
function showRunSuccess(){
const ev=(lastTrends&&lastTrends.eval)||{};
const flabel={triage:'Triage',implement:'Implement',review:'Review',ci:'CI',duplicate:'Duplicate',mention:'Mention',other:'Other'};
let h='<p style="color:#8598b4;margin-bottom:12px">Did each agent run complete? One record per Claude invocation (triage, implement, review, CI-explain, duplicate-check), marked <b style="color:#c4d4e8">ok</b> when the run exited cleanly and <b style="color:#c4d4e8">fail</b> on watchdog kills, auth errors, or exhausted retries. Execution health only — decision quality is scored separately (see the Eval Quality tile).</p>';
const pr=ev.pass_rate_24h;
const sev=pr==null?'SAFE':(pr>=95?'SAFE':(pr>=80?'MEDIUM':'HIGH'));
const glyph=pr==null?'—':(pr>=95?'&#9679;':(pr>=80?'&#9650;':'&#10008;'));
h+=`<div class="modal-finding ${sev}"><span class="sev ${sev}">${glyph} ${pr==null?'NO RUNS':pr+'%'}</span> run success &middot; <b>last 24h only</b> (${ev.runs_24h||0} runs)${ev.pass_rate_prev_24h!=null?` &middot; prior 24h: ${ev.pass_rate_prev_24h}%`:''}</div>`;
h+=`<div id="rs-list" style="margin-top:12px"><p style="color:#8598b4">Loading runs...</p></div>`;
// GitHub Actions CI — the other half of execution health: the agent ran
// clean AND its work built green. Rendered from the cached ring_stats
// (ci_runs, refreshed ~60s server-side); no extra fetch.
const ci=(lastData.rings&&lastData.rings.ci_runs)||[];
h+='<div style="border-top:1px solid var(--line);margin-top:12px;padding-top:10px">';
h+='<div style="font-size:12px;font-weight:600;color:#8598b4;letter-spacing:.3px;margin-bottom:6px">GITHUB CI &middot; AetherSDR workflow runs</div>';
if(!ci.length){h+='<p style="color:#8598b4;font-size:12px">No CI data yet (fetch pending or API unavailable).</p>'}
else{
const day=Date.now()-86400000;
const recent24=ci.filter(w=>new Date(w.created_at).getTime()>=day);
const done24=recent24.filter(w=>w.conclusion);
const ok24=done24.filter(w=>w.conclusion==='success').length;
const rate=done24.length?Math.round(100*ok24/done24.length):null;
const csev=rate==null?'SAFE':(rate>=90?'SAFE':(rate>=70?'MEDIUM':'HIGH'));
const cglyph=rate==null?'—':(rate>=90?'&#9679;':(rate>=70?'&#9650;':'&#10008;'));
h+=`<div class="modal-finding ${csev}"><span class="sev ${csev}">${cglyph} ${rate==null?'NO COMPLETED RUNS':rate+'%'}</span> CI success &middot; last 24h (${ok24}/${done24.length} passed${recent24.length>done24.length?`, ${recent24.length-done24.length} in progress`:''})</div>`;
const CICON={success:['&#9679;','var(--good)','PASS'],failure:['&#10008;','var(--crit)','FAIL'],cancelled:['&#8856;','var(--muted-dim)','CANCELLED'],skipped:['&#8856;','var(--muted-dim)','SKIPPED'],timed_out:['&#10008;','var(--crit)','TIMEOUT'],action_required:['&#9650;','var(--warn)','ACTION REQ']};
for(const w of ci.slice(0,10)){
const ic=w.conclusion?(CICON[w.conclusion]||['&#9650;','var(--warn)',esc(w.conclusion.toUpperCase())]):['&#9711;','var(--accent)','RUNNING'];
h+=`<div style="display:flex;align-items:center;gap:8px;padding:4px 2px;border-bottom:1px solid var(--line);font-size:11px">`+
`<span style="color:${ic[1]};width:86px;flex:0 0 auto;font-weight:600">${ic[0]} ${ic[2]}</span>`+
`<span style="color:#c4d4e8;width:150px;flex:0 0 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(w.name)}</span>`+
`<span style="flex:1;color:#8598b4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(w.title||w.branch)}</span>`+
`<span style="color:#5f708a;font-size:10px;flex:0 0 auto">${fmtTime(w.created_at)}</span>`+
`<a href="${w.url}" target="_blank" style="color:#5de3ff;text-decoration:none;font-size:10px;flex:0 0 auto">view &#x2197;</a></div>`;
}
}
h+='</div>';
h+=`<div class="detail" style="margin-top:12px;color:#8598b4">Recorded by the run_claude hook in run-agent.sh &middot; every run is also a Galileo trace (log stream <span style="color:#c4d4e8">agent-runs</span>) &middot; <a href="https://app.galileo.ai/" target="_blank" style="color:#5de3ff;text-decoration:none">Galileo console &#x2197;</a></div>`;
document.getElementById('modal-title').textContent='Run Success — Agent Execution Health';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
fetch('/api/eval').then(r=>r.json()).then(d=>{
let fh='';
const withRuns=(d.flows||[]).filter(f=>f.runs>0);
if(withRuns.length){
fh+='<div style="margin-bottom:10px">';
for(const f of withRuns){
const prf=f.pass_rate;
const col=prf>=95?'var(--good)':(prf>=80?'var(--warn)':'var(--crit)');
fh+=`<div style="display:flex;align-items:center;gap:8px;margin-top:6px">`+
`<span style="width:110px;font-size:11px;color:#c4d4e8">${flabel[f.flow]||esc(f.flow)}</span>`+
`<span style="flex:1;max-width:220px;height:6px;background:var(--bg-3);border-radius:3px;overflow:hidden;display:inline-block"><span style="display:block;height:100%;width:${prf}%;background:${col};border-radius:3px"></span></span>`+
`<span style="font-size:11px;color:#c4d4e8;width:40px;text-align:right">${prf}%</span>`+
`<span style="font-size:10px;color:#8598b4">${f.ok}/${f.runs} ok</span></div>`;
}
fh+='<div style="font-size:10px;color:#5f708a;margin-top:6px">per-flow rates &middot; recent run history (last ~200 runs, spans multiple days) — intentionally wider than the 24h headline above</div></div>';
}
const runs=(d.recent||[]).filter(e=>e.kind==='run').slice(0,12);
if(!runs.length&&!withRuns.length){fh='<p style="color:#8598b4">No agent runs recorded yet.</p>'}
else{
fh+='<div style="border-top:1px solid var(--line);padding-top:8px">';
for(const e of runs){
const ok=e.status==='ok';
const walk=e.trace_id?` onclick="window.open('/agent-walk?trace='+encodeURIComponent('${e.trace_id}'),'_blank')" style="cursor:pointer"`:'';
fh+=`<div class="modal-finding ${ok?'SAFE':'HIGH'}"${walk} title="${e.trace_id?'Open in Agent Walk':''}" >`+
`<span class="sev ${ok?'SAFE':'HIGH'}">${ok?'&#9679; OK':'&#10008; FAIL'}</span> `+
`<span class="tool-name">${flabel[e.flow]||esc(e.flow||'')}</span>${e.ref?' #'+esc(String(e.ref)):''} `+
`<span style="color:#5f708a;font-size:10px">${fmtTime(e.ts)}</span>`+
`${e.galileo_trace_url?` <a href="${e.galileo_trace_url}" target="_blank" onclick="event.stopPropagation()" style="color:#5de3ff;text-decoration:none;font-size:10px">Galileo &#x2197;</a>`:''}</div>`;
}
fh+='</div>';
}
document.getElementById('rs-list').innerHTML=fh;
}).catch(()=>{document.getElementById('rs-list').innerHTML='<p style="color:#604040">Failed to load run data.</p>'})}
// API Cost modal — the tokenomics story: the agent runs on a flat Claude MAX
// subscription; 'avoided' = what the same tokens would have cost at
// per-model API rates. Includes the 48h hourly token-usage chart.
function showApiCost(){
const t=(lastData.stats&&lastData.stats.tokens)||{};
const cyc=t.cycle||{},life=t.lifetime||{};
const tok=(lastTrends&&lastTrends.tokens_48h)||[];
let h='<p style="color:#8598b4;margin-bottom:12px">The agent runs on a flat Claude MAX subscription. <b style="color:#c4d4e8">API cost avoided</b> is what the same token volume would have cost at per-model API rates (input, output, cache read/create priced separately, mirroring bot-cost.py). Breakeven &gt;100% means the subscription has already paid for itself this cycle.</p>';
const cycCost=cyc.estimated_cost_usd||0,cycSub=cyc.subscription_amount_usd||200;
const cycPct=cycSub?Math.round(100*cycCost/cycSub):0;
const csev=cycPct>=100?'SAFE':'MEDIUM';
h+=`<div class="modal-finding ${csev}"><span class="sev ${csev}">${cycPct>=100?'&#9679;':'&#9650;'} $${cycCost.toFixed(2)}</span> avoided this cycle (since ${esc(cyc.cycle_start_iso||'?')}) &middot; breakeven ${cycPct}% of the $${cycSub} subscription${cycPct>=100?` — ROI +$${(cycCost-cycSub).toFixed(2)}`:' — building'}</div>`;
const lifeCost=life.estimated_cost_usd||0,lifeSub=life.subscription_total_usd||cycSub;
const cycles=life.subscription_cycles_paid||1;
const lifePct=lifeSub?Math.round(100*lifeCost/lifeSub):0;
const lsev=lifePct>=100?'SAFE':'MEDIUM';
h+=`<div class="modal-finding ${lsev}"><span class="sev ${lsev}">${lifePct>=100?'&#9679;':'&#9650;'} $${lifeCost.toFixed(2)}</span> avoided lifetime (since ${esc(life.subscription_start_iso||'?')}, ${cycles} cycle${cycles===1?'':'s'} &middot; $${lifeSub.toFixed(0)} paid) &middot; breakeven ${lifePct}%${lifePct>=100?` — ROI +$${(lifeCost-lifeSub).toFixed(2)}`:''}</div>`;
// Token totals (lifetime counters from the session JSONL tailer)
h+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:12px 0">';
const cells=[['Input',fmtCompact(t.input||0)],['Output',fmtCompact(t.output||0)],['Cache read',fmtCompact(t.cache_read||0)],['Cache create',fmtCompact(t.cache_create||0)],['API messages',fmtCompact(t.messages||0)]];
for(const [k,v] of cells)h+=`<div style="background:var(--bg-2);border:1px solid var(--line);border-radius:8px;padding:8px 12px"><div style="font-size:10px;color:#8598b4;text-transform:uppercase;letter-spacing:.3px">${k}</div><div style="font-size:18px;font-weight:600;color:#eaf2fb">${v}</div></div>`;
h+='</div>';
// 48h hourly token usage
const tot48=tok.reduce((a,b)=>a+b.total,0);
h+=`<div style="font-size:12px;font-weight:600;color:#8598b4;letter-spacing:.3px;margin-bottom:6px">TOKEN USAGE &middot; last 48 hours &middot; ${fmtCompact(tot48)} total</div>`;
h+=`<div id="cost-chart">${svgAreaChart(tok,620,150,{id:'x-cost-svg',val:b=>b.total})}</div>`;
h+=`<div class="detail" style="margin-top:12px;color:#8598b4">Counters from Claude session transcripts (usage per turn) &middot; per-model rates &middot; full economics in the ops Token Usage panel</div>`;
document.getElementById('modal-title').textContent='API Cost — Subscription Economics';
document.getElementById('modal-body').innerHTML=h;
document.getElementById('modal').classList.add('show');
wireTrendHover(tok,{id:'x-cost-svg',tip:b=>`<b>${fmtCompact(b.total)}</b> tokens (in ${fmtCompact(b.inp)} · out ${fmtCompact(b.out)} · cache ${fmtCompact(b.cache)})`});
}
function showWhitepaper(){document.getElementById('wp-modal').classList.add('show')}
function showConstitution(){
const principles=[
{n:'I',t:'Evidence Over Assertion',d:"A finding's verdict is determined by checkable evidence, not by model confidence."},
{n:'II',t:'Surface Only What Survives',d:"Humans see findings that have passed the gates. Everything else stays in the internal store."},
{n:'III',t:'Liveness By Heartbeat, Never By Clock',d:"An agent is alive if it heartbeated recently. Wall-clock runtime says nothing about health."},
{n:'IV',t:'Claims Are Atomic And Mortal',d:"Two agents claiming the same unit of work concurrently get different units. A claim dies with its holder."},
{n:'V',t:'The Provider Is The Rate Arbiter',d:"The system does not pre-throttle below the upstream provider's actual limit. It handles the provider's backpressure and adapts."},
{n:'VI',t:'Coverage Before Yield',d:"The system does not stop itself on low yield until the operator's stated goals have been credibly attempted."},
{n:'VII',t:'Exploited Means Demonstrated',d:"The exploited flag is set only by an independent, clean-room reproduction — not by the agent that wrote the proof-of-concept."},
{n:'VIII',t:'Fingerprints Are Stable Under Edit',d:"A finding's identity is its location in the code's structure (path, symbol, vulnerability class), not its position in the text."},
{n:'IX',t:'Sandbox By Infrastructure, Not By Prompt',d:"Network egress and filesystem write boundaries are enforced by the runtime environment. Prompt-level rules are defense-in-depth, never the enforcement layer."},
{n:'X',t:'The Operator Outranks Every Agent',d:"Operator instructions are authoritative. Peer-agent messages and prior-agent notes are hints."},
{n:'XI',t:'Persist Atomically',d:"No reader ever observes a partially-written or deleted-but-not-yet-rewritten state."},
];
let h='<p style="color:#607080;margin-bottom:12px">11 inviolable principles from <a href="https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md" target="_blank" style="color:#5de3ff">CiscoDevNet/foundry-security-spec</a>.</p>';
for(const p of principles){
h+=`<div class="modal-finding SAFE" style="margin-bottom:4px">`;
h+=`<span style="color:#a0a8b0;margin-right:6px;font-weight:bold">${p.n}.</span>`;
h+=`<strong>${p.t}</strong>`;
h+=`<div class="detail" style="margin-top:2px;color:#90a0b8;font-size:11px;margin-left:24px">${p.d}</div>`;
h+=`</div>`;}
h+='<div class="detail" style="margin-top:12px;color:#607080;font-size:10px">Source: <a href="https://github.com/CiscoDevNet/foundry-security-spec/blob/main/constitution.md" target="_blank" style="color:#5de3ff">foundry-security-spec/constitution.md</a> @ <code>c770bf77</code> (published 2026-05-12).</div>';
document.getElementById('modal-title').textContent='Cisco Foundry Security Spec';
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
applyView();
pollTrends();setInterval(pollTrends,TREND_POLL_MS);
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
<p style="text-align:center;color:#5de3ff;font-size:15px">Securing an Autonomous AI Coding Agent<br>with Isovalent and Cisco AI Defense</p>
<p class="meta">Jeremy Fielder &middot; Systems Engineer, Strategic Accounts &middot; Cisco Systems<br>April 2026 &middot; v2.1 &middot; Red team review: Grok (xAI)</p>
<p style="text-align:center;margin:12px 0"><a href="/whitepaper.pdf" target="_blank" style="color:#5de3ff;font-size:12px;text-decoration:none;border:1px solid #5de3ff44;padding:6px 14px;border-radius:6px" onmouseover="this.style.borderColor='#5de3ff';this.style.background='#5de3ff10'" onmouseout="this.style.borderColor='#5de3ff44';this.style.background='none'">Open printable version (save as PDF from browser)</a></p>

<h2>1. Executive Summary</h2>
<p><strong>An autonomous AI agent is writing code on a public open-source project right now, monitored by Cisco's Isovalent and AI Defense scanners, on an $80 Raspberry Pi.</strong></p>
<p>AetherClaude is an AI coding agent that triages GitHub issues, implements fixes, reviews community pull requests, detects duplicates, explains CI failures, answers community questions, and compiles release notes for AetherSDR&mdash;an open-source Linux-native SDR client for the amateur radio community. It runs eight skills triggered in real time by GitHub webhooks, with an hourly fallback timer, unattended, on dedicated commodity hardware.</p>
<p>AetherSDR has a community of over 1,000 users around the world actively consuming software produced by this pipeline&mdash;running AetherSDR builds that include AI-authored code, filing bug reports that the agent triages, and requesting features that the agent implements. Contributors who have never written a line of C++ are shaping the project through AI-assisted issue and feature requests that AetherClaude turns into production-ready code. This has democratized participation: the barrier to contributing is no longer knowing how to code, it's knowing how to describe what you need.</p>
<p>This paper documents the <strong>9-ring defense-in-depth model</strong> securing that deployment. Each ring addresses distinct attack vectors&mdash;from kernel-level packet filtering (Ring 1) through Cisco AI Defense static analysis (Ring 6) to mandatory human review (Ring 9). An attacker must penetrate all nine rings to cause damage to the upstream project.</p>
<p>Four <a href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html" target="_blank" style="color:#5de3ff;text-decoration:none;border-bottom:1px solid #5de3ff44" onmouseover="this.style.borderBottomColor='#5de3ff'" onmouseout="this.style.borderBottomColor='#5de3ff44'">Cisco AI Defense technologies</a> are in production today. <strong><a href="https://isovalent.com/products/runtime-security/" target="_blank" style="color:#5de3ff;text-decoration:none">Cilium Tetragon (Isovalent)</a></strong> provides eBPF-based process execution tracking, network connection monitoring, and privilege escalation detection. <strong><a href="https://cisco-ai-defense.github.io/docs/defenseclaw" target="_blank" style="color:#5de3ff;text-decoration:none">DefenseClaw CodeGuard</a></strong> scans every changed file and blocks HIGH/CRITICAL findings. <strong><a href="https://github.com/cisco-ai-defense/mcp-scanner" target="_blank" style="color:#5de3ff;text-decoration:none">MCP Scanner</a></strong> performs YARA + Prompt Defense analysis on all MCP tool declarations. <strong><a href="https://github.com/cisco-ai-defense/skill-scanner" target="_blank" style="color:#5de3ff;text-decoration:none">Skill Scanner</a></strong> analyzes agent skill templates for injection risks. Additionally, a custom <strong><a href="https://github.com/cisco-ai-defense/aibom" target="_blank" style="color:#5de3ff;text-decoration:none">C++ AIBOM scanner</a></strong> generates AI Bills of Materials and <strong>agent-sbom</strong> inventories the agent infrastructure itself. All run on ARM64.</p>
<p>All nine rings feed into a <strong><a href="https://dashboard.aethersdr.com" target="_blank" class="print-link" style="color:#5de3ff;text-decoration:none">live Defense-in-Depth Dashboard</a></strong> with SQLite-backed event history, real-time metrics from eight data sources, clickable scanner detail modals, and secret redaction on all API responses.</p>

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
<li><strong style="color:#27a86f">Agent</strong> (green): AetherClaude UID 965 process activity</li>
<li><strong style="color:#e8506a">Firewall</strong> (red): nftables BLOCK events with destination details</li>
<li><strong style="color:#21a184">Proxy</strong> (teal): tinyproxy allowed/denied domain connections</li>
<li><strong style="color:#e85578">CodeGuard</strong> (pink): DefenseClaw scan results and blocks</li>
<li><strong style="color:#a878e0">MCP</strong> (purple): GitHub API operations and content validation</li>
<li><strong style="color:#45c8e8">Scanners</strong> (cyan): MCP Scanner and Skill Scanner events</li>
<li><strong style="color:#e0b83c">Skills</strong> (yellow): Orchestrator skill dispatch (triage, implement, review, etc.)</li>
<li><strong style="color:#e88fc0">Claude</strong> (pink): Claude Code tool calls with per-tool breakdown</li>
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
<li><strong>Secret redaction:</strong> All events are scrubbed at ingestion (before entering memory or DB) and again at API response. 14 regex patterns cover GitHub PATs, JWTs, Authorization headers, credential file paths, the Galileo API key, and environment variable assignments. Secrets never reach the browser.</li>
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
  header h1 { margin:0; font-size:14px; font-weight:600; color:#5de3ff; letter-spacing:0.5px; text-transform:uppercase; }
  header a.back { color:#607080; text-decoration:none; font-size:11px; border:1px solid #203050; padding:4px 10px; border-radius:4px; }
  header a.back:hover { color:#5de3ff; border-color:#5de3ff; }
  .controls { display:flex; align-items:center; gap:14px; font-size:11px; color:#809090; }
  .controls label { display:flex; align-items:center; gap:6px; }
  .controls input[type=range] { width:120px; }
  .controls input[type=text] { background:#0a0a1a; color:#d0d8e0; border:1px solid #203050; padding:3px 8px; border-radius:3px; width:200px; font-family:inherit; font-size:11px; }
  #stats { color:#607080; font-size:11px; margin-left:auto; }
  #sigma-container { position:fixed; top:48px; left:0; right:320px; bottom:0; background:#08081a; }
  aside#side { position:fixed; top:48px; right:0; bottom:0; width:320px; background:#0f0f22; border-left:1px solid #203050; overflow-y:auto; padding:16px; box-sizing:border-box; font-size:11px; }
  aside h3 { color:#5de3ff; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; margin:18px 0 8px 0; border-bottom:1px solid #203050; padding-bottom:4px; }
  aside h3:first-child { margin-top:0; }
  .field { display:flex; gap:6px; margin:4px 0; }
  .field .k { color:#607080; min-width:80px; }
  .field .v { color:#d0d8e0; word-break:break-all; font-family:'SF Mono', monospace; font-size:10px; }
  .neighbor { padding:3px 6px; margin:2px 0; border:1px solid #203050; border-radius:3px; cursor:pointer; font-family:'SF Mono', monospace; font-size:10px; color:#a0b0c0; }
  .neighbor:hover { border-color:#5de3ff; color:#5de3ff; }
  .community-row { display:flex; justify-content:space-between; padding:3px 6px; cursor:pointer; border-radius:3px; }
  .community-row:hover { background:#1a1a2a; }
  .community-swatch { display:inline-block; width:10px; height:10px; border-radius:50%; vertical-align:middle; margin-right:6px; }
  #empty-state { padding:20px; text-align:center; color:#607080; font-size:12px; line-height:1.6; }
  .loading-spinner { display:inline-block; width:12px; height:12px; border:2px solid #203050; border-top-color:#5de3ff; border-radius:50%; animation:spin 0.8s linear infinite; vertical-align:middle; }
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
  /* HTML 3D-overlay labels — pill style matching the 2D label
   * renderer. Positioned absolutely; the JS overlay loop sets
   * `transform: translate(x,y)` each frame. */
  .threed-label { position:absolute; top:0; left:0; padding:2px 6px; background:rgba(10,10,26,0.92); color:#e0e8f0; font-family:'SF Mono', monospace; font-size:11px; font-weight:600; border-radius:3px; border:1px solid #5de3ff; white-space:nowrap; transform:translate(-9999px,-9999px); will-change:transform; }
  /* Refactor watch-list — high-betweenness symbols. Click jumps the
   * camera to the node and selects it in the detail panel. */
  .bridge-row { display:flex; align-items:baseline; gap:6px; padding:3px 6px; font-family:'SF Mono', monospace; font-size:10px; cursor:pointer; border-radius:3px; border-left:2px solid transparent; }
  .bridge-row:hover { background:#1a1a2a; border-left-color:#5de3ff; }
  .bridge-row .bname { color:#d0d8e0; flex:1; text-overflow:ellipsis; overflow:hidden; white-space:nowrap; }
  .bridge-row .bscope { color:#607080; }
  .bridge-row .bscore { color:#ffaa00; min-width:46px; text-align:right; }
  /* Stale-index banner — appears at top of /codegraph when AetherSDR
   * HEAD has moved since the last extraction. Amber for ≤10 commits
   * behind, red for >10. Click the link to re-kick the extractor. */
  #stale-banner { position:fixed; top:48px; left:0; right:320px; padding:8px 16px; background:#3a2a10; border-bottom:1px solid #ffaa00; color:#ffd0a0; font-size:11px; z-index:9; display:none; align-items:center; gap:10px; }
  #stale-banner.severe { background:#3a1010; border-bottom-color:#ff4444; color:#ffc0c0; }
  #stale-banner b { color:#fff; }
  #stale-banner .stale-sha { font-family:'SF Mono', monospace; color:#a0b0c0; }
</style>
</head>
<body>
<header>
  <h1>AetherSDR Codegraph</h1>
  <a class="back" href="/">&larr; Dashboard</a>
  <div class="controls">
    <label>view:
      <select id="view-mode">
        <option value="dirs">Directories</option>
        <option value="communities">Communities</option>
        <option value="concepts">Concepts</option>
        <option value="symbols">Symbols (2D)</option>
        <option value="symbols3d" selected>Symbols (3D)</option>
        <option value="graphify">Graphify</option>
      </select>
    </label>
    <label id="min-degree-label">min degree: <input type="range" id="min-degree" min="0" max="50" value="5"><span id="min-degree-val">5</span></label>
    <label>search: <input type="text" id="search" placeholder="symbol name..."></label>
    <button id="back-to-dirs" style="display:none;background:#101025;color:#5de3ff;border:1px solid #5de3ff;padding:3px 10px;border-radius:3px;font-size:11px;cursor:pointer">&larr; Back to directories</button>
  </div>
  <span id="stats"><span class="loading-spinner"></span> loading...</span>
</header>
<div id="stale-banner"></div>
<div id="sigma-container"></div>
<div id="threed-container" style="position:fixed;top:48px;left:0;right:320px;bottom:0;display:none;background:#08081a"></div>
<!-- HTML overlay for 3D labels. Positioned absolutely INSIDE
     #threed-container by JS each frame; pointer-events:none so the
     WebGL canvas still gets all the orbit/zoom mouse events. -->
<div id="threed-label-layer" style="position:fixed;top:48px;left:0;right:320px;bottom:0;pointer-events:none;display:none;overflow:hidden"></div>
<!-- Graphify view — third-party vis-network HTML served as-is in an
     iframe so its CSS/JS doesn't fight our Sigma + 3d-force-graph
     stack. Sandboxed for safety; graphify's HTML loads vis-network
     from unpkg, so we have to allow same-origin scripts. -->
<iframe id="graphify-frame" src="about:blank" style="position:fixed;top:48px;left:0;display:none;background:#0f0f1a;border:0;width:calc(100vw - 320px);height:calc(100vh - 48px);margin:0;padding:0"></iframe>
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
<script src="/codegraph/assets/3d-force-graph.min.js"></script>
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

// Custom label renderer — Sigma's default draws bare text with no
// backdrop. Forced labels in the selection/neighbor view sit on top
// of dense edges and dim community-colored nodes, making them
// illegible. This renderer paints a dark pill with a node-colored
// border behind the text so it pops at any zoom level.
function drawLabelWithPill(context, data, settings) {
  if (!data.label) return;
  const fontSize = settings.labelSize || 11;
  const weight = settings.labelWeight || '500';
  context.font = `${weight} ${fontSize}px ${settings.labelFont || 'sans-serif'}`;
  const text = data.label;
  const metrics = context.measureText(text);
  const padX = 5, padY = 2;
  const w = metrics.width + padX * 2;
  const h = fontSize + padY * 2;
  // Position above the node — anchored to its rendered position+size.
  const x = data.x - w / 2;
  const y = data.y - (data.size || 4) - h - 3;
  // Pill backdrop (dark, ~90% opaque) bordered with the node's color.
  context.fillStyle = 'rgba(10, 10, 26, 0.92)';
  context.strokeStyle = data.color || '#5de3ff';
  context.lineWidth = 1;
  if (context.roundRect) {
    context.beginPath();
    context.roundRect(x, y, w, h, 4);
    context.fill();
    context.stroke();
  } else {
    context.fillRect(x, y, w, h);
    context.strokeRect(x, y, w, h);
  }
  // Text
  context.fillStyle = (settings.labelColor && settings.labelColor.color) || '#fff';
  context.textAlign = 'left';
  context.textBaseline = 'top';
  context.fillText(text, x + padX, y + padY);
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
  viewMode: 'symbols3d',     // 'symbols3d' (default) | 'symbols' | 'dirs' | 'communities'
  drilledDir: null,          // path of the directory the user clicked into
};

function setStats(text) { document.getElementById('stats').textContent = text; }

async function fetchData(minDegree) {
  const r = await fetch('/api/codegraph/data?min_degree=' + minDegree);
  if (!r.ok) throw new Error('fetch failed: ' + r.status);
  return r.json();
}

async function fetchDirectories() {
  const r = await fetch('/api/codegraph/directories');
  if (!r.ok) throw new Error('fetch failed: ' + r.status);
  return r.json();
}

async function fetchCommunities() {
  const r = await fetch('/api/codegraph/communities');
  if (!r.ok) throw new Error('fetch failed: ' + r.status);
  return r.json();
}

function rebuildCommunityGraph(data) {
  // Same shape as rebuildDirGraph but per Louvain community. Used as
  // an alternative bubble overview; communities give ~50 clusters
  // where directories give only 5 on AetherSDR's flat layout.
  if (_state.sigma) { _state.sigma.kill(); _state.sigma = null; }
  if (typeof _live !== 'undefined') { _live.pulses.clear(); }
  const g = new graphology.Graph({ type: 'undirected', multi: false });
  for (const c of data.communities) {
    // Same adjacency-based sizing as directories — see rebuildDirGraph
    // for rationale.
    const adjacency = (c.internal_edges || 0) + (c.external_edges || 0);
    g.addNode(c.id, {
      label: c.label,
      community_id: c.community_id,
      symbol_count: c.symbol_count,
      internal_edges: c.internal_edges,
      external_edges: c.external_edges,
      adjacency: adjacency,
      top_symbols: c.top_symbols,
      x: (Math.random() - 0.5) * 1000,
      y: (Math.random() - 0.5) * 1000,
      size: Math.max(3, Math.min(25, Math.sqrt(adjacency) * 0.6 + 3)),
      color: communityColor(c.community_id || 0),
    });
  }
  for (const e of data.edges) {
    if (g.hasNode(e.source) && g.hasNode(e.target) && !g.hasEdge(e.source, e.target)) {
      const srcColor = g.getNodeAttribute(e.source, 'color');
      const sz = Math.max(0.3, Math.min(2.5, Math.log2(e.weight + 1) * 0.3));
      g.addEdge(e.source, e.target, {
        size: sz, color: hexWithAlpha(srcColor, 0.22), weight: e.weight,
      });
    }
  }
  _state.graph = g;
  _state.rawNodes = data.communities;
  _state.rawEdges = data.edges;

  setStats(`${g.order} communities · ${g.size} inter-community edges · running layout…`);
  const layoutFa2 = graphologyLibrary.layoutForceAtlas2;
  const t0 = performance.now();
  // 50-node graph: standard FA2 with strong gravity so isolated
  // communities don't get banished. scalingRatio modest for a
  // compact layout that fits the viewport without zoom-out.
  layoutFa2.assign(g, {
    iterations: 400,
    settings: {
      barnesHutOptimize: true, gravity: 2, scalingRatio: 10,
      slowDown: 4, strongGravityMode: true, linLogMode: false,
    },
  });
  if (graphologyLibrary.layoutNoverlap) {
    graphologyLibrary.layoutNoverlap.assign(g, {
      maxIterations: 50,
      settings: { ratio: 1.5, margin: 2, expansion: 1.05, speed: 3 },
    });
  }
  const layoutMs = performance.now() - t0;

  const container = document.getElementById('sigma-container');
  _state.sigma = new Sigma(g, container, {
    renderEdgeLabels: false,
    renderLabels: true,
    labelRenderedSizeThreshold: 8,
    defaultDrawNodeLabel: drawLabelWithPill,
    defaultDrawNodeHover: drawLabelWithPill,
    labelColor: { color: '#e0e8f0' },
    labelFont: 'SF Mono, monospace',
    labelSize: 10,
    minCameraRatio: 0.005,
    maxCameraRatio: 10,
  });
  _state.sigma.on('clickNode', e => drillIntoCommunity(e.node));

  fitCameraToGraph(g);
  setStats(`${g.order} communities · ${g.size} edges · layout in ${(layoutMs/1000).toFixed(1)}s · click a bubble to drill in`);
  // Reuse community sidebar — it's already keyed off the same data.
  renderCommunityList();
}

async function drillIntoCommunity(commIdStr) {
  _state.viewMode = 'symbols';
  document.getElementById('view-mode').value = 'symbols';
  document.getElementById('back-to-dirs').style.display = '';
  document.getElementById('back-to-dirs').textContent = '← Back to communities';
  document.getElementById('min-degree-label').style.display = '';
  setStats('<span class="loading-spinner"></span> loading symbols in community ' + commIdStr);
  try {
    const data = await fetchData(_state.minDegree);
    const cid = parseInt(commIdStr, 10);
    const keepIds = new Set(data.nodes.filter(n => n.community === cid).map(n => n.id));
    const filtered = {
      nodes: data.nodes.filter(n => keepIds.has(n.id)),
      edges: data.edges.filter(e => keepIds.has(e.source) && keepIds.has(e.target)),
    };
    rebuildGraph(filtered);
    setStats(`${filtered.nodes.length} symbols in community ${commIdStr} · ${filtered.edges.length} edges`);
    // Remember we came from communities, so back button returns there
    _state.drilledFrom = 'communities';
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

async function fetchConceptGraph() {
  const r = await fetch('/api/codegraph/concept-graph');
  if (!r.ok) throw new Error('fetch failed: ' + r.status);
  return r.json();
}

function rebuildConceptGraph(data) {
  // Concept nodes (kind='concept') get a distinct visual treatment:
  // bright magenta-cyan palette by concept_kind, larger size, always
  // labeled. Anchor code-symbol nodes (the ones concepts point at)
  // render in their existing community color, smaller, no forced
  // label. Edges are confidence-tinted: stronger color for higher
  // confidence_score.
  if (_state.sigma) { _state.sigma.kill(); _state.sigma = null; }
  if (typeof _live !== 'undefined') { _live.pulses.clear(); }
  const g = new graphology.Graph({ type: 'directed', multi: false });
  // Color palette by concept kind — keeps the categorical distinction
  // visible even when zoomed out.
  const conceptPalette = {
    subsystem:  '#5de3ff',  // cyan — architectural backbone
    pattern:    '#ffaa00',  // amber — recurring solutions
    principle:  '#ff66cc',  // pink — inviolable rules
    feature:    '#88ddaa',  // mint — user-facing capability
    protocol:   '#aa88ff',  // violet — wire-level spec
  };
  for (const n of data.nodes) {
    const isConcept = (n.kind === 'concept');
    const color = isConcept
      ? (conceptPalette[n.concept_kind] || '#cccccc')
      : communityColor(n.community || 0);
    const size = isConcept
      ? Math.max(5, Math.min(14, 5 + Math.sqrt(n.degree || 1) * 1.2))
      : Math.max(1.5, Math.min(5, Math.log2((n.degree || 1) + 1)));
    g.addNode(n.id, {
      label: n.label,
      kind: n.kind,
      concept_kind: n.concept_kind,
      description: n.description,
      file: n.file_path || '',
      line: n.line_number,
      community_label: n.community_label,
      degree: n.degree,
      x: (Math.random() - 0.5) * 1000,
      y: (Math.random() - 0.5) * 1000,
      size,
      color,
      // Concepts always show their label; anchors don't.
      forceLabel: isConcept,
    });
  }
  for (const e of data.edges) {
    if (g.hasNode(e.source) && g.hasNode(e.target)
        && !g.hasEdge(e.source, e.target)) {
      // Edge color by source-node color at confidence-scaled alpha.
      const srcColor = g.getNodeAttribute(e.source, 'color');
      const conf = Math.max(0.15, Math.min(1.0, e.confidence_score || 0.5));
      g.addEdge(e.source, e.target, {
        kind: e.kind,
        size: 0.5 + conf * 0.8,
        color: hexWithAlpha(srcColor, 0.25 + conf * 0.4),
        confidence_score: conf,
      });
    }
  }
  _state.graph = g;
  _state.rawNodes = data.nodes;
  _state.rawEdges = data.edges;

  setStats(`${data.concept_count} concepts · ${data.anchor_count} anchor symbols · running layout…`);

  const layoutFa2 = graphologyLibrary.layoutForceAtlas2;
  const t0 = performance.now();
  layoutFa2.assign(g, {
    iterations: 500,
    settings: {
      barnesHutOptimize: true, gravity: 1.5, scalingRatio: 12,
      slowDown: 4, strongGravityMode: false, linLogMode: false,
      adjustSizes: true,
    },
  });
  const layoutMs = performance.now() - t0;

  const container = document.getElementById('sigma-container');
  _state.sigma = new Sigma(g, container, {
    renderEdgeLabels: false,
    renderLabels: true,
    labelRenderedSizeThreshold: 4,
    defaultDrawNodeLabel: drawLabelWithPill,
    defaultDrawNodeHover: drawLabelWithPill,
    labelColor: { color: '#e0e8f0' },
    labelFont: 'SF Mono, monospace',
    labelSize: 10,
    minCameraRatio: 0.005,
    maxCameraRatio: 10,
  });
  _state.sigma.on('clickNode', e => selectNode(e.node));
  _state.sigma.on('clickStage', () => selectNode(null));
  fitCameraToGraph(g);
  setStats(`${data.concept_count} concepts · ${data.anchor_count} anchor symbols · ${data.edges.length} edges · layout in ${(layoutMs/1000).toFixed(1)}s`);
}

async function switchToConceptView() {
  _state.viewMode = 'concepts';
  _state.drilledDir = null;
  document.getElementById('view-mode').value = 'concepts';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = 'none';
  show2DContainer();
  setStats('<span class="loading-spinner"></span> loading concept graph…');
  try {
    rebuildConceptGraph(await fetchConceptGraph());
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

async function switchToCommunityView() {
  _state.viewMode = 'communities';
  _state.drilledDir = null;
  document.getElementById('view-mode').value = 'communities';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = 'none';
  show2DContainer();
  setStats('<span class="loading-spinner"></span> loading communities...');
  try {
    rebuildCommunityGraph(await fetchCommunities());
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

function rebuildDirGraph(data) {
  // Directory bubble layout. Each node is a directory (src/gui, src/core, …);
  // size scales by symbol_count; color is community-style via dir name hash.
  // Inter-dir edges are weighted by call count and rendered translucent.
  if (_state.sigma) { _state.sigma.kill(); _state.sigma = null; }
  if (typeof _live !== 'undefined') { _live.pulses.clear(); }
  const g = new graphology.Graph({ type: 'undirected', multi: false });
  // Hash each dir name to a stable hue
  function dirColor(s) {
    let h = 0;
    for (const c of s) h = ((h * 31) + c.charCodeAt(0)) | 0;
    return hslToHex(((h % 360) + 360) % 360, 60, 60);
  }
  for (const d of data.directories) {
    // Size by adjacency (internal + external edges) on sqrt scale —
    // architectural importance, not raw code volume. A small dir
    // with many callers reads as a structural hub; a big dir with
    // few connections reads as bulk. sqrt keeps the long tail from
    // collapsing the spread the way log would.
    const adjacency = (d.internal_edges || 0) + (d.external_edges || 0);
    g.addNode(d.path, {
      label: d.path,
      symbol_count: d.symbol_count,
      internal_edges: d.internal_edges,
      external_edges: d.external_edges,
      adjacency: adjacency,
      top_symbols: d.top_symbols,
      x: (Math.random() - 0.5) * 1000,
      y: (Math.random() - 0.5) * 1000,
      size: Math.max(5, Math.min(40, Math.sqrt(adjacency) * 0.5 + 5)),
      color: dirColor(d.path),
    });
  }
  for (const e of data.edges) {
    if (g.hasNode(e.source) && g.hasNode(e.target) && !g.hasEdge(e.source, e.target)) {
      const srcColor = g.getNodeAttribute(e.source, 'color');
      // Edge size scales with the weight (number of calls between dirs)
      // so the dominant inter-cluster relationships pop visually.
      const sz = Math.max(0.3, Math.min(3, Math.log2(e.weight + 1) * 0.35));
      g.addEdge(e.source, e.target, {
        size: sz, color: hexWithAlpha(srcColor, 0.25), weight: e.weight,
      });
    }
  }
  _state.graph = g;
  _state.rawNodes = data.directories;
  _state.rawEdges = data.edges;

  setStats(`${g.order} directories · ${g.size} inter-dir edges · running layout…`);
  const layoutFa2 = graphologyLibrary.layoutForceAtlas2;
  const t0 = performance.now();
  // 5-node graph: standard FA2 with strong gravity to keep isolated
  // dirs (main.cpp, generated) near the center instead of flung out.
  // scalingRatio kept modest — too much repulsion banishes the
  // weakly-connected bubbles to the corners.
  layoutFa2.assign(g, {
    iterations: 300,
    settings: {
      barnesHutOptimize: true, gravity: 3, scalingRatio: 8,
      slowDown: 3, strongGravityMode: true, linLogMode: false,
    },
  });
  if (graphologyLibrary.layoutNoverlap) {
    graphologyLibrary.layoutNoverlap.assign(g, {
      maxIterations: 40,
      settings: { ratio: 1.3, margin: 2, expansion: 1.05, speed: 3 },
    });
  }
  const layoutMs = performance.now() - t0;

  const container = document.getElementById('sigma-container');
  _state.sigma = new Sigma(g, container, {
    renderEdgeLabels: false,
    renderLabels: true,
    labelRenderedSizeThreshold: 5,
    defaultDrawNodeLabel: drawLabelWithPill,
    defaultDrawNodeHover: drawLabelWithPill,
    labelColor: { color: '#e0e8f0' },
    labelFont: 'SF Mono, monospace',
    labelSize: 11,
    labelWeight: '500',
    minCameraRatio: 0.005,
    maxCameraRatio: 10,
  });
  _state.sigma.on('clickNode', e => drillIntoDirectory(e.node));
  _state.sigma.on('clickStage', () => { /* no-op in dir mode */ });

  fitCameraToGraph(g);
  setStats(`${g.order} directories · ${g.size} edges · layout in ${(layoutMs/1000).toFixed(1)}s · click a bubble to drill in`);
  renderDirSidebar();
}

function fitCameraToGraph(g) {
  // After layout, reset Sigma's camera so the rendered bounding box
  // fills the viewport with a small margin. Sigma normalizes graph
  // coords into [0,1] internally; the camera's default ratio=1 already
  // shows the unit stage, so x=0.5,y=0.5 + ratio=1.05 centers and adds
  // a comfortable padding for any noverlap excursion past the unit box.
  // Without this step, sparse graphs (5 bubbles, mostly disconnected)
  // appear as tiny dots in a sea of empty canvas.
  if (!_state.sigma) return;
  _state.sigma.getCamera().setState({ x: 0.5, y: 0.5, ratio: 1.05, angle: 0 });
  _state.sigma.refresh();
}

function renderDirSidebar() {
  // Repurpose the community-list panel for the directory list in dir mode.
  const el = document.getElementById('community-list');
  if (!el || !_state.rawNodes) return;
  el.innerHTML = _state.rawNodes.slice(0, 30).map(d => {
    const color = _state.graph.getNodeAttribute(d.path, 'color');
    return `<div class="community-row" data-dir="${escapeHtml(d.path)}"><span><span class="community-swatch" style="background:${color}"></span>${escapeHtml(d.path)}</span><span>${d.symbol_count}</span></div>`;
  }).join('');
  el.querySelectorAll('.community-row').forEach(row => {
    row.addEventListener('click', () => drillIntoDirectory(row.dataset.dir));
  });
}

async function drillIntoDirectory(dirPath) {
  _state.drilledDir = dirPath;
  _state.viewMode = 'symbols';
  document.getElementById('view-mode').value = 'symbols';
  document.getElementById('back-to-dirs').style.display = '';
  document.getElementById('min-degree-label').style.display = '';
  setStats('<span class="loading-spinner"></span> loading symbols in ' + dirPath);
  try {
    const data = await fetchData(_state.minDegree);
    // Filter to symbols whose file_path starts with the chosen directory.
    const prefix = dirPath + '/';
    const keepIds = new Set(
      data.nodes.filter(n => (n.file || '').startsWith(prefix)).map(n => n.id)
    );
    const filtered = {
      nodes: data.nodes.filter(n => keepIds.has(n.id)),
      edges: data.edges.filter(e => keepIds.has(e.source) && keepIds.has(e.target)),
    };
    rebuildGraph(filtered);
    setStats(`${filtered.nodes.length} symbols in ${dirPath} · ${filtered.edges.length} edges`);
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

async function switchToDirectoryView() {
  _state.viewMode = 'dirs';
  _state.drilledDir = null;
  document.getElementById('view-mode').value = 'dirs';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = 'none';
  show2DContainer();
  setStats('<span class="loading-spinner"></span> loading directories...');
  try {
    rebuildDirGraph(await fetchDirectories());
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

async function switchToSymbolView() {
  _state.viewMode = 'symbols';
  _state.drilledDir = null;
  document.getElementById('view-mode').value = 'symbols';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = '';
  show2DContainer();
  setStats('<span class="loading-spinner"></span> loading...');
  try {
    rebuildGraph(await fetchData(_state.minDegree));
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

// 3D state lives separately so toggling between 2D and 3D doesn't
// dispose / recreate the Three.js scene every time.
const _3d = {
  graph: null,
  currentNode: null,
  // Built on every rebuild3DGraph. Maps node id -> Set of neighbor ids,
  // used to keep neighbor-only highlight O(1) per render frame.
  adjacency: new Map(),
  // Selection state (separate from _state.highlightedId because the
  // 3D view doesn't go through selectNode for the highlighting path).
  selectedId: null,
  neighborSet: new Set(),
  // Search-match set — populated by the header search input when the
  // 3D view is active. Behaves like a selection: matches highlight,
  // everything else dims.
  searchSet: new Set(),
};

function _3dIsHighlighted(nodeId) {
  if (_3d.searchSet.size > 0) return _3d.searchSet.has(nodeId);
  if (_3d.selectedId == null) return true;  // nothing selected → all bright
  if (nodeId === _3d.selectedId) return true;
  return _3d.neighborSet.has(nodeId);
}

function refresh3DHighlight() {
  // Poke 3d-force-graph's accessors so the color/size/edge functions
  // re-evaluate against the current _3d.selectedId / _3d.neighborSet.
  if (!_3d.graph) return;
  _3d.graph
    .nodeColor(_3d.graph.nodeColor())
    .nodeVal(_3d.graph.nodeVal())
    .linkColor(_3d.graph.linkColor())
    .linkWidth(_3d.graph.linkWidth())
    .linkVisibility(_3d.graph.linkVisibility());
}

function show3DContainer() {
  document.getElementById('sigma-container').style.display = 'none';
  document.getElementById('graphify-frame').style.display = 'none';
  document.getElementById('threed-container').style.display = '';
  document.getElementById('threed-label-layer').style.display = '';
  // 3d-force-graph caches width/height at construction time and
  // doesn't auto-track container resizes. Kick a resize now (in case
  // the container changed dimensions while hidden) and on every
  // future window resize / container resize.
  resize3D();
}

function showGraphifyContainer() {
  document.getElementById('sigma-container').style.display = 'none';
  document.getElementById('threed-container').style.display = 'none';
  document.getElementById('threed-label-layer').style.display = 'none';
  const frame = document.getElementById('graphify-frame');
  // Lazy-load the iframe src so we don't fetch the 4 MB graph.html
  // until the user actually picks the Graphify view.
  if (!frame.dataset.loaded) {
    frame.src = '/codegraph/graphify';
    frame.dataset.loaded = '1';
  }
  frame.style.display = '';
}

function resize3D() {
  if (!_3d.graph) return;
  const c = document.getElementById('threed-container');
  if (!c) return;
  const w = c.clientWidth, h = c.clientHeight;
  if (w > 0 && h > 0) {
    _3d.graph.width(w).height(h);
  }
}
function show2DContainer() {
  document.getElementById('threed-container').style.display = 'none';
  document.getElementById('threed-label-layer').style.display = 'none';
  document.getElementById('graphify-frame').style.display = 'none';
  document.getElementById('sigma-container').style.display = '';
  stop3DLabelLoop();
}

async function switchToGraphifyView() {
  _state.viewMode = 'graphify';
  document.getElementById('view-mode').value = 'graphify';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = 'none';
  showGraphifyContainer();
  setStats('Graphify viz · vis-network · 5125 nodes / 8417 edges / 451 communities');
}

// HTML-overlay labels for 3D mode. We don't use SpriteText (needs an
// external THREE that conflicts with 3d-force-graph's bundled one).
// Instead, project each highlighted node's world position to screen
// coords each frame and translate an absolutely-positioned <div>
// pill there. Cheap: one matrix-mult per labeled node per frame.
const _3dLabels = {
  divs: new Map(),  // nodeId -> HTMLElement
  rafId: 0,
  tmpVec: null,     // borrowed THREE.Vector3 from the scene
};

function clear3DLabels() {
  const layer = document.getElementById('threed-label-layer');
  for (const div of _3dLabels.divs.values()) {
    div.remove();
  }
  _3dLabels.divs.clear();
}

function build3DLabels() {
  clear3DLabels();
  if (!_3d.graph || _3d.selectedId == null) return;
  const layer = document.getElementById('threed-label-layer');
  const data = _3d.graph.graphData();
  for (const n of data.nodes) {
    if (!_3dIsHighlighted(n.id)) continue;
    const div = document.createElement('div');
    div.className = 'threed-label';
    div.textContent = n.label || '';
    div.style.borderColor = communityColor(n.community || 0);
    layer.appendChild(div);
    _3dLabels.divs.set(n.id, div);
  }
}

function tick3DLabels() {
  if (_3d.selectedId == null || _3dLabels.divs.size === 0) {
    _3dLabels.rafId = 0;
    return;
  }
  const camera = _3d.graph.camera();
  const scene = _3d.graph.scene();
  // Lazy-init a Vector3 borrowed from the scene's own Three.js
  // namespace (3d-force-graph bundles its own; we don't import it).
  if (!_3dLabels.tmpVec && scene && scene.position && scene.position.clone) {
    _3dLabels.tmpVec = scene.position.clone();
  }
  if (!_3dLabels.tmpVec || !camera) {
    _3dLabels.rafId = requestAnimationFrame(tick3DLabels);
    return;
  }
  const layer = document.getElementById('threed-label-layer');
  const rect = layer.getBoundingClientRect();
  const data = _3d.graph.graphData();
  const nodeById = new Map(data.nodes.map(n => [n.id, n]));
  const camPos = camera.position;
  // Depth-cued sizing: labels close to the camera render bigger,
  // labels far away shrink. Reference distance picked so a node
  // ~150 units from the camera reads at base 11px; closer = up to
  // 1.6x, farther = down to 0.4x.
  const REF_DISTANCE = 150;
  for (const [nid, div] of _3dLabels.divs) {
    const n = nodeById.get(nid);
    if (!n) { div.style.display = 'none'; continue; }
    _3dLabels.tmpVec.set(n.x || 0, n.y || 0, n.z || 0);
    _3dLabels.tmpVec.project(camera);
    if (_3dLabels.tmpVec.z > 1) { div.style.display = 'none'; continue; }
    const sx = (_3dLabels.tmpVec.x + 1) * 0.5 * rect.width;
    const sy = (1 - _3dLabels.tmpVec.y) * 0.5 * rect.height;
    // Compute world-distance from camera and derive a font scale.
    const dx = (n.x || 0) - camPos.x;
    const dy = (n.y || 0) - camPos.y;
    const dz = (n.z || 0) - camPos.z;
    const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
    const scale = Math.max(0.4, Math.min(1.6, REF_DISTANCE / Math.max(dist, 1)));
    div.style.fontSize = (11 * scale).toFixed(2) + 'px';
    div.style.opacity = Math.max(0.3, Math.min(1, scale)).toFixed(2);
    div.style.display = '';
    div.style.transform = `translate(${sx - div.offsetWidth / 2}px, ${sy - div.offsetHeight - 16}px)`;
  }
  _3dLabels.rafId = requestAnimationFrame(tick3DLabels);
}

function start3DLabelLoop() {
  if (_3dLabels.rafId) return;
  _3dLabels.rafId = requestAnimationFrame(tick3DLabels);
}
function stop3DLabelLoop() {
  if (_3dLabels.rafId) cancelAnimationFrame(_3dLabels.rafId);
  _3dLabels.rafId = 0;
  clear3DLabels();
}

function apply3DSearch(q) {
  // Mirror of the 2D search behaviour but driven against
  // _3d.searchSet. Empty query restores the default render
  // (everything bright, all edges visible). A non-empty query
  // populates the set and refreshes; matches stay bright +
  // labeled, others dim and shrink, edges between non-matches
  // hide.
  if (!_3d.graph) return;
  _3d.searchSet.clear();
  if (q) {
    const data = _3d.graph.graphData();
    for (const n of data.nodes) {
      if (n.label && n.label.toLowerCase().includes(q)) {
        _3d.searchSet.add(n.id);
      }
    }
    setStats(`${_3d.searchSet.size} match${_3d.searchSet.size===1?'':'es'} for "${q}" · 3D`);
  } else {
    const data = _3d.graph.graphData();
    setStats(`${data.nodes.length} nodes · ${data.links.length} edges · 3D · drag to rotate, scroll to zoom`);
  }
  refresh3DHighlight();
  // Build labels for matches (or clear them if no query). Reuses
  // the same label loop we use for click-selection.
  if (_3d.searchSet.size > 0) {
    build3DLabelsForSet(_3d.searchSet);
    start3DLabelLoop();
  } else if (_3d.selectedId == null) {
    stop3DLabelLoop();
  }
}

function build3DLabelsForSet(idSet) {
  // Variant of build3DLabels() that draws labels for an arbitrary
  // node-id set instead of the current selection.
  clear3DLabels();
  if (!_3d.graph) return;
  const layer = document.getElementById('threed-label-layer');
  const data = _3d.graph.graphData();
  for (const n of data.nodes) {
    if (!idSet.has(n.id)) continue;
    const div = document.createElement('div');
    div.className = 'threed-label';
    div.textContent = n.label || '';
    div.style.borderColor = communityColor(n.community || 0);
    layer.appendChild(div);
    _3dLabels.divs.set(n.id, div);
  }
}

async function switchTo3DView() {
  _state.viewMode = 'symbols3d';
  document.getElementById('view-mode').value = 'symbols3d';
  document.getElementById('back-to-dirs').style.display = 'none';
  document.getElementById('min-degree-label').style.display = '';
  show3DContainer();
  setStats('<span class="loading-spinner"></span> loading 3D…');
  try {
    const data = await fetchData(_state.minDegree);
    rebuild3DGraph(data);
  } catch (e) {
    setStats('error: ' + e.message);
  }
}

function rebuild3DGraph(data) {
  const container = document.getElementById('threed-container');
  // Reuse the existing 3D graph if present, just swap data — keeps
  // the WebGL context alive across re-filters (min-degree slider).
  if (!_3d.graph) {
    _3d.graph = ForceGraph3D({ controlType: 'orbit' })(container)
      .backgroundColor('#08081a')
      .nodeLabel(n => `${n.label}\n${n.file || ''}${n.line ? ':' + n.line : ''}\ndegree ${n.degree}`)
      // Two visual cues for "this node is not adjacent to your
      // selection": dim color + shrunken size. Per-node opacity in
      // 3d-force-graph requires a custom nodeThreeObject + a stable
      // THREE handle, which proved fragile across UMD-bundle paths.
      // Color + size achieves the same visual recession.
      .nodeColor(n => _3dIsHighlighted(n.id)
        ? communityColor(n.community || 0)
        : '#1a2030')
      .nodeVal(n => {
        const base = Math.max(1, Math.sqrt(n.degree || 1));
        return _3dIsHighlighted(n.id) ? base : base * 0.3;
      })
      .nodeOpacity(0.9)
      // Edge color: cyan when touching the selected node; default
      // community-source tint when nothing is selected. (Hidden
      // edges go through linkVisibility below.)
      .linkColor(l => {
        const srcId = (l.source && l.source.id !== undefined) ? l.source.id : l.source;
        if (_3d.selectedId != null) return '#5de3ff';
        const srcNode = (l.source && l.source.community !== undefined)
          ? l.source
          : (data.nodes.find(n => n.id === srcId) || {});
        return hexWithAlpha(communityColor(srcNode.community || 0), 0.25);
      })
      .linkOpacity(0.55)
      .linkWidth(l => _3d.selectedId == null ? 0.4 : 1.2)
      // Hide every edge whose endpoints aren't in the current
      // highlight set, so the visible edge graph collapses to:
      //   - selection mode: edges touching _3d.selectedId
      //   - search mode:    edges between two search matches
      //   - default:        all edges
      .linkVisibility(l => {
        const srcId = (l.source && l.source.id !== undefined) ? l.source.id : l.source;
        const dstId = (l.target && l.target.id !== undefined) ? l.target.id : l.target;
        if (_3d.searchSet.size > 0) {
          return _3d.searchSet.has(srcId) && _3d.searchSet.has(dstId);
        }
        if (_3d.selectedId == null) return true;
        return srcId === _3d.selectedId || dstId === _3d.selectedId;
      })
      // Click → set selection, recompute neighbor set, mutate every
      // node's material in place, refresh link accessors, populate
      // the detail pane, and aim the camera.
      .onNodeClick(n => {
        // Highlight + detail-pane only. Camera stays put so the user's
        // orbit/zoom state isn't yanked out from under them on every
        // click.
        _3d.currentNode = n;
        _3d.selectedId = n.id;
        _3d.neighborSet = new Set(_3d.adjacency.get(n.id) || []);
        select3DNode(n);
        refresh3DHighlight();
        build3DLabels();
        start3DLabelLoop();
      })
      .onBackgroundClick(() => {
        _3d.selectedId = null;
        _3d.neighborSet = new Set();
        refresh3DHighlight();
        stop3DLabelLoop();
        document.getElementById('node-info').innerHTML =
          '<div id="empty-state">Click a node to inspect.<br>Drag to rotate, scroll to zoom.</div>';
      });
  }
  // Build the adjacency map so neighbor-only highlighting on click
  // is O(1) per render frame. Both directions because the graph is
  // logically undirected for the neighbor-overlay purpose.
  _3d.adjacency = new Map();
  for (const e of data.edges) {
    if (!_3d.adjacency.has(e.source)) _3d.adjacency.set(e.source, new Set());
    if (!_3d.adjacency.has(e.target)) _3d.adjacency.set(e.target, new Set());
    _3d.adjacency.get(e.source).add(e.target);
    _3d.adjacency.get(e.target).add(e.source);
  }
  // Reset selection across reloads (min-degree change, view switch).
  _3d.selectedId = null;
  _3d.neighborSet = new Set();

  // Build the graph payload — convert our edge {source,target} shape
  // 3d-force-graph accepts as-is.
  _3d.graph.graphData({
    nodes: data.nodes.map(n => ({
      id: n.id,
      label: n.label,
      community: n.community,
      community_label: n.community_label,
      file: n.file,
      line: n.line,
      degree: n.degree,
      kind: n.kind,
    })),
    links: data.edges.map(e => ({ source: e.source, target: e.target, kind: e.kind })),
  });
  setStats(`${data.nodes.length} nodes · ${data.edges.length} edges · 3D · drag to rotate, scroll to zoom`);
}

function select3DNode(n) {
  // Mirror the 2D selectNode behaviour for the right-side detail
  // pane. We don't have a graphology graph in 3D mode, so we hand-
  // build the same fields the 2D selectNode renders.
  _state.highlightedId = String(n.id);
  const el = document.getElementById('node-info');
  if (!el) return;
  el.innerHTML = `
    <div class="field"><div class="k">name</div><div class="v">${escapeHtml(n.label || '')}</div></div>
    <div class="field"><div class="k">kind</div><div class="v">${escapeHtml(n.kind || '')}</div></div>
    <div class="field"><div class="k">file</div><div class="v">${escapeHtml(n.file || '?')}${n.line ? ':' + n.line : ''}</div></div>
    <div class="field"><div class="k">degree</div><div class="v">${n.degree}</div></div>
    <div class="field"><div class="k">community</div><div class="v"><span class="community-swatch" style="background:${communityColor(n.community || 0)}"></span>${escapeHtml(n.community_label || '?')}</div></div>
  `;
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

async function checkStaleness() {
  // Compare the codegraph's recorded HEAD against AetherSDR's live
  // HEAD; show a banner if the index is behind. Severe (>10 commits)
  // gets a red banner; small drift gets amber. Silent on errors —
  // the UI shouldn't shout about an offline git or missing metadata.
  try {
    const r = await fetch('/api/codegraph/staleness');
    if (!r.ok) return;
    const d = await r.json();
    if (!d.is_stale) return;
    const banner = document.getElementById('stale-banner');
    const cb = d.commits_behind;
    const severe = (cb < 0) || (cb > 10);
    banner.classList.toggle('severe', severe);
    const cbText = (cb < 0) ? 'unknown (recorded SHA unreachable)' : `${cb} commit${cb===1?'':'s'} behind`;
    const recorded = (d.src_head_sha || '').substring(0, 8);
    const current = (d.current_head_sha || '').substring(0, 8);
    banner.innerHTML =
      `<b>Codegraph is stale</b> — ${cbText}. ` +
      `Indexed <span class="stale-sha">${escapeHtml(recorded)}</span>, ` +
      `HEAD is <span class="stale-sha">${escapeHtml(current)}</span>. ` +
      `Last extraction: ${escapeHtml(d.extracted_at || '?')}. ` +
      `Re-run nightly job to refresh.`;
    banner.style.display = 'flex';
  } catch (e) { /* silent */ }
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
    // Labels enabled at the renderer level so forceLabel can override
    // them per-node. We pin labelRenderedSizeThreshold to 1000 so the
    // default behaviour (no selection, no search) shows no labels —
    // only nodes whose reducer returns forceLabel:true will paint.
    renderLabels: true,
    labelRenderedSizeThreshold: 1000,
    // Use the custom pill-backed label renderer for both default and
    // hover paths. Without the pill, label text sits directly on top
    // of dense edges and dim background dots and becomes illegible.
    defaultDrawNodeLabel: drawLabelWithPill,
    defaultDrawNodeHover: drawLabelWithPill,
    labelColor: { color: '#e0e8f0' },
    labelFont: 'SF Mono, monospace',
    labelSize: 11,
    labelWeight: '600',
    minCameraRatio: 0.005,
    maxCameraRatio: 10,
    // Selection emphasis: when a node is selected via click,
    // highlight it and its neighbors + their edges; dim the rest.
    nodeReducer: (node, data) => {
      const g = _state.graph;
      if (!g) return data;
      // Search mode: matches get a forced label + size boost; non-
      // matches dim but keep their label attribute intact so hover
      // still shows the full qualified name in the pill.
      if (_state.searchMatches.size > 0) {
        if (_state.searchMatches.has(node)) {
          return { ...data, size: (data.size || 2) * 2.5, forceLabel: true, zIndex: 2 };
        }
        return { ...data, color: '#1a2030', zIndex: 0 };
      }
      const sel = _state.highlightedId;
      if (!sel) return data;
      const isSel = (node === sel);
      const isNeighbor = g.hasEdge(sel, node) || g.hasEdge(node, sel);
      if (isSel) return { ...data, size: (data.size || 2) * 2.2, forceLabel: true, zIndex: 2 };
      if (isNeighbor) {
        // Progressive label disclosure: label the top-N neighbors
        // by degree, where N scales inversely with the camera ratio.
        // At default zoom (ratio ~1) only the 5 most-connected
        // neighbors get labels; zoom in to reveal more in tiers.
        //   ratio 1.0  → top 5
        //   ratio 0.5  → top 12
        //   ratio 0.2  → top 30
        //   ratio 0.05 → top 100
        //   ratio 0.005 (max zoom) → top 1000 (effectively all)
        const ratio = (_state.sigma && _state.sigma.getCamera().ratio) || 1;
        const list = _state.neighborsByDegree || [];
        // Inverse-power curve: N(ratio) = round(5 / ratio).
        // With minCameraRatio=0.005 the user can always zoom in deep
        // enough to reveal every neighbor regardless of count.
        let n = Math.round(5 / Math.max(ratio, 0.005));
        n = Math.min(n, list.length);
        // Build a small cache so we don't iterate the list every node
        // reducer call. Recompute when ratio bucket changes.
        if (!_state._labelCacheKey || _state._labelCacheKey !== `${sel}|${n}`) {
          _state._labelCache = new Set(list.slice(0, n));
          _state._labelCacheKey = `${sel}|${n}`;
        }
        const showLabel = _state._labelCache.has(node);
        return { ...data, forceLabel: showLabel, zIndex: 1 };
      }
      return { ...data, color: '#1a2030', zIndex: 0 };
    },
    edgeReducer: (edge, data) => {
      const g = _state.graph;
      if (!g) return data;
      // Hide edges in search mode — fewer visual distractions.
      if (_state.searchMatches.size > 0) {
        const ext = g.extremities(edge);
        const both = _state.searchMatches.has(ext[0]) && _state.searchMatches.has(ext[1]);
        if (!both) return { ...data, hidden: true };
        return { ...data, color: '#5de3ff', size: 0.8, zIndex: 1 };
      }
      const sel = _state.highlightedId;
      if (!sel) return data;
      const ext = g.extremities(edge);
      const touches = (ext[0] === sel || ext[1] === sel);
      if (touches) return { ...data, color: '#5de3ff', size: 0.8, zIndex: 1 };
      return { ...data, hidden: true };
    },
  });
  _state.sigma.on('clickNode', e => selectNode(e.node));
  _state.sigma.on('clickStage', () => selectNode(null));
  // Force the reducer to re-run on every camera change so the
  // progressive label-disclosure threshold updates as the user zooms.
  // Sigma's render pipeline caches reducer output between frames if
  // attributes don't change; an explicit refresh bypasses that.
  // Invalidate the label cache so the next reducer pass recomputes.
  _state.sigma.getCamera().on('updated', () => {
    if (_state.highlightedId) {
      _state._labelCacheKey = null;
      _state.sigma.refresh();
    }
  });

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
  // Precompute the neighbor IDs sorted by degree descending — the
  // reducer uses this list to label only the top-N at any given zoom.
  _state.neighborsByDegree = [];
  if (nodeId && _state.graph) {
    const g = _state.graph;
    const ns = g.neighbors(nodeId);
    ns.sort((a, b) => (g.getNodeAttribute(b, 'degree') || 0) -
                      (g.getNodeAttribute(a, 'degree') || 0));
    _state.neighborsByDegree = ns;
  }
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
  // Phase 3 enrichment: ask the API which concepts are connected
  // to this symbol via documented_in / rationale_for / motivates /
  // implements_pattern / obsolesces edges, and append a
  // "Documented as" section to the detail pane.
  fetch('/api/codegraph/concept-rationale?id=' + encodeURIComponent(nodeId))
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      if (!d || !d.concepts || !d.concepts.length) return;
      const html = d.concepts.map(c => {
        const score = (c.confidence_score || 0).toFixed(2);
        return `<div style="margin:4px 0;padding:4px 6px;border-left:2px solid #ffaa00;background:#1a1208">
          <div style="font-size:10px;color:#ffcc44">${escapeHtml(c.relation)} <span style="color:#607080">conf ${score}</span></div>
          <div style="font-family:'SF Mono',monospace;font-size:11px;color:#d0d8e0">${escapeHtml(c.name)}</div>
          <div style="font-size:10px;color:#809090;margin-top:2px">${escapeHtml((c.description || '').substring(0, 150))}</div>
        </div>`;
      }).join('');
      const info = document.getElementById('node-info');
      // Only inject if we still have the same node selected by the time
      // the fetch returns (otherwise we'd dump stale content).
      if (_state.highlightedId === nodeId) {
        info.insertAdjacentHTML('beforeend',
          `<h3 style="margin-top:14px">Documented as <span style="color:#607080;font-weight:normal">(${d.concepts.length} concept${d.concepts.length===1?'':'s'})</span></h3>${html}`);
      }
    })
    .catch(() => { /* silent */ });
}

function highlightCommunity(cid) {
  const g = _state.graph;
  g.forEachNode((nid, attr) => {
    const matches = (attr.community === cid);
    g.setNodeAttribute(nid, 'color', matches ? attr.color : '#152035');
  });
  _state.sigma.refresh();
}

// Mouse-wheel adjustment for the min-degree slider. Native range
// inputs ignore the wheel; this hooks it up so hovering and scrolling
// nudges the value by ±1. preventDefault stops the page from also
// scrolling. passive:false is required by Chrome to honor preventDefault
// on wheel events.
document.getElementById('min-degree').addEventListener('wheel', e => {
  e.preventDefault();
  const slider = e.currentTarget;
  const min = parseInt(slider.min, 10) || 0;
  const max = parseInt(slider.max, 10) || 50;
  const cur = parseInt(slider.value, 10);
  // Scroll up (negative deltaY) increases the value — matches the
  // visual intuition of "slide right when wheel goes up".
  const next = Math.max(min, Math.min(max, cur + (e.deltaY < 0 ? 1 : -1)));
  if (next !== cur) {
    slider.value = String(next);
    slider.dispatchEvent(new Event('input', { bubbles: true }));
  }
}, { passive: false });

let _refetchTimer = null;
document.getElementById('min-degree').addEventListener('input', e => {
  const v = parseInt(e.target.value, 10);
  document.getElementById('min-degree-val').textContent = v;
  _state.minDegree = v;
  if (_refetchTimer) clearTimeout(_refetchTimer);
  _refetchTimer = setTimeout(async () => {
    setStats('<span class="loading-spinner"></span> reloading…');
    try {
      const data = await fetchData(v);
      if (_state.viewMode === 'symbols3d') rebuild3DGraph(data);
      else rebuildGraph(data);
    } catch (e) { setStats('error: ' + e.message); }
  }, 250);
});

document.getElementById('search').addEventListener('input', e => {
  const q = e.target.value.toLowerCase().trim();
  // 3D mode has its own match-set + render path; route there if active.
  if (_state.viewMode === 'symbols3d') {
    apply3DSearch(q);
    return;
  }
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
    // Camera: only auto-zoom for a small match set, using Sigma's
    // node display coords (which are correctly normalized). For
    // many-match queries leave the camera as-is — the user already
    // has the full graph in view and the lit matches stand out
    // against the dimmed background. Moving the camera off-screen
    // (which my previous bbox-in-graph-coords math was doing) just
    // blacks out the canvas.
    if (_state.searchMatches.size === 1 && q.length >= 2) {
      const nid = [..._state.searchMatches][0];
      const dd = _state.sigma.getNodeDisplayData(nid);
      if (dd) {
        _state.sigma.getCamera().animate({ x: dd.x, y: dd.y, ratio: 0.15 }, { duration: 400 });
      }
    } else if (_state.searchMatches.size > 1 && _state.searchMatches.size <= 6 && q.length >= 2) {
      // Average the matches' display coords for a sensible center.
      let sx = 0, sy = 0, n = 0;
      for (const nid of _state.searchMatches) {
        const dd = _state.sigma.getNodeDisplayData(nid);
        if (dd) { sx += dd.x; sy += dd.y; n++; }
      }
      if (n) _state.sigma.getCamera().animate({ x: sx/n, y: sy/n, ratio: 0.35 }, { duration: 400 });
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

// "Hide singleton communities" checkbox — toggling refreshes whichever
// symbol-mode view is active so the filter takes effect immediately.
// Persisted in localStorage so reloads remember the setting.
// 3D canvas must follow the container size. Window resize fires for
// browser-window changes; ResizeObserver catches everything else
// (sidebar toggles, dev-tools open, etc).
window.addEventListener('resize', resize3D);
if (typeof ResizeObserver !== 'undefined') {
  new ResizeObserver(resize3D).observe(document.getElementById('threed-container'));
}

// View-mode toggle. Default lands in directory view (bubble overview);
// user can switch to flat symbol view via the dropdown or by drilling
// into a directory.
document.getElementById('view-mode').addEventListener('change', e => {
  if (e.target.value === 'dirs') switchToDirectoryView();
  else if (e.target.value === 'communities') switchToCommunityView();
  else if (e.target.value === 'concepts') switchToConceptView();
  else if (e.target.value === 'symbols3d') switchTo3DView();
  else if (e.target.value === 'graphify') switchToGraphifyView();
  else switchToSymbolView();
});
document.getElementById('back-to-dirs').addEventListener('click', () => {
  if (_state.drilledFrom === 'communities') switchToCommunityView();
  else switchToDirectoryView();
});

async function init() {
  try {
    _state.meta = await fetchMeta();
    document.getElementById('meta').innerHTML = Object.entries(_state.meta).map(([k,v]) =>
      `<div class="field"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div></div>`
    ).join('');
    // Default landing view: 3D symbols. Directories / Communities /
    // 2D symbols are one dropdown click away.
    show3DContainer();
    const data = await fetchData(_state.minDegree);
    rebuild3DGraph(data);
    startLiveOverlay();
    fetchBridges(20).then(renderBridgeList).catch(() => {});
    checkStaleness();
    // Deep-link support: /codegraph?focus=<qualified_name> selects the
    // matching node and aims the camera at it after the layout has had
    // a chance to compute initial positions. Used by the Agent Walk
    // blast-radius panel — clicking a high-risk caller jumps straight
    // to its position in the 3D graph.
    const focusName = new URLSearchParams(location.search).get('focus');
    if (focusName) {
      focusOnSymbol(focusName, data);
    }
  } catch (e) {
    setStats('error: ' + e.message);
    document.getElementById('node-info').innerHTML = '<div id="empty-state" style="color:#ff6b6b">' + escapeHtml(e.message) + '<br><br>Has codegraph-extract.py been run? Run:<br><code>bin/codegraph-extract.py; bin/codegraph-analyze.py</code></div>';
  }
}

// Find a node by its qualified_name (which the API returns as the
// node's `label` field — see /api/codegraph/data SQL: `qualified_name
// AS label`) and select + camera-zoom to it. Used by the deep-link
// flow from the Agent Walk blast-radius panel.
function focusOnSymbol(qualifiedName, data) {
  const node = (data.nodes || []).find(n => n.label === qualifiedName);
  if (!node) {
    // Common cause: the node was filtered out by the min-degree slider.
    // Banner the user with the situation; they can drop min-degree and
    // re-navigate via the same URL.
    setStats(`focus: "${qualifiedName}" not in current view (try lowering min-degree)`);
    return;
  }
  // Mirror what onNodeClick does — without the click. We need a brief
  // delay so the 3d-force-graph simulation has settled initial node
  // positions; querying node.x/y/z before the first tick gives undefined.
  // 800ms is comfortable; the layout is usually settled by ~300ms but
  // some larger graphs need longer.
  setTimeout(() => {
    _3d.currentNode = node;
    _3d.selectedId = node.id;
    _3d.neighborSet = new Set(_3d.adjacency.get(node.id) || []);
    select3DNode(node);
    refresh3DHighlight();
    // Render text labels on the focused node + every neighbor (mirrors
    // onNodeClick's behavior). Without this the user lands on a sea
    // of unlabeled dots and has to click to learn names — defeats the
    // whole point of arriving via a deep-link from the Agent Walk
    // blast-radius panel.
    build3DLabels();
    start3DLabelLoop();
    // Aim the camera. Position it `distance` units away along the
    // axis from origin through the node so we look "at" it from
    // outside the cluster. lookAt = node itself.
    if (_3d.graph && typeof node.x === 'number') {
      const distance = 120;
      const dist = Math.hypot(node.x, node.y, node.z) || 1;
      const ratio = 1 + distance / dist;
      _3d.graph.cameraPosition(
        { x: node.x * ratio, y: node.y * ratio, z: node.z * ratio },
        { x: node.x, y: node.y, z: node.z },
        1500
      );
    }
  }, 800);
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
header h1{margin:0;font-family:system-ui,sans-serif;font-size:16px;color:#5de3ff;font-weight:500;letter-spacing:0.5px}
header .picker{display:flex;align-items:center;gap:6px}
header select,header input{background:#0a0a1a;color:#c8d8e8;border:1px solid #304050;padding:4px 8px;font-family:inherit;font-size:11px;border-radius:3px;min-width:200px}
header select{min-width:340px}
header a.back{color:#607080;font-size:11px;text-decoration:none;margin-left:auto;border:1px solid #304050;padding:4px 10px;border-radius:6px}
header a.back:hover{color:#5de3ff;border-color:#5de3ff}
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
.event-dot:hover{stroke:#5de3ff;stroke-width:2}
.event-dot.sel{stroke:#5de3ff;stroke-width:2}
.color-WEBHOOK{fill:#aa88ff}
.color-SKILL{fill:#00ff88}
.color-SCAN{fill:#5de3ff}
.color-DEFENSE{fill:#6688ff}
.color-MCP{fill:#ffaa00}
.color-EXEC{fill:#607080}
.color-TOOL{fill:#ff6688}
.color-PROMPT{fill:#ff88dd}
.color-RESPONSE{fill:#88ddff}
.color-GUARD{fill:#ffdd44}
.color-OTHER{fill:#404060}
/* Bottom row: split into two panes — log stream (B) on the left,
 * event detail (C) on the right. Both fill the remaining vertical
 * space so the swimlane (A) above keeps its natural height. */
#bottom-pane{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:#20304a;border-top:1px solid #20304a;min-height:340px;height:42vh}
#log-stream,#detail{padding:12px 20px;background:#0e0e22;font-size:11px;line-height:1.5;overflow-y:auto}
#log-stream h3,#detail h3{font-family:system-ui,sans-serif;margin:0 0 8px 0;font-size:13px;color:#5de3ff;font-weight:500;letter-spacing:0.3px;position:sticky;top:0;background:#0e0e22;padding-bottom:6px;border-bottom:1px solid #20304a;z-index:1}
#detail .row{display:flex;margin-bottom:4px}
#detail .k{color:#607080;width:120px;flex-shrink:0}
#detail .v{color:#c8d8e8;font-family:'SF Mono',monospace;word-break:break-all}
#detail .stage-pill{display:inline-block;background:#203040;color:#5de3ff;padding:1px 8px;border-radius:10px;font-size:10px;margin-left:6px}
/* Log stream rows. Compact monospace so dense traces stay readable. */
#log-stream .lrow{display:flex;gap:8px;padding:2px 4px 2px 6px;font-family:'SF Mono',monospace;font-size:10px;border-radius:2px;cursor:pointer;align-items:baseline;border-left:3px solid #303040;background:#0e0e22}
#log-stream .lrow:hover{filter:brightness(1.4)}
#log-stream .lrow.cur{box-shadow:inset 0 0 0 1px #5de3ff;color:#fff}
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
.player button:hover{border-color:#5de3ff;color:#5de3ff}
.player button.active{background:#203040;color:#5de3ff;border-color:#5de3ff}
.player .speed-label{color:#607080}
.player .progress{flex:1;height:4px;background:#101025;border-radius:2px;position:relative;overflow:hidden;margin:0 12px}
.player .progress .bar{position:absolute;left:0;top:0;height:100%;background:#00ff88;width:0;transition:width 0.05s linear}
.player .progress .ts-label{color:#607080;font-size:10px;min-width:90px;text-align:right;font-family:'SF Mono',monospace}
.player .tok-counter{color:#00ff88;font-size:11px;min-width:155px;text-align:right;font-weight:600;font-family:'SF Mono',monospace}
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
/* Live mode indicator (replaces the player bar when polling) */
.live-bar{display:none;align-items:center;gap:12px;padding:8px 20px;background:#102018;border-bottom:1px solid #205040;font-size:11px;color:#c8d8e8}
.live-bar.on{display:flex}
.live-bar .dot{width:8px;height:8px;border-radius:50%;background:#ff2222;animation:live-pulse 1.1s ease-in-out infinite;display:inline-block;vertical-align:middle}
@keyframes live-pulse{0%,100%{opacity:1}50%{opacity:0.35}}
.live-bar .label{color:#ff5555;font-weight:bold;letter-spacing:0.5px}
.live-bar .meta{color:#607080}
.live-bar button{background:#101025;color:#c8d8e8;border:1px solid #304050;padding:4px 12px;font-family:inherit;font-size:11px;border-radius:3px;cursor:pointer}
.live-bar button:hover{border-color:#5de3ff;color:#5de3ff}
.live-bar .switch-live{margin-left:auto;background:#102030;border-color:#205070;color:#88ccff}
.live-bar .switch-live:hover{border-color:#88ccff;color:#bbe0ff}
/* Live nudge pill on replay mode (when trace is still active) */
.live-nudge{display:none;align-items:center;gap:10px;padding:6px 14px;margin:6px 20px;background:#102018;border:1px solid #205040;border-radius:14px;font-size:11px;color:#88ffaa;width:fit-content}
.live-nudge.on{display:inline-flex}
.live-nudge button{background:#205040;color:#bbffcc;border:1px solid #4a8060;padding:3px 10px;font-family:inherit;font-size:10px;border-radius:10px;cursor:pointer;letter-spacing:0.3px}
.live-nudge button:hover{background:#306050;border-color:#88ffaa}
/* New-trace banner */
.new-trace-banner{display:none;align-items:center;gap:10px;padding:8px 14px;margin:6px 20px;background:#0c1a2e;border:1px solid #2050a0;border-radius:6px;font-size:11px;color:#bbe0ff}
.new-trace-banner.on{display:flex}
.new-trace-banner .dot{width:7px;height:7px;border-radius:50%;background:#3a90ff;animation:live-pulse 1.6s ease-in-out infinite}
.new-trace-banner .info{flex:1}
.new-trace-banner .info .id{color:#88ccff;font-family:'SF Mono',monospace}
.new-trace-banner .info .sum{color:#7090b0;margin-left:6px}
.new-trace-banner button{background:#102438;color:#bbe0ff;border:1px solid #2050a0;padding:3px 12px;font-family:inherit;font-size:10px;border-radius:3px;cursor:pointer}
.new-trace-banner button:hover{background:#1a3a60;border-color:#88ccff}
.new-trace-banner .dismiss{background:transparent;border-color:transparent;color:#506070}
.new-trace-banner .dismiss:hover{background:transparent;color:#aabac8;border-color:transparent}
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
  <span><span class="swatch color-GUARD"></span>CodeGuard</span>
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
  <span class="tok-counter" id="tok-counter" title="Tokens (input+output) and API-equivalent cost at Fable 5 rates">—</span>
</div>
<div class="live-bar" id="live-bar">
  <span class="dot"></span><span class="label">LIVE</span>
  <span class="meta">polling every 2s · <span id="live-events">0 events</span></span>
  <button id="btn-stop-live" title="Stop polling and switch to replay">⏹ Stop &amp; switch to replay</button>
</div>
<div class="live-nudge" id="live-nudge">
  This trace is still in-flight
  <button id="btn-switch-live">▶ Switch to Live</button>
</div>
<div class="new-trace-banner" id="new-trace-banner">
  <span class="dot"></span>
  <span class="info">New trace started: <span class="id" id="ntb-id"></span><span class="sum" id="ntb-sum"></span></span>
  <button id="ntb-switch">Switch</button>
  <button id="ntb-newtab">New Tab</button>
  <button class="dismiss" id="ntb-dismiss">Dismiss</button>
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
let _tokenTimeline=[],_tokenTotal=null,_tokenByTime={};

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
    _tokenTimeline=(d.token_timeline||[]).map(e=>({t:new Date(e.time).getTime(),tok:(e.input||0)+(e.output||0),cost:e.cost||0}));
    _tokenTotal=d.token_total||null;showTokTotal();
    _tokenByTime={};(d.token_timeline||[]).forEach(x=>{_tokenByTime[x.time]=x;});
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
  // Event dots — uncategorized (stage 0) go in a thin row above the swimlane.
  // Blast-radius overlays are collected in a separate string and appended
  // after the main loop so SVG z-order paints them on top of the Edit dots.
  let blastOverlays='';
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
    // Blast-radius enrichment: TOOL events for Edit/Write that the
    // codegraph hook flagged carry a `blast_radius` field. Render the
    // Edit dot in its normal TOOL pink so the tool-call signal stays
    // visible, then collect a small risk-colored overlay dot (added
    // to the SVG AFTER all main dots so z-order paints it on top).
    const radius=5;
    const dotCls=isAlert?`event-dot alert-pulse ${colorCls}`:`event-dot ${colorCls}`;
    const titleExtra = e.blast_radius
      ? ` · blast risk ${e.blast_radius.risk_score} (${e.blast_radius.high_risk_count} high-risk)`
      : '';
    svg+=`<circle class="${dotCls}" data-i="${i}" cx="${xCenter}" cy="${yCenter}" r="${radius}"><title>${esc(e.type)} · ${esc(e.binary)} · ${esc((e.args||'').substring(0,80))}${esc(titleExtra)}</title></circle>`;
    if(e.blast_radius){
      const rs=e.blast_radius.risk_score||0;
      // Thresholds match the hook's MIN_RISK_SCORE (0.005) and the
      // dashboard's "yellow vs red" mental model.
      const fill = rs>=0.5 ? '#ff4444' : rs>=0.05 ? '#ffaa00' : '#88ddaa';
      // r=4 (vs r=5 for the TOOL dot underneath) so the pink rim is
      // visible around the overlay. Includes .event-dot class + data-i
      // so the existing click handler binds and selecting the overlay
      // reliably selects the right Edit event (vs. pointer-events:none,
      // which made the click pass through to whichever dot happened to
      // be on top in a busy lane). Black rim ensures it pops against
      // the TOOL pink even when colors are close.
      blastOverlays+=`<circle class="event-dot blast-dot color-GUARD" data-i="${i}" cx="${xCenter}" cy="${yCenter}" r="4" style="fill:${fill};stroke:#0a0a1a;stroke-width:1.2"><title>Blast risk ${rs} (${e.blast_radius.high_risk_count} high-risk symbols) — click for details</title></circle>`;
    }
  }
  // Append blast-radius overlays last so they stack ON TOP of the
  // Edit/Write dots they enrich.
  svg+=blastOverlays;
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
  // Per-event token usage: a claude-code event shares the exact timestamp of
  // its assistant turn, so join to that turn's recorded usage.
  let tokHtml='';
  const _tk=_tokenByTime[e.time];
  if(_tk && (e.source==='claude-code'||e.source==='claude-transcript')){
    const _mdl=_tk.model?(' \u00b7 '+esc(String(_tk.model).replace('claude-',''))):'';
    tokHtml='<div class="row"><div class="k">turn tokens</div>'+
      '<div class="v" title="Tokens + cost for the assistant turn that emitted this event (shared if the turn made several tool calls); priced per the model that turn used">'+
      'in '+_tk.input.toLocaleString('en-US')+' \u00b7 out '+_tk.output.toLocaleString('en-US')+
      ' \u00b7 cache '+(_tk.cache_read+_tk.cache_create).toLocaleString('en-US')+
      ' \u00b7 <span style="color:#00ff88">$'+(_tk.cost||0).toFixed(4)+'</span>'+_mdl+'</div></div>';
  }
  let blastHtml='';
  if(e.blast_radius){
    const b=e.blast_radius;
    const rs=b.risk_score||0;
    const tier = rs>=0.5 ? 'HIGH' : rs>=0.05 ? 'MEDIUM' : 'low';
    const tierColor = rs>=0.5 ? '#ff4444' : rs>=0.05 ? '#ffaa00' : '#88ddaa';
    let topRows='';
    if(b.top && b.top.length){
      topRows='<div style="margin-top:6px;font-size:10px;color:#a0b0c0">Top high-risk callers <span style="color:#607080">(click to open in Codegraph 3D)</span>:</div>';
      for(const t of b.top){
        // Deep-link to /codegraph?focus=<qualified_name> — the codegraph
        // page's init() picks up the focus param, finds the matching
        // node by label (= qualified_name), selects it, and animates
        // the camera to its position. Opens in a new tab so the user
        // doesn't lose their current Agent Walk view.
        const focusUrl='/codegraph?focus='+encodeURIComponent(t.name);
        topRows+=`<div style="font-family:'SF Mono',monospace;font-size:10px;padding:1px 0">`+
                 `<span style="color:#ffaa00">bw=${t.bw}</span> `+
                 `<span style="color:#607080">d=${t.d}</span> `+
                 `<a href="${focusUrl}" target="_blank" style="color:#88ccff;text-decoration:none;border-bottom:1px dotted #506070" `+
                 `onmouseover="this.style.color='#bbe0ff';this.style.borderBottomColor='#bbe0ff'" `+
                 `onmouseout="this.style.color='#88ccff';this.style.borderBottomColor='#506070'">`+
                 `${esc(t.name)}</a></div>`;
      }
    }
    blastHtml='<div style="margin-top:10px;padding:8px 10px;background:#15131c;'+
              'border-left:3px solid '+tierColor+';border-radius:3px">'+
              '<div style="font-size:11px;color:'+tierColor+';font-weight:600">'+
              'CODEGRAPH BLAST RADIUS · '+tier+' (risk '+rs+')</div>'+
              '<div style="font-size:10px;color:#8090a0;margin-top:2px">'+
              esc(b.symbols_count||0)+' symbol(s) edited · '+
              esc(b.callers_count||0)+' transitive callers · '+
              esc(b.high_risk_count||0)+' high-risk affected</div>'+
              topRows+
              '</div>';
  }
  d.innerHTML='<h3>Event detail <span class="stage-pill">stage '+stage+' · '+esc(stageName)+'</span></h3>'+
    '<div class="row"><div class="k">timestamp</div><div class="v">'+esc(e.time)+'</div></div>'+
    '<div class="row"><div class="k">type</div><div class="v">'+esc(e.type)+'</div></div>'+
    '<div class="row"><div class="k">source</div><div class="v">'+esc(e.source)+'</div></div>'+
    '<div class="row"><div class="k">binary</div><div class="v">'+esc(e.binary)+'</div></div>'+
    '<div class="row"><div class="k">uid</div><div class="v">'+esc(e.uid)+'</div></div>'+
    '<div class="row"><div class="k">policy</div><div class="v">'+esc(e.policy||'(none)')+'</div></div>'+
    '<div class="row"><div class="k">args</div><div class="v">'+esc(e.args)+'</div></div>'+
    '<div class="row"><div class="k">trace_id</div><div class="v">'+esc(e.trace_id)+'</div></div>'+
    tokHtml+
    blastHtml;
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
       `<span class="lstage" style="color:#5de3ff">${stage||'·'}</span>`+
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
    `<span class="lstage" style="color:#5de3ff">${stage||'·'}</span>`+
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
function _setTokCounter(tok,cost){
  const el=document.getElementById('tok-counter');
  if(!el)return;
  el.textContent='\u2b22 '+tok.toLocaleString('en-US')+' tok \u00b7 $'+cost.toFixed(2);
}
// Sum the trace's token usage up to a virtual playback time (ms epoch) and
// render it. Linear over the (small) timeline; called on each progress tick.
function updateTokAt(ms){
  let tok=0,cost=0;
  for(const e of _tokenTimeline){if(e.t<=ms){tok+=e.tok;cost+=e.cost;}}
  _setTokCounter(tok,cost);
}
function showTokTotal(){
  if(_tokenTotal)_setTokCounter((_tokenTotal.input||0)+(_tokenTotal.output||0),_tokenTotal.cost||0);
  else _setTokCounter(0,0);
}
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
  updateTokAt(t0);
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
    showTokTotal();
  },_replayDuration/_speed+50));
  // Progress bar tick
  _progressInterval=setInterval(()=>{
    const elapsed=performance.now()-_replayStart;
    const pct=Math.min(100,(elapsed/(_replayDuration/_speed))*100);
    document.getElementById('progress-bar').style.width=pct+'%';
    const tCurrent=new Date(t0+elapsed*_speed);
    document.getElementById('progress-ts').textContent=fmtTime(tCurrent.toISOString());
    updateTokAt(t0+elapsed*_speed);
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
  showTokTotal();
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
  updateTokAt(new Date(_events[idx].time).getTime());
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

// ── Live mode (event-driven, SSE) ───────────────────────────────────
// Subscribes to /api/agent-walk-stream via EventSource. The server
// pushes each new event as it lands in append_event() — no wall-clock
// poll. Honors Foundry-security-spec Principle III ("Liveness By
// Heartbeat, Never By Clock"): the only periodic traffic on this
// connection is a 15s `:ping` comment frame for keep-alive; payload
// frames are 100% event-driven.
let _liveMode=false,_liveES=null,_liveCursor='',_liveTraceId='';
const _dismissedTraces=new Set();

function startLive(traceId){
  if(!traceId)return;
  _liveMode=true;_liveTraceId=traceId;
  // Cursor = latest event already loaded; server picks up from there.
  _liveCursor=_events.length?_events[_events.length-1].time:'';
  document.getElementById('player').style.display='none';
  document.getElementById('live-nudge').classList.remove('on');
  document.getElementById('live-bar').classList.add('on');
  updateLiveCounter();
  openLiveStream();
}

function openLiveStream(){
  if(_liveES){try{_liveES.close()}catch(e){}}
  const url='/api/agent-walk-stream?trace='+encodeURIComponent(_liveTraceId)+
    '&since='+encodeURIComponent(_liveCursor||'');
  const es=new EventSource(url);
  _liveES=es;
  es.addEventListener('message',ev=>{
    if(!_liveMode){es.close();return}
    let msg;try{msg=JSON.parse(ev.data)}catch(e){return}
    if(msg.kind==='event'&&msg.entry){
      _events.push(msg.entry);
      _liveCursor=msg.entry.time||_liveCursor;
      renderSwimlane();
      logStreamAppendLive([msg.entry]);
      updateLiveCounter();
    }else if(msg.kind==='related'&&msg.trace_id){
      if(_dismissedTraces.has(msg.trace_id))return;
      if(msg.trace_id===_liveTraceId)return;
      showNewTraceBanner({trace_id:msg.trace_id,event_count:1,summary:msg.summary||''});
    }
  });
  es.addEventListener('backlog-done',ev=>{
    let d;try{d=JSON.parse(ev.data)}catch(e){d={}}
    if(d.cursor)_liveCursor=d.cursor;
  });
  es.addEventListener('complete',()=>{
    // Trace finished — close stream, keep the captured swimlane visible
    // in static replay mode so the user can scrub it.
    if(_liveES){try{_liveES.close()}catch(e){}_liveES=null}
    _liveMode=false;
    document.getElementById('live-bar').classList.remove('on');
    if(_events.length>0)document.getElementById('player').style.display='flex';
    const meta=document.getElementById('meta');
    if(meta&&!meta.querySelector('.completed-tag')){
      const s=document.createElement('span');
      s.className='completed-tag';s.style.cssText='margin-left:12px;color:#88ccff';
      s.textContent='✓ Trace completed';
      meta.appendChild(s);
    }
  });
  // EventSource auto-reconnects after the default ~3s on transport
  // errors. We just log; no manual retry needed.
  es.addEventListener('error',()=>{
    // Connection blip — EventSource will retry. If readyState===CLOSED
    // the server explicitly ended it (e.g. shutdown); reopen ourselves
    // after a brief delay so we recover from dashboard restarts.
    if(es.readyState===EventSource.CLOSED&&_liveMode){
      setTimeout(()=>{if(_liveMode)openLiveStream()},1500);
    }
  });
}

function stopLive(opts){
  opts=opts||{};
  _liveMode=false;
  if(_liveES){try{_liveES.close()}catch(e){}_liveES=null}
  document.getElementById('live-bar').classList.remove('on');
  if(_events.length>0)document.getElementById('player').style.display='flex';
}

function updateLiveCounter(){
  const el=document.getElementById('live-events');
  if(el)el.textContent=_events.length+' events';
}

// Append newly-arrived live events to the log stream pane via the
// existing logStreamAppend(idx) helper. The placeholder ("Press ▶
// Play …") is cleared on first call so the live rows appear cleanly.
function logStreamAppendLive(newEvents){
  const body=document.getElementById('log-stream-body');
  if(body){
    const placeholder=body.querySelector('.empty-state');
    if(placeholder)placeholder.remove();
  }
  const startIdx=_events.length-newEvents.length;
  for(let i=0;i<newEvents.length;i++){
    logStreamAppend(startIdx+i);
  }
}

function showNewTraceBanner(t){
  const banner=document.getElementById('new-trace-banner');
  document.getElementById('ntb-id').textContent=t.trace_id.substring(0,8)+'…';
  document.getElementById('ntb-sum').textContent=' ('+t.event_count+' events) '+(t.summary||'').substring(0,60);
  banner.dataset.traceId=t.trace_id;
  banner.classList.add('on');
}

function hideNewTraceBanner(){
  document.getElementById('new-trace-banner').classList.remove('on');
}

// Check if a just-loaded trace is still in-flight; if so, show the
// nudge pill offering to switch to live mode.
function maybeOfferLive(){
  if(_events.length===0)return;
  const last=_events[_events.length-1];
  const lastMs=new Date(last.time).getTime();
  const ageSec=(Date.now()-lastMs)/1000;
  const hasCleanup=_events.some(e=>e.stage===10);
  if(ageSec<30&&!hasCleanup){
    document.getElementById('live-nudge').classList.add('on');
  }else{
    document.getElementById('live-nudge').classList.remove('on');
  }
}

// Wrap loadTrace so we can (a) tear down any active poll before
// switching traces, (b) offer live mode if the loaded trace is still
// active, (c) auto-start live mode when URL carries ?live=1. The
// original loadTrace doesn't return a promise, so we schedule the
// post-load check on a short setTimeout — its internal fetch
// completes in ~50-200ms; 300ms gives generous headroom without
// being user-perceptible.
const _origLoadTrace=loadTrace;
loadTrace=function(traceId){
  if(_liveMode)stopLive();
  hideNewTraceBanner();
  document.getElementById('live-nudge').classList.remove('on');
  _origLoadTrace.call(this,traceId);
  if(!traceId)return;
  setTimeout(()=>{
    const urlLive=new URLSearchParams(location.search).get('live')==='1';
    if(urlLive&&_events.length>0){startLive(traceId)}
    else{maybeOfferLive()}
  },300);
};

// Wire live-mode buttons
document.getElementById('btn-stop-live').addEventListener('click',()=>stopLive());
document.getElementById('btn-switch-live').addEventListener('click',()=>{
  const sel=document.getElementById('trace-select').value||
    new URLSearchParams(location.search).get('trace');
  if(sel)startLive(sel);
});
document.getElementById('ntb-switch').addEventListener('click',()=>{
  const tid=document.getElementById('new-trace-banner').dataset.traceId;
  if(!tid)return;
  hideNewTraceBanner();
  const u=new URL(location.href);u.searchParams.set('trace',tid);u.searchParams.set('live','1');
  history.replaceState({},'',u);
  // Reset and start live on the new trace
  _events=[];_selectedIdx=-1;_liveCursor='';
  document.getElementById('swim').innerHTML='';
  logStreamClear();
  document.getElementById('trace-select').value=tid;
  // Fetch backlog via the normal endpoint, then start live tail
  fetch('/api/agent-walk?trace='+encodeURIComponent(tid)).then(r=>r.json()).then(d=>{
    _events=d.events||[];renderSwimlane();
    _tokenTimeline=(d.token_timeline||[]).map(e=>({t:new Date(e.time).getTime(),tok:(e.input||0)+(e.output||0),cost:e.cost||0}));
    _tokenTotal=d.token_total||null;showTokTotal();
    _tokenByTime={};(d.token_timeline||[]).forEach(x=>{_tokenByTime[x.time]=x;});
    startLive(tid);
  });
});
document.getElementById('ntb-newtab').addEventListener('click',()=>{
  const tid=document.getElementById('new-trace-banner').dataset.traceId;
  if(!tid)return;
  window.open('/agent-walk?trace='+encodeURIComponent(tid)+'&live=1','_blank');
  hideNewTraceBanner();
});
document.getElementById('ntb-dismiss').addEventListener('click',()=>{
  const tid=document.getElementById('new-trace-banner').dataset.traceId;
  if(tid)_dismissedTraces.add(tid);
  hideNewTraceBanner();
});

// Wire pickers
document.getElementById('trace-select').addEventListener('change',ev=>{loadTrace(ev.target.value)});
document.getElementById('trace-input').addEventListener('change',ev=>{loadTrace(ev.target.value.trim())});
document.getElementById('trace-input').addEventListener('keydown',ev=>{if(ev.key==='Enter')loadTrace(ev.target.value.trim())});

window.addEventListener('resize',()=>{if(_events.length>0)renderSwimlane()});
loadRecentTraces();
</script>
</body></html>"""

# Cartographer viewer — renders repo-context.json (the Cartographer pack) as
# styled cards/tables in the AetherSDR design language. Self-contained, no
# external deps (CSP-safe). Served at /cartographer; the scanner row links here.
CARTOGRAPHER_HTML = r"""<!DOCTYPE html>
<html><head><title>Cartographer — Repo Context</title><meta charset="utf-8">
<style>
:root{--bg:#060b13;--bg-1:#0a121e;--bg-2:#0e1a2a;--bg-3:#12233a;--panel:rgba(18,34,56,.55);--ink:#eaf2fb;--ink-soft:#c4d4e8;--muted:#8598b4;--muted-dim:#5f708a;--line:rgba(120,165,210,.12);--line-hi:rgba(120,190,230,.28);--accent:#3aa7ff;--accent-bright:#5de3ff;--good:#27a86f;--warn:#b3831c;--crit:#e8506a;--radius:16px;--radius-sm:11px;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,sans-serif;--mono:'SF Mono','JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--ink-soft);font-family:var(--sans);font-size:13px}
.hdr{background:var(--bg-1);border-bottom:1px solid var(--line);padding:12px 24px;display:flex;justify-content:space-between;align-items:baseline}
.hdr h1{font-size:19px;color:var(--accent-bright);font-weight:600;letter-spacing:.4px}
.hdr .sub{color:var(--muted-dim);font-size:11px;font-family:var(--mono)}
.hdr a{color:var(--muted);font-size:11px;text-decoration:none;border:1px solid var(--line-hi);border-radius:8px;padding:4px 12px}
.hdr a:hover{color:var(--accent-bright);border-color:var(--accent)}
.wrap{max-width:1200px;margin:0 auto;padding:20px 24px 60px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:14px 16px}
.kpi .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px}
.kpi .v{font-size:26px;font-weight:600;color:var(--ink);margin-top:4px}
.kpi .v.crit{color:var(--crit)}.kpi .v.warn{color:var(--warn)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 22px;margin-bottom:16px}
.panel h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:12px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--muted);font-weight:600;padding:5px 8px;border-bottom:1px solid var(--line-hi);position:sticky;top:0;background:var(--bg-1)}
td{padding:5px 8px;border-bottom:1px solid var(--line);color:var(--ink-soft);vertical-align:top}
td.mono,.mono{font-family:var(--mono);font-size:11px}
tr:hover td{background:var(--bg-2)}
.cat{margin-bottom:14px;border:1px solid var(--line);border-radius:var(--radius-sm);overflow:hidden}
.cat>summary{cursor:pointer;padding:10px 14px;background:var(--bg-2);font-weight:600;color:var(--ink-soft);list-style:none;display:flex;justify-content:space-between;align-items:center}
.cat>summary::-webkit-details-marker{display:none}
.cat>summary:hover{background:var(--bg-3)}
.cat .body{padding:4px 14px 10px}
.cat .desc{color:var(--muted);font-size:11px;font-weight:400;margin-left:10px}
.pill{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:100px}
.sev-CRITICAL{background:rgba(232,80,106,.14);color:#f2879b}.sev-HIGH{background:rgba(232,80,106,.10);color:var(--crit)}
.sev-MEDIUM{background:rgba(179,131,28,.14);color:#d9a02b}.sev-LOW{background:rgba(39,168,111,.14);color:var(--good)}
.chip{display:inline-block;background:var(--bg-3);border:1px solid var(--line-hi);border-radius:100px;padding:2px 10px;font-size:11px;margin:2px 4px 2px 0;color:var(--ink-soft)}
.chip .n{color:var(--accent-bright);font-weight:600;margin-left:4px}
.loading,.empty{color:var(--muted-dim);padding:40px;text-align:center}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
a.src{color:var(--accent);text-decoration:none}a.src:hover{color:var(--accent-bright)}
</style></head><body>
<div class="hdr">
  <div><h1>Cartographer &middot; Repo Context</h1><div class="sub" id="freshness">loading&hellip;</div></div>
  <a href="/">&larr; Dashboard</a>
</div>
<div class="wrap" id="root"><div class="loading">Loading repo-context pack&hellip;</div></div>
<script>
const CAT_COLOR={buffer_ops:'#e85578',format:'#bd7c20',cmd_exec:'#e8506a',path_ops:'#2f96ea',alloc_free:'#a878e0',deserial:'#21a184',input_read:'#5de3ff'};
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function shortsym(s){s=String(s||'');const p=s.split('::');return p[p.length-1]||s}
fetch('/repo-context.json').then(r=>{if(!r.ok)throw 0;return r.json()}).then(render).catch(()=>{
  document.getElementById('root').innerHTML='<div class="empty">No repo-context pack available yet.<br><span style="font-size:11px">The Cartographer runs on the codegraph refresh cadence (nightly + on push).</span></div>';
});
function render(p){
  const l0=p.l0_repo_card||{},subs=p.l1_subsystems||[],sec=p.l2_security||{},keys=p.l3_key_symbols||[];
  document.getElementById('freshness').innerHTML=`HEAD ${esc((l0.head_sha||'').slice(0,12))} &middot; ${esc(l0.extractor_version||'')} &middot; generated ${esc(p.generated_at||'')}`;
  let h='';
  // L0 KPIs
  const cveCls=l0.open_cve_count>0?'crit':'';
  h+='<div class="kpis">'+[
    ['Symbols',(l0.symbol_count||0).toLocaleString(),''],
    ['Edges',(l0.edge_count||0).toLocaleString(),''],
    ['Subsystems',l0.community_count||subs.length||0,''],
    ['Tagged sites',l0.call_tag_count||0,''],
    ['Open CVEs',l0.open_cve_count||0,cveCls],
    ['Dependencies',l0.dependency_count||0,''],
  ].map(([l,v,c])=>`<div class="kpi"><div class="l">${l}</div><div class="v ${c}">${v}</div></div>`).join('')+'</div>';
  // L2 security overlay (lead with it — the point of the page)
  h+='<div class="panel"><h2>Security overlay</h2>';
  const cats=sec.categories||{};
  if(!sec.available||!Object.keys(cats).length){h+='<div class="empty">No call-site overlay (DB predates the tagger).</div>';}
  else{
    for(const [cat,d] of Object.entries(cats)){
      const col=CAT_COLOR[cat]||'#8598b4';
      h+=`<details class="cat"${cat==='buffer_ops'||cat==='cmd_exec'?' open':''}><summary><span><span class="dot" style="background:${col}"></span>${esc(cat)}<span class="desc">${esc(d.desc||'')}</span></span><span class="pill" style="background:${col}22;color:${col}">${d.count} sites</span></summary><div class="body"><table><thead><tr><th>File:line</th><th>API</th><th>Enclosing function</th><th>betw.</th></tr></thead><tbody>`;
      for(const s of (d.top_sites||[])){
        h+=`<tr><td class="mono">${esc(s.file)}:${s.line}</td><td class="mono" style="color:${col}">${esc(s.api)}</td><td class="mono">${esc(shortsym(s.function))}</td><td class="mono">${(s.betweenness||0).toFixed(3)}</td></tr>`;
      }
      h+='</tbody></table></div></details>';
    }
    const ib=sec.input_boundaries||[];
    if(ib.length){h+='<h2 style="margin-top:16px">Input boundaries &middot; attack surface</h2>';
      for(const b of ib.slice(0,15))h+=`<span class="chip">${esc(shortsym(b.function))}<span class="n">${(b.betweenness||0).toFixed(2)}</span></span>`;}
  }
  h+='</div>';
  // Dependency CVEs
  const cves=sec.dependency_cves||[];
  if(cves.length){
    h+='<div class="panel"><h2>Dependency CVEs</h2><table><thead><tr><th>Severity</th><th>Component</th><th>CVE</th><th>Summary</th></tr></thead><tbody>';
    for(const v of cves)h+=`<tr><td><span class="pill sev-${esc(v.severity||'')}">${esc(v.severity||'?')}</span></td><td>${esc(v.component)}</td><td class="mono">${esc(v.id)}</td><td>${esc(v.summary||'')}</td></tr>`;
    h+='</tbody></table></div>';
  }
  // L1 subsystems
  h+='<div class="panel"><h2>Subsystem map</h2><table><thead><tr><th>Subsystem</th><th>Symbols</th><th>Key members</th><th>Concepts</th></tr></thead><tbody>';
  for(const s of subs)h+=`<tr><td class="mono">${esc(s.label)}</td><td>${s.size}</td><td class="mono">${(s.key_symbols||[]).map(shortsym).map(esc).slice(0,4).join(', ')}</td><td>${(s.concepts||[]).map(esc).join(', ')||'&mdash;'}</td></tr>`;
  h+='</tbody></table></div>';
  // L3 key symbols
  h+='<div class="panel"><h2>Key symbols &middot; by betweenness</h2><table><thead><tr><th>Symbol</th><th>Location</th><th>Subsystem</th><th>betw.</th></tr></thead><tbody>';
  for(const k of keys)h+=`<tr><td class="mono">${esc(shortsym(k.symbol))}</td><td class="mono">${esc(k.loc)}</td><td class="mono">${esc(k.subsystem)}</td><td class="mono">${(k.betweenness||0).toFixed(3)}</td></tr>`;
  h+='</tbody></table></div>';
  h+='<div style="text-align:right;margin-top:8px"><a class="src" href="/repo-context.md" target="_blank">raw markdown &#x2197;</a> &nbsp; <a class="src" href="/repo-context.json" target="_blank">json &#x2197;</a></div>';
  document.getElementById('root').innerHTML=h;
}
</script>
</body></html>"""

def _classify_agent_walk_stage(typ, src, args, binary):
    """Return 1..10 for the 10 walk stages; 0 if uncategorized.

    Pure function over (type, source, args, binary). Used by both the
    /api/agent-walk endpoint (replay — fetch all events for one trace)
    and /api/agent-walk-live (live polling — only events since cursor).

    Order matters — first match wins. The classifier is keyed off
    observed real-trace shapes (see project_agent_walk_demo memory
    for sample rows). Stage 0 events are filtered out at the caller."""
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
    # 7. MCP — server-side MCP activity
    if typ == 'MCP':
        return 7
    # 4. Scanning — skill-scanner + mcp-scanner + codeguard family
    if src in ('skill-scan', 'mcp-scan', 'vt-scan', 'prompt-scan', 'codeguard'):
        return 4
    if typ in ('SCAN', 'GUARD') and binary in ('skill-scanner', 'mcp-scanner', 'vt-scan', 'prompt-scanner', 'codeguard'):
        return 4
    # 6. Tool calls — DC verdict / tool-hook events for non-MCP tools
    if src == 'defenseclaw' and (
            'pretooluse' in args or 'posttooluse' in args
            or 'tool' in args
            or 'action=' in args or 'verdict' in args
            or 'gateway completed' in args):
        return 6
    # 2. Orchestrator — run boundaries + state-machine work
    if src == 'skill-dispatch' and (
            'agent-run' in binary or 'orch-' in binary):
        return 2
    # 3. Skill selection — every other skill-dispatch event
    if src == 'skill-dispatch':
        return 3
    return 0


# ── Short-TTL response caches ────────────────────────────────────────────────
# /api/events (stats block) and /api/agent-walk-traces (picker) are both
# expensive to build and are polled continuously by the dashboard UI + TUI.
# Each is cached for a second or two so a burst of concurrent polls reuses
# one computed result instead of every request rebuilding it. The dashboard
# is a live view; sub-second staleness on counters is imperceptible.
STATS_PAYLOAD_TTL = 1.0   # seconds
PICKER_CACHE_TTL  = 10.0  # seconds
_stats_payload = {'ts': 0.0, 'data': None}
_stats_payload_lock = threading.Lock()
_picker_cache = {}        # (limit, include_skipped) -> (monotonic_ts, traces)
_picker_cache_lock = threading.Lock()


def build_stats_payload():
    """Build the stats/tokens/rings/tools block served by /api/events,
    cached for STATS_PAYLOAD_TTL. The underlying counters update
    continuously in background threads; caching collapses concurrent
    polls into a single build (the /api/events hot path was rebuilding
    this whole nested dict on every request)."""
    now = time.monotonic()
    with _stats_payload_lock:
        if _stats_payload['data'] is not None and now - _stats_payload['ts'] < STATS_PAYLOAD_TTL:
            return _stats_payload['data']
    with lock:
        payload = {
            'stats': {
                'total_events': stats['total_events'],
                'exec_count': stats['exec_count'],
                'kprobe_count': stats['kprobe_count'],
                'exit_count': stats['exit_count'],
                'aetherclaude_events': stats['aetherclaude_events'],
                'network_connections': stats['network_connections'],
                'alert_count': len(stats['alerts']),
                'policy_hits': dict(stats['policy_hits']),
                'binaries_seen': dict(stats['binaries_seen']),
                'alerts': list(stats['alerts']),
                'suppressed': stats['suppressed'],
                'tokens': {
                    'input': token_stats['input'],
                    'output': token_stats['output'],
                    'cache_read': token_stats['cache_read'],
                    'cache_create': token_stats['cache_create'],
                    'messages': token_stats['messages'],
                    'total': token_stats['input'] + token_stats['output'],
                    'estimated_cost_usd': token_stats.get('cost', 0),
                    'cycle': {
                        'input': token_stats['cycle_input'],
                        'output': token_stats['cycle_output'],
                        'cache_read': token_stats['cycle_cache_read'],
                        'cache_create': token_stats['cycle_cache_create'],
                        'messages': token_stats['cycle_messages'],
                        'estimated_cost_usd': token_stats.get('cycle_cost', 0),
                        'cycle_start_iso': token_stats['cycle_start_iso'],
                        'subscription_amount_usd': token_stats['subscription_amount_usd'],
                    },
                    'lifetime': {
                        'estimated_cost_usd': token_stats.get('cost', 0),
                        'subscription_cycles_paid': token_stats['subscription_cycles_paid'],
                        'subscription_total_usd': round(
                            token_stats['subscription_amount_usd'] * token_stats['subscription_cycles_paid'], 2),
                        'subscription_start_iso': token_stats['subscription_start_iso'],
                    },
                },
                'tools': {'total': tool_stats['total'], 'breakdown': tool_stats['breakdown']},
            },
            'mcp_scan_details': ring_stats.get('r6_mcp_details', []),
            'rings': dict(ring_stats),
        }
    with _stats_payload_lock:
        _stats_payload['ts'] = now
        _stats_payload['data'] = payload
    return payload


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
        elif self.path == '/cartographer' or self.path.startswith('/cartographer?'):
            # Cartographer repo-context viewer — renders repo-context.json
            # (Foundry Cartographer pack) as styled cards/tables.
            self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
            self.wfile.write(CARTOGRAPHER_HTML.encode())
        elif self.path == '/codegraph/graphify' or self.path == '/codegraph/graphify.html':
            # Serve graphify's self-contained graph.html as a fallback
            # view mode. We render it inside an iframe so its vis-network
            # CSS / JS doesn't fight our Sigma + 3d-force-graph stack.
            try:
                with open(os.path.join(GRAPHIFY_OUT_DIR, 'graph.html'), 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                # Cache for the day; graphify writes a new file when
                # the nightly job re-runs.
                self.send_header('Cache-Control', 'public, max-age=300')
                self.end_headers()
                self.wfile.write(data)
            except (FileNotFoundError, OSError) as ex:
                self.send_response(503)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(
                    f'<html><body style="background:#0a0a1a;color:#c0c8d0;font-family:sans-serif;padding:40px;text-align:center">'
                    f'<h2>Graphify output not built yet</h2>'
                    f'<p>{GRAPHIFY_OUT_DIR}/graph.html does not exist.</p>'
                    f'<p>Run on the Mac Mini:</p>'
                    f'<pre style="text-align:left;display:inline-block;background:#1a1a2a;padding:12px;border-radius:6px">'
                    f'sudo -u aetherclaude bash -lc \\\n'
                    f'  &quot;GRAPHIFY_VIZ_NODE_LIMIT=10000 graphify cluster-only \\\n'
                    f'   /Users/aetherclaude/workspace/AetherSDR/src&quot;</pre>'
                    f'<p style="color:#607080;font-size:11px;margin-top:20px">Error: {ex}</p>'
                    f'</body></html>'.encode())
            return
        elif self.path.startswith('/codegraph/assets/'):
            # Static-file serve for the vendored Sigma+graphology JS.
            # Tight path-safety: name must be a known JS asset.
            name = self.path[len('/codegraph/assets/'):].split('?', 1)[0]
            ALLOWED = {
                'sigma.min.js': 'application/javascript',
                'graphology.umd.min.js': 'application/javascript',
                'graphology-library.min.js': 'application/javascript',
                '3d-force-graph.min.js': 'application/javascript',
                'three-spritetext.min.js': 'application/javascript',
                'three.min.js': 'application/javascript',
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
        elif self.path == '/api/codegraph/concept-graph':
            # Concept-centric subgraph for the "Concepts" view mode.
            # Returns every concept node + every code symbol any
            # concept connects to, along with the inter-concept and
            # concept-to-symbol edges. Code-only edges are dropped
            # (we don't need the full code graph here — only the
            # rationale layer + its anchor symbols).
            try:
                conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
                conn.row_factory = sqlite3.Row
                # All concepts
                concept_ids: set[int] = set()
                nodes: list[dict] = []
                for r in conn.execute(
                    'SELECT id, qualified_name AS label, name, '
                    '       parent_scope AS concept_kind, '
                    '       signature AS description, '
                    '       file_path, community_id AS community, '
                    '       community_label, degree '
                    '  FROM symbols WHERE kind = "concept"'
                ):
                    d = dict(r)
                    d['kind'] = 'concept'
                    nodes.append(d)
                    concept_ids.add(d['id'])
                # Concept ↔ anything edges (inferred only)
                edges: list[dict] = []
                anchor_ids: set[int] = set()
                for r in conn.execute(
                    'SELECT src_id, dst_id, kind, confidence_score '
                    '  FROM edges '
                    " WHERE confidence = 'INFERRED'"
                ):
                    src, dst = r['src_id'], r['dst_id']
                    src_is_c = src in concept_ids
                    dst_is_c = dst in concept_ids
                    if not src_is_c and not dst_is_c:
                        continue
                    edges.append({
                        'source': src, 'target': dst,
                        'kind': r['kind'],
                        'confidence_score': r['confidence_score'],
                    })
                    if not src_is_c:
                        anchor_ids.add(src)
                    if not dst_is_c:
                        anchor_ids.add(dst)
                # Hydrate the anchor code-symbol nodes
                if anchor_ids:
                    ph = ','.join('?' * len(anchor_ids))
                    for r in conn.execute(
                        f'SELECT id, qualified_name AS label, name, kind, '
                        f'       file_path, line_number, '
                        f'       community_id AS community, '
                        f'       community_label, degree '
                        f'  FROM symbols WHERE id IN ({ph})',
                        list(anchor_ids)
                    ):
                        nodes.append(dict(r))
                conn.close()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'nodes': nodes, 'edges': edges,
                    'concept_count': len(concept_ids),
                    'anchor_count': len(anchor_ids),
                }).encode())
            except sqlite3.Error as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
            return
        elif self.path == '/api/codegraph/concept-rationale':
            # Concepts attached to a single symbol — used by the
            # node-info sidebar's "Documented as" enrichment when a
            # code symbol is selected.
            try:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(self.path).query) if '?' in self.path else {}
                # The path-vs-query parsing above won't match because
                # the elif hit on exact path. Re-parse from raw self.path.
                from urllib.parse import urlparse as _u, parse_qs as _q
                qs = _q(_u(self.path).query)
                sid_raw = qs.get('id', [''])[0].strip()
                if not sid_raw:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(b'{"error":"id query param required"}')
                    return
                sid = int(sid_raw)
                conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
                conn.row_factory = sqlite3.Row
                rels = ('documented_in', 'rationale_for', 'motivates',
                        'implements_pattern', 'obsolesces')
                ph = ','.join('?' * len(rels))
                rows = conn.execute(
                    f'SELECT s.id, s.name, s.qualified_name, '
                    f'       s.parent_scope AS concept_kind, '
                    f'       s.signature AS description, '
                    f'       e.kind AS relation, e.confidence_score '
                    f'  FROM edges e JOIN symbols s ON e.src_id=s.id '
                    f' WHERE e.dst_id=? AND s.kind="concept" '
                    f'   AND e.kind IN ({ph})',
                    (sid, *rels)
                ).fetchall()
                rows2 = conn.execute(
                    f'SELECT s.id, s.name, s.qualified_name, '
                    f'       s.parent_scope AS concept_kind, '
                    f'       s.signature AS description, '
                    f'       e.kind AS relation, e.confidence_score '
                    f'  FROM edges e JOIN symbols s ON e.dst_id=s.id '
                    f' WHERE e.src_id=? AND s.kind="concept" '
                    f'   AND e.kind IN ({ph})',
                    (sid, *rels)
                ).fetchall()
                conn.close()
                seen = set()
                concepts = []
                for r in list(rows) + list(rows2):
                    if r['id'] in seen:
                        continue
                    seen.add(r['id'])
                    concepts.append(dict(r))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'concepts': concepts}).encode())
            except (sqlite3.Error, ValueError) as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
            return
        elif self.path == '/api/codegraph/communities':
            # Aggregate by Louvain community for a more granular bubble
            # overview than the 5-bucket directory view. Caps at the
            # top-50 communities by member count — the long tail of
            # singleton communities (median size = 1 on AetherSDR)
            # would otherwise drown the meaningful structural clusters.
            try:
                conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
                conn.row_factory = sqlite3.Row
                cid_of: dict[int, int] = {}
                cstats: dict[int, dict] = {}
                for r in conn.execute(
                    'SELECT id, community_id, community_label FROM symbols '
                    ' WHERE community_id IS NOT NULL'
                ):
                    cid = r['community_id']
                    cid_of[r['id']] = cid
                    bucket = cstats.setdefault(cid, {
                        'community_id': cid,
                        'label': r['community_label'] or f'cid:{cid}',
                        'symbol_count': 0,
                        'internal_edges': 0,
                        'external_edges': 0,
                        'top_symbols': [],
                    })
                    bucket['symbol_count'] += 1
                # Top symbols per community by degree
                for r in conn.execute(
                    'SELECT id, qualified_name, degree FROM symbols '
                    ' WHERE community_id IS NOT NULL ORDER BY degree DESC LIMIT 8000'
                ):
                    c = cid_of.get(r['id'])
                    if c is None:
                        continue
                    tops = cstats[c]['top_symbols']
                    if len(tops) < 3:
                        tops.append({
                            'name': r['qualified_name'], 'degree': r['degree'],
                        })
                edge_counts: dict[tuple[int, int], int] = {}
                for r in conn.execute('SELECT src_id, dst_id FROM edges'):
                    s = cid_of.get(r['src_id'])
                    t = cid_of.get(r['dst_id'])
                    if s is None or t is None:
                        continue
                    if s == t:
                        cstats[s]['internal_edges'] += 1
                        continue
                    cstats[s]['external_edges'] += 1
                    key = (s, t) if s < t else (t, s)
                    edge_counts[key] = edge_counts.get(key, 0) + 1
                conn.close()
                # Cap at top-50 by symbol count
                sorted_c = sorted(cstats.values(),
                                  key=lambda c: -c['symbol_count'])[:50]
                kept_ids = {c['community_id'] for c in sorted_c}
                kept_edges = [
                    {'source': str(s), 'target': str(t), 'weight': w}
                    for (s, t), w in edge_counts.items()
                    if s in kept_ids and t in kept_ids
                ]
                # Stringify community_id so it's safe as a graphology node key
                for c in sorted_c:
                    c['id'] = str(c['community_id'])
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'communities': sorted_c, 'edges': kept_edges,
                }).encode())
            except sqlite3.Error as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
            return
        elif self.path == '/api/codegraph/directories':
            # Aggregate the codegraph by top-level src/<dir> for the
            # directory drill-down view. Each entry collapses all
            # symbols under that directory into one bubble; edges
            # between directories are weighted by the call count.
            #
            # This addresses the hairball-on-default problem: the
            # 7K-node symbol view becomes a ~25-bubble overview, and
            # users click into a directory to see its symbols.
            try:
                conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
                conn.row_factory = sqlite3.Row
                # Pull every symbol's directory; we use the first two
                # path components ('src/gui', 'src/core', 'src/models', …).
                # Fewer components would lump everything together;
                # more would explode into per-class buckets.
                dir_of: dict[int, str] = {}
                dir_stats: dict[str, dict] = {}
                for r in conn.execute(
                    'SELECT id, file_path FROM symbols'
                ):
                    fp = r['file_path'] or ''
                    parts = fp.split('/')
                    if len(parts) >= 2 and parts[0] == 'src':
                        dirkey = f'src/{parts[1]}'
                    elif len(parts) >= 2:
                        dirkey = parts[0]
                    else:
                        dirkey = 'misc'
                    dir_of[r['id']] = dirkey
                    bucket = dir_stats.setdefault(dirkey, {
                        'path': dirkey, 'symbol_count': 0,
                        'internal_edges': 0, 'external_edges': 0,
                        'top_symbols': [],
                    })
                    bucket['symbol_count'] += 1
                # Per-directory top symbols by degree (for the tooltip).
                for r in conn.execute(
                    'SELECT id, qualified_name, degree FROM symbols '
                    ' ORDER BY degree DESC LIMIT 5000'
                ):
                    d = dir_of.get(r['id'])
                    if not d:
                        continue
                    tops = dir_stats[d]['top_symbols']
                    if len(tops) < 5:
                        tops.append({
                            'name': r['qualified_name'], 'degree': r['degree']
                        })
                # Aggregate inter-directory edges.
                edge_counts: dict[tuple[str, str], int] = {}
                for r in conn.execute(
                    'SELECT src_id, dst_id FROM edges'
                ):
                    s = dir_of.get(r['src_id'])
                    t = dir_of.get(r['dst_id'])
                    if not s or not t:
                        continue
                    if s == t:
                        dir_stats[s]['internal_edges'] += 1
                        continue
                    dir_stats[s]['external_edges'] += 1
                    key = (s, t)
                    edge_counts[key] = edge_counts.get(key, 0) + 1
                conn.close()
                dirs = sorted(dir_stats.values(),
                              key=lambda d: -d['symbol_count'])
                edges = [
                    {'source': s, 'target': t, 'weight': w}
                    for (s, t), w in edge_counts.items()
                ]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'directories': dirs, 'edges': edges,
                }).encode())
            except sqlite3.Error as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
            return
        elif self.path == '/api/codegraph/staleness':
            # Compare the codegraph's recorded src_head_sha against
            # AetherSDR's live HEAD. Returns:
            #   src_head_sha    — recorded at extraction time
            #   current_head_sha — live `git rev-parse HEAD`
            #   commits_behind  — count between recorded..current
            #   is_stale        — commits_behind > 0
            #   extracted_at    — when the index was built
            # Best-effort: if either side is unavailable, returns
            # is_stale=false and a `reason` field so the UI knows
            # not to render a banner.
            import subprocess
            try:
                conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
                meta = dict(conn.execute('SELECT key, value FROM metadata').fetchall())
                conn.close()
            except sqlite3.Error as ex:
                self.send_response(503); self.end_headers()
                self.wfile.write(json.dumps({'error': str(ex)}).encode())
                return
            recorded = (meta.get('src_head_sha') or '').strip()
            src_path = '/Users/aetherclaude/workspace/AetherSDR'
            current = ''
            commits_behind = 0
            reason = ''
            if not recorded:
                reason = 'no src_head_sha in metadata (re-run extractor)'
            else:
                try:
                    out = subprocess.run(
                        ['git', '-C', src_path, 'rev-parse', 'HEAD'],
                        capture_output=True, text=True, timeout=5,
                    )
                    if out.returncode == 0:
                        current = out.stdout.strip()
                except Exception as e:
                    reason = f'git rev-parse failed: {e}'
            if recorded and current and recorded != current:
                try:
                    out = subprocess.run(
                        ['git', '-C', src_path, 'rev-list',
                         f'{recorded}..{current}', '--count'],
                        capture_output=True, text=True, timeout=5,
                    )
                    if out.returncode == 0:
                        commits_behind = int(out.stdout.strip() or '0')
                    else:
                        # Recorded SHA may be unreachable (force-pushed,
                        # branch swap). Surface as a stale signal but
                        # without an exact count.
                        commits_behind = -1
                        reason = 'recorded SHA unreachable from HEAD'
                except Exception as e:
                    reason = f'git rev-list failed: {e}'
            is_stale = (commits_behind != 0 and recorded and current)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'is_stale': bool(is_stale),
                'commits_behind': commits_behind,
                'src_head_sha': recorded,
                'current_head_sha': current,
                'extracted_at': meta.get('extracted_at', ''),
                'reason': reason,
            }).encode())
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
        elif self.path in ('/repo-context.md', '/repo-context.json'):
            # Cartographer repo-context pack (published to Shared/data by the
            # codegraph refresh job). md for humans/Claude, json for harnesses.
            fname = self.path.lstrip('/')
            ctype = 'application/json' if fname.endswith('.json') else 'text/markdown; charset=utf-8'
            try:
                with open(f'/Users/Shared/aetherclaude/data/{fname}', 'rb') as sf:
                    data = sf.read()
                self.send_response(200)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Disposition', f'inline; filename="{fname}"')
                self.end_headers()
                self.wfile.write(data)
            except:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith('/api/cartographer'):
            # Compact summary for the dashboard scanner row (HEAD sha + site
            # counts). Reads the pack json; graceful empty on absence.
            summary = {'available': False}
            try:
                with open('/Users/Shared/aetherclaude/data/repo-context.json') as sf:
                    pk = json.load(sf)
                l0 = pk.get('l0_repo_card', {})
                cats = (pk.get('l2_security', {}) or {}).get('categories', {})
                summary = {'available': True, 'head_sha': l0.get('head_sha', ''),
                           'generated_at': pk.get('generated_at', ''),
                           'call_tag_count': l0.get('call_tag_count', 0),
                           'open_cve_count': l0.get('open_cve_count', 0),
                           'subsystems': len(pk.get('l1_subsystems', [])),
                           'categories': {k: v.get('count', 0) for k, v in cats.items()}}
            except Exception:
                pass
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self._send_json(summary)
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
                page = page.replace('color:#5de3ff', 'color:#0a4a7a').replace('color:#5de3ff', 'color:#0a6aba').replace('color:#607080', 'color:#666').replace('color:#4090d0', 'color:#0a6aba').replace('color:#405060', 'color:#888')
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
        elif self.path.startswith('/api/eval'):
            # Galileo eval panel: per-flow aggregate (live-run pass rate +
            # latest experiment scores) plus recent run rows for deep-linking.
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT ts, trace_id, flow, ref, status, kind, galileo_trace_url, scores_json '
                    'FROM eval_results ORDER BY id DESC LIMIT 200'
                ).fetchall()
                conn.close()
                flows = {}
                recent = []
                for ts, trace_id, flow, ref, status, kind, url, scores_json in rows:
                    f = flows.setdefault(flow, {'flow': flow, 'runs': 0, 'ok': 0, 'fail': 0, 'scores': None, 'last_ts': None})
                    if kind == 'run':
                        f['runs'] += 1
                        f['ok' if status == 'ok' else 'fail'] += 1
                        if not f['last_ts']:
                            f['last_ts'] = ts
                    elif kind == 'experiment' and f['scores'] is None and scores_json:
                        # newest experiment for this flow wins (rows are DESC)
                        try:
                            f['scores'] = json.loads(scores_json)
                        except Exception:
                            pass
                    if len(recent) < 50:
                        recent.append({'ts': ts, 'trace_id': trace_id, 'flow': flow, 'ref': ref,
                                       'status': status, 'kind': kind, 'galileo_trace_url': url,
                                       'scores': json.loads(scores_json) if (kind == 'experiment' and scores_json) else None})
                for f in flows.values():
                    f['pass_rate'] = round(100.0 * f['ok'] / f['runs']) if f['runs'] else None
                # Stable flow order for the panel
                order = ['triage', 'implement', 'review', 'ci', 'duplicate', 'mention', 'other']
                flow_list = [flows[k] for k in order if k in flows] + [v for k, v in flows.items() if k not in order]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'flows': flow_list, 'recent': recent})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'flows': [], 'recent': [], 'error': str(ex)})
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
        elif self.path.startswith('/api/antares'):
            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    'SELECT scan_time, issue_number, cwe, verdict, file_path, rank, rationale, commands_used, trace_id '
                    'FROM detector_findings ORDER BY id DESC LIMIT 200'
                ).fetchall()
                total = conn.execute('SELECT COUNT(*) FROM detector_findings').fetchone()[0]
                runs = conn.execute("SELECT COUNT(DISTINCT scan_time) FROM detector_findings").fetchone()[0]
                conn.close()
                findings = [{'scan_time': r[0], 'issue': r[1], 'cwe': r[2], 'verdict': r[3],
                             'file': r[4], 'rank': r[5], 'rationale': r[6],
                             'commands_used': r[7], 'trace_id': r[8]} for r in rows]
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'findings': findings, 'total': total, 'runs': runs})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'findings': [], 'total': 0, 'runs': 0, 'error': str(ex)})
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
        elif self.path.startswith('/api/trends'):
            # Exec-view aggregates: hourly activity (24h), daily agent runs
            # (7d), posture history, eval + issue-action two-window rates.
            # All buckets zero-filled server-side; 60s module cache keeps the
            # GROUP BYs off the hot path. Poll cadence client-side is
            # REFRESH-interval * 20 (~60s).
            global _trends_cache
            nowt = time.time()
            if _trends_cache['ts'] > nowt - 60 and _trends_cache['data']:
                payload = _trends_cache['data']
            else:
                payload = {'activity': [], 'blocked_prev_24h': 0, 'daily_runs': [],
                           'posture': [], 'eval': {}, 'actions': {}, 'tokens_48h': [],
                           'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
                try:
                    conn = sqlite3.connect(EVENTS_DB, timeout=10)
                    # events + blocked over the last 24h in 15-minute buckets
                    # (96 points — high-res for the exec activity chart; the
                    # blocked tile sparkline consumes the same series)
                    got = {r[0]: (r[1], r[2]) for r in conn.execute(
                        "SELECT strftime('%Y-%m-%dT%H:',created_at) || "
                        "printf('%02d',(CAST(strftime('%M',created_at) AS INTEGER)/15)*15) || ':00Z', "
                        "COUNT(*), "
                        "SUM(CASE WHEN type='BLOCK' OR policy='domain-filter' THEN 1 ELSE 0 END) "
                        "FROM events WHERE created_at>=datetime('now','-24 hours') GROUP BY 1")}
                    base = int(nowt // 900) * 900
                    for i in range(95, -1, -1):
                        key = time.strftime('%Y-%m-%dT%H:%M:00Z', time.gmtime(base - i * 900))
                        ev, bl = got.get(key, (0, 0))
                        payload['activity'].append({'t': key, 'events': ev, 'blocked': bl or 0})
                    payload['blocked_prev_24h'] = conn.execute(
                        "SELECT COUNT(*) FROM events WHERE (type='BLOCK' OR policy='domain-filter') "
                        "AND created_at>=datetime('now','-48 hours') "
                        "AND created_at<datetime('now','-24 hours')").fetchone()[0]
                    # daily real agent runs (same definition as the trace picker:
                    # distinct trace_ids with claude-code events)
                    got_d = {r[0]: r[1] for r in conn.execute(
                        "SELECT date(created_at), COUNT(DISTINCT trace_id) FROM events "
                        "WHERE source='claude-code' AND trace_id IS NOT NULL "
                        "AND created_at>=datetime('now','-7 days') GROUP BY 1")}
                    for i in range(6, -1, -1):
                        d = time.strftime('%Y-%m-%d', time.gmtime(nowt - i * 86400))
                        payload['daily_runs'].append({'d': d, 'runs': got_d.get(d, 0)})
                    # Antares KPI: candidate vulnerable files localized (rows with
                    # a file_path from a 'vulnerable' verdict), 24h + 7-day series.
                    try:
                        def _acount(where):
                            return conn.execute(
                                "SELECT COUNT(*) FROM detector_findings WHERE "
                                "verdict='vulnerable' AND file_path IS NOT NULL AND "
                                + where).fetchone()[0]
                        got_a = {r[0]: r[1] for r in conn.execute(
                            "SELECT date(scan_time), COUNT(*) FROM detector_findings "
                            "WHERE verdict='vulnerable' AND file_path IS NOT NULL "
                            "AND scan_time>=datetime('now','-7 days') GROUP BY 1")}
                        a7 = [{'d': time.strftime('%Y-%m-%d', time.gmtime(nowt - i * 86400)),
                               'n': 0} for i in range(6, -1, -1)]
                        for e in a7:
                            e['n'] = got_a.get(e['d'], 0)
                        last_row = conn.execute(
                            "SELECT issue_number FROM detector_findings "
                            "WHERE verdict='vulnerable' AND file_path IS NOT NULL "
                            "ORDER BY id DESC LIMIT 1").fetchone()
                        payload['antares'] = {
                            'candidates_24h': _acount("scan_time>=datetime('now','-24 hours')"),
                            'candidates_prev_24h': _acount(
                                "scan_time>=datetime('now','-48 hours') "
                                "AND scan_time<datetime('now','-24 hours')"),
                            'runs_24h': conn.execute(
                                "SELECT COUNT(DISTINCT scan_time) FROM detector_findings "
                                "WHERE scan_time>=datetime('now','-24 hours')").fetchone()[0],
                            'last_issue': (last_row[0] if last_row else ''),
                            'cand_7d': a7,
                        }
                    except Exception:
                        payload['antares'] = {}
                    # posture history (≤96 points ≈ 24h at 300s cadence)
                    payload['posture'] = [{'t': r[0], 'score': r[1]} for r in conn.execute(
                        "SELECT ts, score FROM posture_snapshots "
                        "WHERE ts>=datetime('now','-1 day') ORDER BY ts ASC LIMIT 96")]
                    # hourly token usage, 48h (trace_tokens rows are ISO-T
                    # timestamps — cutoff passed in the same format so the
                    # lexical comparison is sound; idx_tt_ts range scan)
                    cutoff48 = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(nowt - 48 * 3600))
                    got_t = {r[0]: r[1:] for r in conn.execute(
                        "SELECT strftime('%Y-%m-%dT%H:00:00Z',timestamp), "
                        "SUM(input+output+cache_read+cache_create), SUM(input), "
                        "SUM(output), SUM(cache_read+cache_create) "
                        "FROM trace_tokens WHERE timestamp>=? GROUP BY 1", (cutoff48,))}
                    payload['tokens_48h'] = []
                    base48 = int(nowt // 3600) * 3600
                    for i in range(47, -1, -1):
                        key = time.strftime('%Y-%m-%dT%H:00:00Z', time.gmtime(base48 - i * 3600))
                        tot, inp, out, cache = got_t.get(key, (0, 0, 0, 0))
                        payload['tokens_48h'].append({'t': key, 'total': tot or 0, 'inp': inp or 0,
                                                      'out': out or 0, 'cache': cache or 0})
                    # CodeGuard run markers for the activity chart: cluster
                    # codeguard-source events within 5 minutes into 'runs';
                    # each carries its events (capped at 12) for the hover
                    # data card, plus the true total count.
                    try:
                        cg_rows = conn.execute(
                            "SELECT CAST(strftime('%s',created_at) AS INTEGER), created_at, "
                            "type, args, policy FROM events WHERE source='codeguard' "
                            "AND created_at>=datetime('now','-24 hours') "
                            "ORDER BY created_at ASC LIMIT 2000").fetchall()
                        cg_clusters = []
                        for ep, ca, ty, ar, po in cg_rows:
                            if ep is None:
                                continue
                            evd = {'t': (ca or '').replace(' ', 'T') + 'Z',
                                   'type': ty or '', 'args': (ar or '')[:90], 'policy': po or ''}
                            if cg_clusters and ep - cg_clusters[-1]['_end'] <= 300:
                                c = cg_clusters[-1]
                                c['_end'] = ep
                                c['count'] += 1
                                if len(c['events']) < 12:
                                    c['events'].append(evd)
                            else:
                                cg_clusters.append({'t': evd['t'], '_end': ep,
                                                    'count': 1, 'events': [evd]})
                        for c in cg_clusters:
                            c['t_end'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c.pop('_end')))
                        payload['codeguard_24h'] = cg_clusters[-50:]
                    except Exception:
                        payload['codeguard_24h'] = []
                    # Workflow markers: triage / implement / review / antares
                    # (detect) passes from issue_actions, each enriched with a
                    # first-line finding summary from the Antares + CodeGuard
                    # sweeps for that issue/PR. Titles are joined client-side
                    # from rings.issue_titles.
                    try:
                        # Antares summary per number (prefer a vulnerable verdict).
                        ant_sum = {}
                        for num, verdict, cand, rat in conn.execute(
                                "SELECT issue_number, verdict, file_path, rationale "
                                "FROM detector_findings "
                                "WHERE scan_time>=datetime('now','-24 hours') "
                                "ORDER BY id ASC"):
                            if num is None:
                                continue
                            k = str(num)
                            if verdict == 'vulnerable' and (rat or cand):
                                ant_sum[k] = ('vulnerable', (rat or '').strip()
                                              or ('candidate: ' + (cand or '')))
                            elif k not in ant_sum:
                                ant_sum[k] = (verdict or 'clean', '')
                        # CodeGuard PR summary per ref (first finding + count).
                        cg_sum = {}
                        for ref, sev, rid, ctitle in conn.execute(
                                "SELECT ref, severity, rule_id, title "
                                "FROM codeguard_findings "
                                "WHERE source='pr' AND ref IS NOT NULL "
                                "AND scan_time>=datetime('now','-24 hours') "
                                "ORDER BY id ASC"):
                            k = str(ref)
                            cg_sum.setdefault(k, []).append(
                                '[%s] %s %s' % (sev or '', rid or '', (ctitle or '')[:70]))
                        iac = sqlite3.connect(ISSUE_ACTIONS_DB, timeout=10)
                        wf = []
                        for num, action, state, outcome, detail, ca in iac.execute(
                                "SELECT issue_number, action, state, outcome, detail, created_at "
                                "FROM issue_actions "
                                "WHERE action IN ('triage','implement','review','detect') "
                                "AND outcome!='started' "
                                # Real ISO timestamps only — migrated rows carry a
                                # 'migration-…' created_at that lexically defeats the
                                # window filter and is an unparseable marker time.
                                "AND created_at GLOB '2[0-9][0-9][0-9]-*' "
                                "AND replace(created_at,'T',' ')>=datetime('now','-24 hours') "
                                "ORDER BY created_at ASC LIMIT 600"):
                            k = str(num)
                            mk = {'t': (ca or '').replace(' ', 'T') + 'Z',
                                  'kind': action, 'num': k,
                                  'state': state or '', 'outcome': outcome or ''}
                            av = ant_sum.get(k)
                            if av:
                                mk['antares_verdict'] = av[0]
                                if av[1]:
                                    mk['antares'] = av[1][:180]
                            cv = cg_sum.get(k)
                            if cv:
                                mk['codeguard'] = cv[0]
                                mk['codeguard_more'] = len(cv) - 1
                            if action == 'detect' and detail:
                                mk['detail'] = detail[:180]
                            wf.append(mk)
                        iac.close()
                        payload['workflow_24h'] = wf[-250:]
                    except Exception:
                        payload['workflow_24h'] = []
                    # eval pass rates, two 24h windows (ts is ISO w/ 'T' — normalize)
                    def _pr(where):
                        tot, ok = conn.execute(
                            "SELECT COUNT(*), SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) "
                            f"FROM eval_results WHERE kind='run' AND {where}").fetchone()
                        return (round(100.0 * (ok or 0) / tot) if tot else None), tot
                    cur, cur_n = _pr("replace(ts,'T',' ')>=datetime('now','-1 day')")
                    prev, _ = _pr("replace(ts,'T',' ')>=datetime('now','-2 days') "
                                  "AND replace(ts,'T',' ')<datetime('now','-1 day')")
                    # True eval QUALITY: mean of the newest experiment's scorer
                    # means per flow (stale-code recall, scope adherence, …
                    # from run-eval.sh / Galileo). Distinct from pass_rate,
                    # which is run-success (did claude exit 0). None until the
                    # scheduled eval job has produced scored experiments.
                    score_mean = None; score_flows = 0
                    try:
                        exp = conn.execute(
                            "SELECT flow, scores_json FROM eval_results WHERE id IN "
                            "(SELECT MAX(id) FROM eval_results WHERE kind='experiment' "
                            "AND scores_json IS NOT NULL GROUP BY flow)").fetchall()
                        fmeans = []
                        for _fl, sj in exp:
                            sc = json.loads(sj)
                            vals = [v for v in sc.values() if isinstance(v, (int, float))]
                            if vals:
                                fmeans.append(sum(vals) / len(vals))
                        if fmeans:
                            score_mean = round(100.0 * sum(fmeans) / len(fmeans))
                            score_flows = len(fmeans)
                    except Exception:
                        pass
                    # 48h quality series for the tile sparkline: one point per
                    # experiment BATCH (the daily 05:00 job posts all flows
                    # within seconds; a >10-min gap starts a new batch). Batch
                    # score = mean of its per-flow scorer means. Sparse by
                    # nature — experiments are daily, not hourly.
                    quality_48h = []
                    try:
                        exp_rows = conn.execute(
                            "SELECT CAST(strftime('%s',replace(ts,'T',' ')) AS INTEGER), scores_json "
                            "FROM eval_results WHERE kind='experiment' AND scores_json IS NOT NULL "
                            "AND replace(ts,'T',' ')>=datetime('now','-2 days') ORDER BY ts ASC").fetchall()
                        batches = []
                        for ep, sj in exp_rows:
                            sc = json.loads(sj)
                            vals = [v for v in sc.values() if isinstance(v, (int, float))]
                            if not vals or ep is None:
                                continue
                            fm = sum(vals) / len(vals)
                            if batches and ep - batches[-1]['end'] <= 600:
                                batches[-1]['means'].append(fm)
                                batches[-1]['end'] = ep
                            else:
                                batches.append({'start': ep, 'end': ep, 'means': [fm]})
                        quality_48h = [{'t': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(b['start'])),
                                        'score': round(100.0 * sum(b['means']) / len(b['means']))}
                                       for b in batches]
                    except Exception:
                        pass
                    # 7-day daily success-rate series for the Run success
                    # tile's trendline. Days with no runs carry pass_rate null
                    # (rendered as a gap, never faked). The modal's per-flow
                    # bars intentionally use the wider recent-200 history from
                    # /api/eval; this series supplies the time dimension.
                    got_s = {r[0]: (r[1], r[2] or 0) for r in conn.execute(
                        "SELECT date(replace(ts,'T',' ')), COUNT(*), "
                        "SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) "
                        "FROM eval_results WHERE kind='run' "
                        "AND replace(ts,'T',' ')>=datetime('now','-7 days') GROUP BY 1")}
                    success_7d = []
                    for i in range(6, -1, -1):
                        dkey = time.strftime('%Y-%m-%d', time.gmtime(nowt - i * 86400))
                        n, ok = got_s.get(dkey, (0, 0))
                        success_7d.append({'d': dkey, 'runs': n,
                                           'pass_rate': round(100.0 * ok / n) if n else None})
                    payload['eval'] = {'pass_rate_24h': cur, 'runs_24h': cur_n or 0,
                                       'pass_rate_prev_24h': prev,
                                       'success_7d': success_7d,
                                       'score_mean': score_mean, 'score_flows': score_flows,
                                       'quality_48h': quality_48h}
                    conn.close()
                except Exception as ex:
                    payload['error'] = str(ex)
                # issues/PRs handled — separate DB owned by the orchestrator
                try:
                    aconn = sqlite3.connect(ISSUE_ACTIONS_DB, timeout=5)
                    h24 = aconn.execute(
                        "SELECT COUNT(DISTINCT issue_number) FROM issue_actions "
                        "WHERE replace(created_at,'T',' ')>=datetime('now','-1 day')").fetchone()[0]
                    hprev = aconn.execute(
                        "SELECT COUNT(DISTINCT issue_number) FROM issue_actions "
                        "WHERE replace(created_at,'T',' ')>=datetime('now','-2 days') "
                        "AND replace(created_at,'T',' ')<datetime('now','-1 day')").fetchone()[0]
                    # 7-day daily series for the tile's trendline. Zero-fill:
                    # unlike a pass RATE, zero handled on a day is a real zero,
                    # not undefined.
                    got_h = {r[0]: r[1] for r in aconn.execute(
                        "SELECT date(replace(created_at,'T',' ')), COUNT(DISTINCT issue_number) "
                        "FROM issue_actions WHERE replace(created_at,'T',' ')>=datetime('now','-7 days') "
                        "GROUP BY 1")}
                    handled_7d = []
                    for i in range(6, -1, -1):
                        dkey = time.strftime('%Y-%m-%d', time.gmtime(nowt - i * 86400))
                        handled_7d.append({'d': dkey, 'handled': got_h.get(dkey, 0)})
                    aconn.close()
                    payload['actions'] = {'handled_24h': h24, 'handled_prev_24h': hprev,
                                          'handled_7d': handled_7d}
                except Exception:
                    payload['actions'] = {'handled_24h': None, 'handled_prev_24h': None,
                                          'handled_7d': []}
                _trends_cache = {'ts': nowt, 'data': payload}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self._send_json(payload)
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
                buf_total = len(memory_buffer)
                if not selected_types and not search:
                    # No-filter hot path: slice the last 1000 directly
                    # instead of materializing all ~10k events.
                    display_src = memory_buffer[-1000:]
                    filtered_count = buf_total
                else:
                    filtered = [e for e in memory_buffer if _matches(e)]
                    filtered_count = len(filtered)
                    display_src = filtered[-1000:]
            display = list(reversed(display_src))
            d = {'events': display, 'total': buf_total, 'filtered': filtered_count}
            d.update(build_stats_payload())
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
        elif self.path.startswith('/api/agent-walk-otel'):
            # Export one agent-walk trace as OTLP/JSON spans following the
            # AGNTCY observability schema (github.com/agntcy/observe), an
            # extension of the OTel GenAI semantic conventions. Lets any
            # OTel-compatible consumer (e.g. AGNTCY telemetry-hub backed by
            # ClickHouse) ingest AetherClaude runs without bespoke glue.
            # Point events are emitted as zero-duration child spans under a
            # synthetic root span covering the whole orchestrator run.
            import hashlib
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            tid = (params.get('trace_id', [''])[0] or '').strip()
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
            if not re.fullmatch(r'[0-9a-f]{32}', tid):
                self._send_json({'error': 'trace_id must be 32 lowercase hex chars'}); return

            def _nanos(ts):
                if not ts:
                    return 0
                s = ts.rstrip('Z')
                frac = 0.0
                if '.' in s:
                    s, f = s.split('.', 1)
                    try:
                        frac = float('0.' + f)
                    except ValueError:
                        frac = 0.0
                try:
                    dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
                except ValueError:
                    return 0
                return int((dt.timestamp() + frac) * 1e9)

            def _span_id(seed):
                return hashlib.sha256(seed.encode()).hexdigest()[:16]

            def _attr(k, v):
                if isinstance(v, bool):
                    return {'key': k, 'value': {'boolValue': v}}
                if isinstance(v, int):
                    return {'key': k, 'value': {'intValue': str(v)}}
                return {'key': k, 'value': {'stringValue': str(v)}}

            try:
                conn = sqlite3.connect(EVENTS_DB)
                rows = conn.execute(
                    "SELECT id, timestamp, type, binary_name, args, source "
                    "FROM events WHERE trace_id = ? ORDER BY id LIMIT 5000",
                    (tid,)).fetchall()
                conn.close()
            except Exception as ex:
                self._send_json({'error': str(ex)}); return
            if not rows:
                self._send_json({'resourceSpans': [], 'error': 'no events for trace_id'}); return

            ts_vals = [t for t in (_nanos(r[1]) for r in rows) if t]
            first_ts = min(ts_vals) if ts_vals else 0
            last_ts = max(ts_vals) if ts_vals else first_ts
            root_id = _span_id(tid + ':root')
            start_cond = next((r[4] for r in rows if r[5] == 'webhook' and r[4]), '')
            root_attrs = [
                _attr('gen_ai.operation.name', 'invoke_agent'),
                _attr('gen_ai.system', 'claude_code'),
                _attr('gen_ai.agent.name', 'AetherClaude'),
                _attr('gen_ai.agent.id', 'github.com/ten9876/aetherclaude'),
                _attr('gen_ai.agent.description',
                      'Autonomous GitHub issue-triage, PR-review and CI-explainer agent for AetherSDR'),
                _attr('gen_ai.request.model', 'claude-fable-5'),
                _attr('gen_ai.ioa.span_kind', 'agent'),
                _attr('gen_ai.ioa.collection_method', 'instrumentation'),
            ]
            if start_cond:
                root_attrs.append(_attr('gen_ai.ioa.start_condition', str(start_cond)[:200]))
            spans = [{
                'traceId': tid, 'spanId': root_id,
                'name': 'invoke_agent AetherClaude', 'kind': 1,
                'startTimeUnixNano': str(first_ts), 'endTimeUnixNano': str(last_ts),
                'attributes': root_attrs, 'status': {'code': 1},
            }]
            for rid, ts, _etype, binary, args, source in rows:
                t = _nanos(ts)
                binary = binary or ''
                if source == 'claude-code' and binary.startswith('claude:'):
                    op, ioa_kind = 'execute_tool', 'tool'
                    name = 'execute_tool ' + binary.split(':', 1)[1]
                elif source == 'webhook':
                    op, ioa_kind = 'receive_event', 'workflow'
                    name = 'webhook ' + binary.replace('github:', '')
                else:
                    op, ioa_kind = 'process', 'workflow'
                    name = ((source or 'event') + ' ' + binary).strip()
                attrs = [
                    _attr('gen_ai.operation.name', op),
                    _attr('gen_ai.system', 'claude_code'),
                    _attr('gen_ai.ioa.span_kind', ioa_kind),
                ]
                if op == 'execute_tool':
                    attrs.append(_attr('gen_ai.tool.name', binary.split(':', 1)[1]))
                if args:
                    attrs.append(_attr('aetherclaude.event.detail', str(args)[:300]))
                is_err = 'ERROR' in (args or '') or 'FATAL' in (args or '')
                if is_err:
                    attrs.append(_attr('error.type', 'agent_error'))
                spans.append({
                    'traceId': tid, 'spanId': _span_id(tid + ':' + str(rid)),
                    'parentSpanId': root_id, 'name': name[:120], 'kind': 1,
                    'startTimeUnixNano': str(t), 'endTimeUnixNano': str(t),
                    'attributes': attrs,
                    'status': {'code': 2 if is_err else 1},
                })
            self._send_json({'resourceSpans': [{
                'resource': {'attributes': [
                    _attr('service.name', 'aetherclaude'),
                    _attr('service.namespace', 'aethersdr'),
                    _attr('telemetry.sdk.name', 'aetherclaude-dashboard'),
                ]},
                'scopeSpans': [{
                    'scope': {'name': 'aetherclaude.agntcy.observe', 'version': '1.0.0'},
                    'spans': spans,
                }],
            }]})
        elif self.path.startswith('/api/agent-walk-traces'):
            # List recent traces for the picker dropdown. One row per
            # distinct trace_id, with summary (event count, time bounds,
            # webhook event type if available).
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            limit = min(int(params.get('limit', ['25'])[0]), 100)
            # ?include_skipped=1 keeps traces with no claude activity
            # in the result. Default hides them — skip-only traces
            # (dispatcher scanned, found nothing eligible, exited) have
            # no review/comment to replay. Diagnostic escape hatch
            # mirrors what we used to investigate trace 446b7880.
            include_skipped = params.get('include_skipped', ['0'])[0] == '1'
            _pk = (limit, include_skipped)
            _pnow = time.monotonic()
            with _picker_cache_lock:
                _phit = _picker_cache.get(_pk)
            if _phit is not None and _pnow - _phit[0] < PICKER_CACHE_TTL:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'traces': _phit[1]})
                return
            try:
                conn = sqlite3.connect(EVENTS_DB)
                # Over-fetch when filtering so we still return ~limit
                # rows after removing skip-only traces. 4x cap covers
                # typical bot ratio (most CI-passed runs do work).
                # Claude-activity filter lives in SQL so LIMIT applies to
                # real agent runs directly. Skip-only traces (a dispatcher
                # scanned and exited without invoking Claude) outnumber real
                # runs ~20:1, so the old "over-fetch limit*4, then filter in
                # Python against the in-memory set" returned only a couple of
                # rows once that backlog grew: it looked back just limit*4
                # traces, almost all skip-only. The subquery rides idx_source
                # (<15ms) and, unlike the 7-day in-memory warm-up set,
                # surfaces claude-active traces of any age. ?include_skipped=1
                # drops the filter to show every trace (diagnostic escape).
                claude_filter = ("" if include_skipped else
                    "AND trace_id IN (SELECT DISTINCT trace_id FROM events "
                    "WHERE source='claude-code' AND trace_id IS NOT NULL "
                    "AND LENGTH(trace_id) > 8) ")
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
                    + claude_filter +
                    "GROUP BY trace_id "
                    # Gating is on actual Claude tool use (>=1 claude-code
                    # event), pushed into the subquery above. Traces with only
                    # orchestrator/webhook/scan events (a dispatcher run that
                    # scanned and exited) are excluded; real runs of any size
                    # are kept. No event-count threshold — the old
                    # `event_count > 5000` gate hid every normal-sized run.
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
                with _picker_cache_lock:
                    _picker_cache[_pk] = (_pnow, traces)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({'traces': traces})
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'traces': [], 'error': str(ex)})
        elif self.path.startswith('/api/agent-walk-stream'):
            # Server-Sent-Events live tail. Event-driven, per Foundry-
            # security-spec Principle III ("Liveness By Heartbeat, Never
            # By Clock"). Replaces the prior /api/agent-walk-live wall-
            # clock polling endpoint.
            #
            # Frames:
            #   data: {"kind":"event","entry":{...}}\n\n      — new event for this trace
            #   data: {"kind":"related","trace_id":"...",...}\n\n — another trace started
            #   data: {"kind":"complete"}\n\n                  — stage-10 cleanup seen
            #   event: backlog-done\ndata: {"cursor":"..."}\n\n — initial backlog flushed
            #   : ping\n\n                                     — 15s liveness heartbeat
            #
            # Client should use EventSource; browser handles auto-reconnect.
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            trace_id = params.get('trace', [''])[0].strip()
            since = params.get('since', [''])[0].strip()
            if not trace_id:
                self.send_response(400); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'error': 'trace param required'})
                return
            # SSE headers — Cache-Control:no-cache + X-Accel-Buffering:no
            # ensure the cloudflared tunnel (and any proxy in front) flushes
            # each frame immediately rather than buffering for compression.
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Subscribe BEFORE the backlog query so we don't miss events
            # arriving during the window between backlog-done and our
            # first queue.get(). Backpressure: 500-entry bounded queue,
            # producers drop on Full rather than block.
            q = _queue_mod.Queue(maxsize=500)
            sub = {'trace_id': trace_id, 'q': q}
            with _agent_walk_sub_lock:
                _agent_walk_subscribers.append(sub)

            def _write_frame(payload_obj, event_name=None):
                """Write one SSE frame. Returns False if the socket is
                broken (caller should exit the drain loop)."""
                try:
                    if event_name:
                        self.wfile.write(f'event: {event_name}\n'.encode())
                    self.wfile.write(b'data: ')
                    self.wfile.write(json.dumps(payload_obj).encode())
                    self.wfile.write(b'\n\n')
                    self.wfile.flush()
                    return True
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return False

            max_ts = since
            try:
                # Backlog: emit any events for this trace > since (same
                # classifier as the SSE feed so dots line up identically).
                conn = sqlite3.connect(EVENTS_DB)
                if since:
                    rows = conn.execute(
                        "SELECT timestamp, type, uid, binary_name, args, "
                        "       policy, is_agent, source, trace_id "
                        "FROM events WHERE trace_id = ? AND timestamp > ? "
                        "ORDER BY timestamp ASC, id ASC",
                        (trace_id, since)).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT timestamp, type, uid, binary_name, args, "
                        "       policy, is_agent, source, trace_id "
                        "FROM events WHERE trace_id = ? "
                        "ORDER BY timestamp ASC, id ASC",
                        (trace_id,)).fetchall()
                # Quick activity check for the trace
                trace_last_row = conn.execute(
                    "SELECT MAX(timestamp) FROM events WHERE trace_id = ?",
                    (trace_id,)).fetchone()
                conn.close()
                trace_last_ts = (trace_last_row[0] if trace_last_row else None) or ''
                saw_cleanup = False
                for r in rows:
                    ts, typ, uid, binary, args, policy, is_agent, source, tid = r
                    stage = _classify_agent_walk_stage(typ, source, args, binary)
                    if stage == 0:
                        continue
                    if stage == 10:
                        saw_cleanup = True
                    entry = {
                        'time': ts, 'type': typ, 'uid': uid, 'binary': binary,
                        'args': args, 'policy': policy,
                        'is_agent': bool(is_agent), 'source': source,
                        'trace_id': tid, 'stage': stage,
                    }
                    if not _write_frame({'kind': 'event', 'entry': entry}):
                        return  # client gone; finally-block cleans up
                    max_ts = ts
                # Mark end of backlog
                if not _write_frame({'cursor': max_ts}, event_name='backlog-done'):
                    return
                # If trace already finished, send complete and keep heart-
                # beating briefly in case the client wants to confirm
                # rather than tearing down immediately.
                if saw_cleanup:
                    _write_frame({}, event_name='complete')

                # Drain queue indefinitely. 15s heartbeats keep the
                # connection (and any intermediate proxy) alive without
                # being a wall-clock data refresh — frames carry payload
                # only when something actually happened. This is the
                # heartbeat-driven liveness the Foundry spec calls for.
                last_heartbeat = time.time()
                while True:
                    try:
                        msg = q.get(timeout=15)
                    except _queue_mod.Empty:
                        # Heartbeat as SSE comment line; no data event.
                        try:
                            self.wfile.write(b': ping\n\n')
                            self.wfile.flush()
                            last_heartbeat = time.time()
                            continue
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            return
                    # Dedupe against backlog by timestamp — anything
                    # at-or-before max_ts was already sent.
                    entry = msg.get('entry') or {}
                    ets = entry.get('time') or ''
                    if msg.get('kind') == 'event' and ets and ets <= max_ts:
                        continue
                    if not _write_frame(msg):
                        return
                    if ets:
                        max_ts = ets
                    last_heartbeat = time.time()
                    # If the event we just sent was stage-10, signal
                    # completion so the client can stop the EventSource.
                    if msg.get('kind') == 'event' and (entry.get('stage') == 10):
                        _write_frame({}, event_name='complete')
            finally:
                with _agent_walk_sub_lock:
                    try:
                        _agent_walk_subscribers.remove(sub)
                    except ValueError:
                        pass
            return
        elif self.path.startswith('/api/agent-walk-live'):
            # Live-tail endpoint for Agent Walk. Client polls every ~2s
            # with the timestamp of the last event it has seen. Server
            # returns:
            #   - new events for the trace since `since` (classified)
            #   - cursor (timestamp of the latest event — pass back next poll)
            #   - active (false once stage-10 cleanup event seen OR > 60s silent)
            #   - related (OTHER traces that started in the same window —
            #     drives the "new trace started" banner in the UI)
            # Cheap: indexed query, ~ms per request. See project memory
            # project_agent_walk_demo for the demo flow it enables.
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(self.path).query)
            trace_id = params.get('trace', [''])[0].strip()
            since = params.get('since', [''])[0].strip()
            if not trace_id:
                self.send_response(400); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'error': 'trace param required'})
                return
            try:
                conn = sqlite3.connect(EVENTS_DB)
                # New events for this trace since cursor (exclusive).
                # When `since` is empty, returns all events for the trace
                # (initial load fallback — but normally /api/agent-walk
                # has been called first for the backlog).
                if since:
                    rows = conn.execute(
                        "SELECT timestamp, type, uid, binary_name, args, policy, "
                        "       is_agent, source, trace_id "
                        "FROM events WHERE trace_id = ? AND timestamp > ? "
                        "ORDER BY timestamp ASC, id ASC",
                        (trace_id, since)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT timestamp, type, uid, binary_name, args, policy, "
                        "       is_agent, source, trace_id "
                        "FROM events WHERE trace_id = ? "
                        "ORDER BY timestamp ASC, id ASC",
                        (trace_id,)
                    ).fetchall()
                all_events = []
                for r in rows:
                    ts, typ, uid, binary, args, policy, is_agent, source, tid = r
                    all_events.append({
                        'time': ts, 'type': typ, 'uid': uid, 'binary': binary,
                        'args': args, 'policy': policy,
                        'is_agent': bool(is_agent), 'source': source,
                        'trace_id': tid,
                        'stage': _classify_agent_walk_stage(typ, source, args, binary),
                    })
                events = [e for e in all_events if e['stage'] > 0]
                # Cursor: latest timestamp we've now sent. Client passes
                # this back as `since` next poll.
                cursor = events[-1]['time'] if events else since
                # Activity check: trace is still in-flight if its latest
                # event is < 60s old AND no stage-10 cleanup event yet.
                # Use the WHOLE trace's last event, not just this batch —
                # quick query against the index.
                trace_last_row = conn.execute(
                    "SELECT MAX(timestamp) FROM events WHERE trace_id = ?",
                    (trace_id,)).fetchone()
                trace_last_ts = (trace_last_row[0] if trace_last_row else None) or ''
                has_cleanup = False
                for e in all_events:
                    if e['stage'] == 10:
                        has_cleanup = True
                        break
                active = True
                if has_cleanup:
                    active = False
                elif trace_last_ts:
                    try:
                        last_dt = datetime.strptime(trace_last_ts[:19],
                            '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - last_dt).total_seconds() > 60:
                            active = False
                    except (ValueError, TypeError):
                        pass
                # Related traces: other traces that have a WEBHOOK or
                # agent-run START event with timestamp > since. Cheap
                # (indexed on timestamp) and limited to 10 for safety.
                related = []
                if since:
                    rel_rows = conn.execute(
                        "SELECT trace_id, MIN(timestamp) AS first_ts, COUNT(*) AS c "
                        "FROM events "
                        "WHERE trace_id IS NOT NULL "
                        "  AND trace_id != ? "
                        "  AND LENGTH(trace_id) > 8 "
                        "  AND timestamp > ? "
                        "  AND (type = 'WEBHOOK' "
                        "       OR (source = 'skill-dispatch' "
                        "           AND binary_name = 'skill:agent-run' "
                        "           AND args = 'starting')) "
                        "GROUP BY trace_id "
                        "ORDER BY first_ts ASC LIMIT 10",
                        (trace_id, since)
                    ).fetchall()
                    for (tid, first_ts, _c) in rel_rows:
                        # Cheap event-count + 1-line summary for the banner.
                        summary_row = conn.execute(
                            "SELECT COUNT(*), "
                            "       (SELECT args FROM events "
                            "         WHERE trace_id=? AND type='WEBHOOK' "
                            "         ORDER BY id ASC LIMIT 1) "
                            "FROM events WHERE trace_id=?",
                            (tid, tid)).fetchone()
                        ec = summary_row[0] if summary_row else 0
                        summary = (summary_row[1] if summary_row else '') or ''
                        related.append({
                            'trace_id': tid,
                            'first_ts': first_ts,
                            'event_count': ec,
                            'summary': summary[:120],
                        })
                conn.close()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self._send_json({
                    'trace_id': trace_id,
                    'events': events,
                    'cursor': cursor,
                    'active': active,
                    'related': related,
                })
            except Exception as ex:
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                self._send_json({'events': [], 'related': [], 'active': False, 'error': str(ex)})
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

            classify_stage = _classify_agent_walk_stage

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
                # Attach blast-radius enrichment to TOOL events. The
                # codegraph blast-radius hook fires immediately before
                # each Edit/Write tool call and emits a row with
                # source='codegraph', binary='codegraph:blast', args=
                # JSON-encoded summary. We pair each blast row with
                # the next claude:Edit/Write/MultiEdit event whose
                # args (basename) matches, then drop the blast row
                # from the swimlane (it's now metadata on the dot).
                pending_blast = []
                for e in all_events:
                    if e['source'] == 'codegraph' and (e['binary'] or '').startswith('codegraph:blast'):
                        try:
                            pending_blast.append(json.loads(e['args']))
                        except (json.JSONDecodeError, TypeError):
                            pass
                if pending_blast:
                    edit_binaries = ('claude:Edit', 'claude:Write',
                                     'claude:MultiEdit', 'claude:NotebookEdit')
                    for ev in events:
                        if not pending_blast:
                            break
                        binary = ev.get('binary') or ''
                        if not binary.startswith(edit_binaries):
                            continue
                        ev_args = (ev.get('args') or '').strip()
                        # Match blast-row's file basename to the tool
                        # event's basename. tail_sessions stores only
                        # basename in args, the blast row's `file`
                        # field may be a full path.
                        for i, blast in enumerate(pending_blast):
                            blast_file = (blast.get('file') or '')
                            blast_basename = blast_file.rsplit('/', 1)[-1]
                            if blast_basename and blast_basename == ev_args:
                                ev['blast_radius'] = blast
                                pending_blast.pop(i)
                                break
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                # Per-trace token timeline from trace_tokens (recorded at
                # ingestion, keyed by the same trace_id as the events).
                # Powers the playback token counter (count + cost).
                _tl = []
                try:
                    _tc = sqlite3.connect(EVENTS_DB)
                    for _r in _tc.execute(
                        'SELECT timestamp, input, output, cache_read, cache_create, model '
                        'FROM trace_tokens WHERE trace_id=? ORDER BY timestamp ASC',
                        (trace_id,)):
                        _tl.append({'time': _r[0], 'input': _r[1], 'output': _r[2],
                                    'cache_read': _r[3], 'cache_create': _r[4],
                                    'model': _r[5],
                                    'cost': _turn_cost(_r[5], _r[1], _r[2], _r[3], _r[4])})
                    _tc.close()
                except Exception as _e:
                    _log_exc('agent_walk.token_timeline', _e)
                _ti = sum(e['input'] for e in _tl)
                _to = sum(e['output'] for e in _tl)
                _tcr = sum(e['cache_read'] for e in _tl)
                _tcc = sum(e['cache_create'] for e in _tl)
                _ttotal = {'input': _ti, 'output': _to, 'cache_read': _tcr,
                           'cache_create': _tcc,
                           'cost': round(sum(e['cost'] for e in _tl), 4)}
                self._send_json({
                    'trace_id': trace_id,
                    'events': events,
                    'first_ts': events[0]['time'] if events else None,
                    'last_ts': events[-1]['time'] if events else None,
                    'event_count': len(events),
                    'background_dropped': dropped,
                    'token_timeline': _tl,
                    'token_total': _ttotal,
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
        elif self.path == '/api/eval-ingest':
            # Eval records from the agent (kind='run', we forward to Galileo) or
            # from bin/run-eval.sh (kind='experiment', already logged to Galileo,
            # we just persist the aggregate for the dashboard panel). HMAC like
            # /api/ingest. Fail-open: never let eval logging 500 a caller.
            import hmac, hashlib
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            sig_header = self.headers.get('X-Ingest-Signature', '')
            # Strict: when a secret is configured, a valid signature is REQUIRED
            # (an absent signature is rejected, unlike /api/ingest's looser check).
            # The endpoint is reachable on 0.0.0.0:8080; the legit caller
            # (galileo-log-run.py / run-eval.sh) always signs.
            if WEBHOOK_SECRET:
                expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
                if not sig_header or not hmac.compare_digest(sig_header, expected):
                    self.send_response(401); self.end_headers(); self.wfile.write(b'Invalid signature'); return
            try:
                entry = json.loads(body)
                kind = entry.get('kind', 'run')
                ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                galileo_url = entry.get('galileo_trace_url')
                if kind == 'run':
                    galileo_url = galileo_forward(entry)
                scores_json = json.dumps(entry.get('scores')) if entry.get('scores') is not None else None
                conn = sqlite3.connect(EVENTS_DB, timeout=30)
                conn.execute(
                    'INSERT INTO eval_results (ts, trace_id, flow, ref, status, kind, galileo_trace_url, scores_json) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (ts, entry.get('trace_id', ''), entry.get('flow', 'other'), str(entry.get('ref', '')),
                     entry.get('status', 'ok'), kind, galileo_url, scores_json))
                conn.commit(); conn.close()
                self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps({'accepted': 1, 'galileo_trace_url': galileo_url}).encode())
            except Exception as e:
                # Persisting/forwarding failed — log and ack so the agent is
                # never blocked by eval plumbing.
                print(f'eval-ingest error: {e}', file=sys.stderr)
                self.send_response(200); self.end_headers()
                self.wfile.write(json.dumps({'accepted': 0, 'error': str(e)}).encode())
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
            elif event_type in ('check_run', 'workflow_run'):
                # Both payloads carry a pull_requests[] array of PR refs
                # for runs triggered by PR pushes. First entry is the
                # triggering PR. Scoping the lock_key to that PR means
                # CI completions on different PRs don't debounce each
                # other through the 60s global window. Runs not tied
                # to a PR (e.g., main-branch push) fall through to
                # lock_key='global', same as before.
                root = payload.get(event_type, {}) or {}
                prs = root.get('pull_requests') or []
                if prs and isinstance(prs, list) and prs[0].get('number'):
                    lock_key = f'pr-{prs[0]["number"]}'
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
            # shouldn't bounce the bot. Three exceptions:
            #   1. @mentions in comments (is_mention)
            #   2. `aetherclaude-eligible` label add — the explicit
            #      authorization signal for implement-fix
            #   3. NEWLY OPENED issues — even when the maintainer is
            #      the sender (e.g. filed via AetherSDR's AI-assisted
            #      bug-report tool, which authenticates as ten9876),
            #      we still want triage to run.
            maint_label = (payload.get('label') or {}).get('name', '')
            maint_eligibility_signal = (
                event_type == 'issues' and action == 'labeled'
                and maint_label == 'aetherclaude-eligible'
            )
            maint_issue_opened = (
                event_type == 'issues' and action == 'opened'
            )
            # Maintainer-opened PRs (and pushes to them) should also
            # reach the orchestrator so the review skill can run on
            # them — same code path community contributors get.
            maint_pr_actionable = (
                event_type == 'pull_request'
                and action in ('opened', 'synchronize', 'reopened', 'ready_for_review')
            )
            # CI/system events (check_run, workflow_run) are NOT interactive
            # maintainer activity — a CI failure on the maintainer's own PR is
            # exactly when explain-ci should fire (and review-pr on success).
            # Without this exemption, every CI completion triggered by ten9876's
            # pushes was dropped here before reaching the CI-conclusion filter,
            # silently disabling the CI-failure explainer for the operator's PRs.
            maint_ci_event = event_type in ('check_run', 'workflow_run')
            if (sender == 'ten9876' and not is_mention
                    and not maint_eligibility_signal
                    and not maint_issue_opened
                    and not maint_pr_actionable
                    and not maint_ci_event):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (maintainer)'); return
            # Skip irrelevant actions
            if event_type == 'issues' and action not in ('opened', 'edited', 'labeled', 'reopened', 'closed'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'issue_comment' and action != 'created':
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            if event_type == 'pull_request' and action not in ('opened', 'synchronize', 'reopened', 'closed'):
                self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
            # CI events: react on completion, both pass and fail.
            #   - failure → explain-ci posts a CI-failure explainer
            #   - success → review-pr posts a review (PR is now ripe)
            # In-progress / requested events are noise (no actionable
            # state change). Other conclusions (cancelled, skipped,
            # timed_out, neutral, stale, action_required) are dropped —
            # neither skill has a meaningful response to them.
            # Pre-fix this was "drop unless conclusion=failure", which
            # silently swallowed every successful CI completion and
            # prevented review-pr from ever firing on the CI path.
            # See trace 54a69a50 (PR #3131 green CI → no review).
            if event_type in ('check_run', 'workflow_run'):
                if action != 'completed':
                    self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (action)'); return
                conclusion_root = payload.get(event_type, {}) or {}
                if conclusion_root.get('conclusion') not in ('failure', 'success'):
                    self.send_response(200); self.end_headers(); self.wfile.write(b'Skipped (CI inconclusive)'); return
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
                except Exception as _e: _log_exc('webhook.mention_write', _e)
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
            except Exception as _e: _log_exc('webhook.trigger_write', _e)
            # Skip when adopted_running — the running orchestrator for
            # this same lock_key already has its trace_id, no need to
            # write or spawn again.
            if not adopted_running:
                try:
                    with open(f'/Users/aetherclaude/state/trace-id.{lock_key}', 'w') as tf:
                        tf.write(trace_id)
                except Exception as _e: _log_exc('webhook.traceid_write', _e)
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
    threading.Thread(target=session_archiver,daemon=True).start()
    threading.Thread(target=session_token_reconciler,daemon=True).start()
    threading.Thread(target=db_trace_backfill_correlator,daemon=True).start()
    threading.Thread(target=track_active_trace,daemon=True).start()
    threading.Thread(target=warmup_claude_active_traces,daemon=True).start()
    s=ThreadingHTTPServer((a.bind,a.port),H);print(f"Dashboard at http://{a.bind}:{a.port}")
    try:s.serve_forever()
    except KeyboardInterrupt:print("\nShutdown")

if __name__=='__main__':main()
