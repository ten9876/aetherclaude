#!/usr/bin/env python3
"""Re-ingest orchestrator.log skill/scan events for a period not ingested live.

tail_orchestrator_skills is the sole producer of source='skill-dispatch',
which _classify_agent_walk_stage maps to the Agent Walk's Orchestrator and
Skill stages, plus the orchestrator-log path into the Scanning stage. Those
stages are populated only as that follower reads the log, so a period the
follower did not read has no rows for them. The lines themselves remain in
the log; this replays them through /api/ingest, the same endpoint
eslogger-bridge.py and galileo-log-run.py post to, so they land via
append_event as live ingest would have written them.

Fidelity
--------
Parsing and event shape come from tetragon-dashboard.py itself
(_parse_orchestrator_line, _orchestrator_event_fields) rather than being
reimplemented here. events.db is an audit record, so a replayed row must be
the row the live path would have written.

Two things differ from the live follower, both deliberate:

  1. Timestamp. The follower stamps now_utc_iso() because it is tailing in
     real time. A replay must use the line's own timestamp, which
     run-agent.sh writes in LOCAL time with no zone marker, so we convert
     to UTC here.

  2. Trace resolution. The follower resolves the [xxxxxxxx] prefix via
     _trace_prefix_to_full, populated by /webhook in the dashboard process.
     A separate process cannot see that dict, and
     db_trace_backfill_correlator expands bare prefixes only within
     _TRACE_BACKFILL_LOOKBACK_SECS. So we rebuild the map from events.db,
     whose trace_ids are full UUIDs, and fall back to the bare prefix when a
     trace is not found — the same value the follower stores on a miss.

Scope note: events.db is a FIFO ring capped at DB_MAX_BYTES. Replaying a
period older than the oldest retained row produces events whose sibling rows
are already pruned, so prefer a range inside the retained window — the
--dry-run summary reports how many trace_ids resolve.

Usage
-----
  # Summarize what would be sent; writes nothing, needs no secret:
  replay-orchestrator-log.py --dry-run --since 2026-09-20T11:08:37

  # Ingest (needs WEBHOOK_SECRET; run as the account that can read it):
  replay-orchestrator-log.py --since 2026-09-20T11:08:37 --until 2026-09-21T18:00:00

--since/--until are LOCAL time, matching the log's own stamps. Both bounds
are half-open [since, until) so consecutive runs cannot double-count a line.
"""
import argparse
import gzip
import hashlib
import hmac
import importlib.util
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime

DEFAULT_LOG = '/Users/aetherclaude/logs/orchestrator.log'
DEFAULT_DASHBOARD = 'http://localhost:8080'
ENV_PATHS = ('/Users/aetherclaude/.env', os.path.expanduser('~/.env'))

_HERE = os.path.dirname(os.path.abspath(__file__))
_DASH_PATH = os.path.join(_HERE, 'tetragon-dashboard.py')

# Leading "<ISO-local> [<8-hex>] ..." stamp written by run-agent.sh's log().
_TS_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\b')
_PREFIX_RE = re.compile(r'\[([0-9a-f]{8})\]')


def load_dashboard():
    """Import tetragon-dashboard.py for its parser. main() is __main__-guarded,
    so importing starts no threads and opens no sockets."""
    spec = importlib.util.spec_from_file_location('tetragon_dashboard', _DASH_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def local_to_utc_iso(stamp):
    """'2026-09-19T03:32:33' (local, no zone) -> '2026-09-19T10:32:33.000Z'.

    time.mktime applies the zone the log was written in, including the DST
    offset in effect on that date rather than today's — which matters for a
    replay spanning a transition.
    """
    tm = time.strptime(stamp, '%Y-%m-%dT%H:%M:%S')
    epoch = time.mktime(tm)  # interprets tm as local wall-clock
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(epoch)) + '.000Z'


def parse_bound(value):
    if not value:
        return None
    return time.mktime(time.strptime(value, '%Y-%m-%dT%H:%M:%S'))


def open_log(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', errors='replace')
    return open(path, 'r', errors='replace')


_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def fetch_trace_map_db(db_path, since_iso):
    """Build {prefix: full trace_id} from events.db — the authoritative source.

    Opened with immutable=1 so the read needs no sidecar file and takes no
    lock; the DB is journal_mode=delete, so there is no WAL to miss. Because
    that mode reads without coordinating with a concurrent writer, every id
    is shape-checked and any prefix claimed by two different UUIDs is left
    unresolved rather than guessed: filing an event under the wrong run is
    worse than leaving it on the bare prefix for the correlator.

    Same resolution db_trace_backfill_correlator's Pass 1 performs, over the
    range being replayed rather than its rolling lookback.
    """
    import sqlite3
    conn = sqlite3.connect(f'file:{db_path}?immutable=1', uri=True)
    try:
        rows = conn.execute(
            'SELECT DISTINCT trace_id FROM events '
            'WHERE trace_id IS NOT NULL AND LENGTH(trace_id) > 8 '
            'AND timestamp >= ?', (since_iso,)).fetchall()
    finally:
        conn.close()
    claims = {}
    for (tid,) in rows:
        if not tid or not _UUID_RE.match(tid):
            continue
        claims.setdefault(tid[:8], set()).add(tid)
    out, collisions = {}, 0
    for prefix, full in claims.items():
        if len(full) == 1:
            out[prefix] = next(iter(full))
        else:
            collisions += 1
    if collisions:
        print(f'  WARNING: {collisions} prefix(es) claimed by multiple trace_ids; '
              f'left unresolved', file=sys.stderr)
    return out


def fetch_trace_map(dashboard, limit):
    """Build {8-char prefix: full trace_id} from the walk-traces picker.

    Read-only. A trace absent here (skip-only runs carry no claude-code
    activity, so the picker filters them out) keeps its bare prefix, which is
    what the live follower would have stored in the same situation.
    """
    url = f'{dashboard}/api/agent-walk-traces?limit={limit}'
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f'  WARNING: could not fetch trace map ({e}); '
              f'falling back to bare 8-char prefixes', file=sys.stderr)
        return {}
    rows = data if isinstance(data, list) else data.get('traces', [])
    out = {}
    for row in rows:
        tid = (row or {}).get('trace_id') or ''
        if len(tid) > 8:
            out.setdefault(tid[:8], tid)
    return out


def build_events(td, path, since, until, trace_map):
    """Parse the log into ingest-ready entries, using the dashboard's own rules."""
    events = []
    unresolved = set()
    scanned = 0
    with open_log(path) as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            scanned += 1

            m_ts = _TS_RE.match(line)
            if not m_ts:
                continue  # no usable timestamp; a replay can't place it
            epoch = time.mktime(time.strptime(m_ts.group(1), '%Y-%m-%dT%H:%M:%S'))
            if since is not None and epoch < since:
                continue
            if until is not None and epoch >= until:
                continue

            skill, detail = td._parse_orchestrator_line(line)
            if not skill:
                continue

            ev_type, ev_binary, ev_source = td._orchestrator_event_fields(skill)

            trace_for_entry = None
            m_prefix = _PREFIX_RE.search(line)
            if m_prefix:
                short = m_prefix.group(1)
                trace_for_entry = trace_map.get(short, short)
                if short not in trace_map:
                    unresolved.add(short)

            events.append({
                'time': local_to_utc_iso(m_ts.group(1)),
                'type': ev_type,
                'uid': 965,
                'binary': ev_binary,
                'args': detail,
                'policy': '',
                'is_agent': True,
                'source': ev_source,
                'trace_id': trace_for_entry,
            })
    return events, scanned, unresolved


def load_secret():
    secret = os.environ.get('WEBHOOK_SECRET', '')
    if secret:
        return secret
    for env_path in ENV_PATHS:
        if not os.path.exists(env_path):
            continue
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('WEBHOOK_SECRET='):
                        return line.split('=', 1)[1].strip().strip('"\'')
        except OSError:
            continue
    return ''


def post_batch(dashboard, events, secret):
    body = json.dumps({'events': events}).encode()
    headers = {'Content-Type': 'application/json'}
    if secret:
        headers['X-Ingest-Signature'] = hmac.new(
            secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(f'{dashboard}/api/ingest', data=body,
                                 method='POST', headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--log', default=DEFAULT_LOG, help='orchestrator.log (.gz ok)')
    ap.add_argument('--dashboard', default=DEFAULT_DASHBOARD)
    ap.add_argument('--since', help='local ISO, inclusive (YYYY-MM-DDTHH:MM:SS)')
    ap.add_argument('--until', help='local ISO, exclusive (YYYY-MM-DDTHH:MM:SS)')
    ap.add_argument('--batch', type=int, default=200, help='events per POST')
    ap.add_argument('--events-db', default='/Users/aetherclaude/data/events.db',
                    help='read read-only to resolve trace prefixes (authoritative)')
    ap.add_argument('--trace-limit', type=int, default=500,
                    help='how many traces to pull for prefix resolution')
    ap.add_argument('--dry-run', action='store_true',
                    help='parse and summarize; write nothing')
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print(f'ERROR: no such log: {args.log}', file=sys.stderr)
        return 2

    since, until = parse_bound(args.since), parse_bound(args.until)
    td = load_dashboard()

    print(f'Log:   {args.log}')
    print(f'Range: {args.since or "(start)"} .. {args.until or "(end)"} (local)')

    # Resolved on a dry run too: prefix resolution is the part most likely to
    # be wrong, so it should be visible before anything is written.
    #
    # The DB is authoritative and covers the whole gap. The picker is only a
    # fallback: it caps at 100 traces with no pagination, which over a
    # multi-day gap resolves a few recent hours and leaves the rest bare.
    trace_map = {}
    if os.path.exists(args.events_db):
        db_since = (args.since or '2026-01-01T00:00:00')[:10]
        trace_map = fetch_trace_map_db(args.events_db, db_since)
        print(f'Prefix map from {args.events_db}: {len(trace_map)} traces')
    if not trace_map:
        trace_map = fetch_trace_map(args.dashboard, args.trace_limit)
        print(f'Prefix map from picker API (fallback): {len(trace_map)} traces')

    events, scanned, unresolved = build_events(td, args.log, since, until, trace_map)

    by_source = {}
    by_stage = {}
    for e in events:
        by_source[e['source']] = by_source.get(e['source'], 0) + 1
        st = td._classify_agent_walk_stage(e['type'], e['source'], e['args'], e['binary'])
        by_stage[st] = by_stage.get(st, 0) + 1

    print(f'\nScanned {scanned} lines -> {len(events)} events')
    print('  by source:')
    for k in sorted(by_source):
        print(f'    {by_source[k]:6d}  {k}')
    print('  by walk stage:')
    for k in sorted(by_stage):
        label = {2: 'Orchestrator', 3: 'Skill', 4: 'Scanning', 5: 'Claude Code'}.get(k, '')
        print(f'    {by_stage[k]:6d}  stage {k} {label}')
    resolved = sum(1 for e in events if e['trace_id'] and len(e['trace_id']) > 8)
    print(f'  trace_ids: {resolved} full, '
          f'{sum(1 for e in events if e["trace_id"] and len(e["trace_id"]) == 8)} bare prefix, '
          f'{sum(1 for e in events if not e["trace_id"])} none')
    if unresolved:
        print(f'  unresolved prefixes ({len(unresolved)}): '
              f'{", ".join(sorted(unresolved)[:8])}'
              f'{" ..." if len(unresolved) > 8 else ""}')

    if events:
        print('\n  first: %s  %s  %s' % (events[0]['time'], events[0]['binary'],
                                         events[0]['args'][:52]))
        print('  last:  %s  %s  %s' % (events[-1]['time'], events[-1]['binary'],
                                       events[-1]['args'][:52]))

    if args.dry_run:
        print('\nDRY RUN — nothing sent.')
        return 0
    if not events:
        print('\nNothing to replay.')
        return 0

    secret = load_secret()
    if not secret:
        print('\nERROR: WEBHOOK_SECRET not found in the environment or '
              f'{ENV_PATHS[0]}.\n       /api/ingest rejects unsigned posts; '
              'run as the account that can read it.', file=sys.stderr)
        return 3

    sent = 0
    for i in range(0, len(events), args.batch):
        chunk = events[i:i + args.batch]
        try:
            res = post_batch(args.dashboard, chunk, secret)
        except Exception as e:
            print(f'\nERROR: batch at offset {i} failed: {e}', file=sys.stderr)
            print(f'       {sent} event(s) already ingested; re-run with '
                  f'--since set past the last one to resume.', file=sys.stderr)
            return 4
        sent += res.get('accepted', len(chunk))
        print(f'  ingested {sent}/{len(events)}', end='\r', flush=True)
    print(f'\nIngested {sent} event(s).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
