"""Unit tests for bin/replay-orchestrator-log.py.

Run: python3 tests/test_replay_orchestrator.py
Exits non-zero on any failure with a one-line summary per case.

This tool writes into events.db, which is an audit record, so the bar is
that a replayed row is indistinguishable from the row live ingest would
have written. Two properties carry that:

  - Parsing is not reimplemented. The tool calls the dashboard's own
    _parse_orchestrator_line / _orchestrator_event_fields, so these tests
    also pin the extraction refactor that made them shared.
  - Everything the tool does add — local->UTC timestamps, half-open range
    bounds, prefix resolution — is verified here.

Covers:
  - local_to_utc_iso converts using the zone in effect on that DATE (DST)
  - --since/--until are half-open, so consecutive runs can't double-count
  - build_events reproduces the follower's type/binary/source mapping
  - scanner lines become SCAN/<scanner> events, not skill-dispatch
  - trace prefixes resolve from the map; unknown prefixes stay bare
  - fetch_trace_map_db drops a prefix claimed by two trace_ids
  - replayed events classify into walk stages 2/3/4
"""
import importlib.util
import os
import sqlite3
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rp = _load('replay_orchestrator', os.path.join(_HERE, '..', 'bin',
                                               'replay-orchestrator-log.py'))
td = _load('tetragon_dashboard', os.path.join(_HERE, '..', 'bin',
                                              'tetragon-dashboard.py'))

_FAILED = []


def check(name, cond, detail=''):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}{(' — ' + detail) if detail else ''}")
        _FAILED.append(name)


def _write_log(lines):
    fd, path = tempfile.mkstemp(suffix='.log')
    with os.fdopen(fd, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return path


# ── timestamp conversion ────────────────────────────────────────────────

def test_local_to_utc_uses_date_specific_offset():
    """run-agent.sh stamps local time with no zone. A replay spanning a DST
    transition must use the offset in effect on each line's own date, not
    today's — otherwise half the events land an hour off."""
    old_tz = os.environ.get('TZ')
    os.environ['TZ'] = 'America/Los_Angeles'
    time.tzset()
    try:
        # PDT (UTC-7) in September.
        check('PDT date converts at UTC-7',
              rp.local_to_utc_iso('2026-09-20T11:08:37') == '2026-09-20T18:08:37.000Z',
              rp.local_to_utc_iso('2026-09-20T11:08:37'))
        # PST (UTC-8) in January — same code path, different offset.
        check('PST date converts at UTC-8',
              rp.local_to_utc_iso('2026-01-15T11:08:37') == '2026-01-15T19:08:37.000Z',
              rp.local_to_utc_iso('2026-01-15T11:08:37'))
    finally:
        if old_tz is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = old_tz
        time.tzset()


# ── range bounds ────────────────────────────────────────────────────────

def test_bounds_are_half_open():
    """[since, until) — a line exactly at `until` belongs to the NEXT run,
    so re-running with the previous --until as --since can't duplicate it."""
    path = _write_log([
        '2026-09-20T10:00:00 [aaaaaaaa] === Agent run starting ===',
        '2026-09-20T11:00:00 [aaaaaaaa] === Agent run complete ===',
        '2026-09-20T12:00:00 [bbbbbbbb] === Agent run starting ===',
    ])
    try:
        since = rp.parse_bound('2026-09-20T11:00:00')
        until = rp.parse_bound('2026-09-20T12:00:00')
        events, scanned, _ = rp.build_events(td, path, since, until, {})
        check('half-open: exactly one event in [11:00, 12:00)', len(events) == 1,
              f'got {len(events)}')
        check('half-open: it is the 11:00 line',
              events and events[0]['args'] == 'complete')
        check('scanned counts every non-empty line', scanned == 3, f'got {scanned}')

        # The excluded 12:00 line is picked up by the adjoining run.
        nxt, _, _ = rp.build_events(td, path, until, None, {})
        check('half-open: next run picks up the boundary line',
              len(nxt) == 1 and nxt[0]['args'] == 'starting', f'got {len(nxt)}')
    finally:
        os.unlink(path)


# ── event shape fidelity ────────────────────────────────────────────────

def test_event_shape_matches_follower():
    path = _write_log([
        '2026-09-20T12:00:00 [aaaaaaaa] === Agent run starting ===',
        '2026-09-20T12:00:05 [aaaaaaaa] --- Skill: PR Review ---',
        '2026-09-20T12:00:09 [aaaaaaaa] Issue #4242 — state changed to implement',
    ])
    try:
        events, _, _ = rp.build_events(td, path, None, None, {})
        check('three markers parsed', len(events) == 3, f'got {len(events)}')
        if len(events) == 3:
            run, skill, orch = events
            check('agent-run: SKILL/skill:agent-run/skill-dispatch',
                  (run['type'], run['binary'], run['source'])
                  == ('SKILL', 'skill:agent-run', 'skill-dispatch'), repr(run))
            check('skill-section detail is the section name',
                  skill['args'] == 'PR Review', repr(skill['args']))
            check('orch marker gets the orch- binary prefix',
                  orch['binary'] == 'skill:orch-transition', repr(orch['binary']))
            check('uid is the agent uid', all(e['uid'] == 965 for e in events))
            check('is_agent set', all(e['is_agent'] for e in events))
    finally:
        os.unlink(path)


def test_scanner_lines_become_scan_events():
    """Scanner output in the orchestrator log is a SCAN event, not a
    skill-dispatch one — that is what puts it in Stage 4 and under the Scan
    filter button."""
    path = _write_log([
        '2026-09-20T12:00:00 [aaaaaaaa] MCP Scanner: 7 tools scanned',
        '2026-09-20T12:00:01 [aaaaaaaa] Skill Scanner: 4 skills clean',
        '2026-09-20T12:00:02 [aaaaaaaa] Prompt Scanner: 11 prompts scanned, clean',
    ])
    try:
        events, _, _ = rp.build_events(td, path, None, None, {})
        check('all three scanners parsed', len(events) == 3, f'got {len(events)}')
        check('scanners are SCAN type', all(e['type'] == 'SCAN' for e in events),
              repr([e['type'] for e in events]))
        check('scanner sources are the scan families',
              {e['source'] for e in events} == {'mcp-scan', 'skill-scan', 'prompt-scan'},
              repr(sorted({e['source'] for e in events})))
        check('scanner binary is bare (no skill: prefix)',
              all(not e['binary'].startswith('skill:') for e in events))
    finally:
        os.unlink(path)


# ── trace prefix resolution ─────────────────────────────────────────────

def test_prefix_resolution():
    full = 'aaaaaaaa-b61b-11f1-9552-07ad1143c9a5'
    path = _write_log([
        '2026-09-20T12:00:00 [aaaaaaaa] === Agent run starting ===',
        '2026-09-20T12:00:01 [cccccccc] === Agent run starting ===',
    ])
    try:
        events, _, unresolved = rp.build_events(
            td, path, None, None, {'aaaaaaaa': full})
        check('known prefix resolves to the full uuid',
              events[0]['trace_id'] == full, repr(events[0]['trace_id']))
        check('unknown prefix stays bare', events[1]['trace_id'] == 'cccccccc',
              repr(events[1]['trace_id']))
        check('unknown prefix is reported', unresolved == {'cccccccc'},
              repr(unresolved))
    finally:
        os.unlink(path)


def test_db_map_drops_ambiguous_prefixes():
    """immutable=1 reads a live DB, so a torn page is conceivable. A prefix
    claimed by two different trace_ids must be dropped, never guessed —
    filing an event under the wrong run is worse than leaving it bare."""
    d = tempfile.mkdtemp()
    try:
        db = os.path.join(d, 'events.db')
        conn = sqlite3.connect(db)
        conn.execute('CREATE TABLE events (trace_id TEXT, timestamp TEXT)')
        good = 'aaaaaaaa-b61b-11f1-9552-07ad1143c9a5'
        dup1 = 'bbbbbbbb-1111-11f1-9552-07ad1143c9a5'
        dup2 = 'bbbbbbbb-2222-11f1-9552-07ad1143c9a5'
        for tid in (good, dup1, dup2, 'short', 'not-a-uuid-at-all-really'):
            conn.execute('INSERT INTO events VALUES (?,?)', (tid, '2026-09-21T00:00:00Z'))
        conn.commit(); conn.close()

        m = rp.fetch_trace_map_db(db, '2026-09-01')
        check('unambiguous prefix resolves', m.get('aaaaaaaa') == good, repr(m))
        check('ambiguous prefix dropped', 'bbbbbbbb' not in m, repr(m))
        check('malformed ids ignored', len(m) == 1, repr(m))
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


# ── walk stage routing ──────────────────────────────────────────────────

def test_replayed_events_land_in_walk_stages():
    """The whole point: these rows must classify into the lanes that went
    empty (2 Orchestrator, 3 Skill, 4 Scanning)."""
    path = _write_log([
        '2026-09-20T12:00:00 [aaaaaaaa] === Agent run starting ===',
        '2026-09-20T12:00:05 [aaaaaaaa] --- Skill: PR Review ---',
        '2026-09-20T12:00:07 [aaaaaaaa] MCP Scanner: 7 tools scanned',
    ])
    try:
        events, _, _ = rp.build_events(td, path, None, None, {})
        stages = [td._classify_agent_walk_stage(e['type'], e['source'],
                                                e['args'], e['binary'])
                  for e in events]
        check('agent-run -> Stage 2', stages[0] == 2, f'got {stages[0]}')
        check('skill-section -> Stage 3', stages[1] == 3, f'got {stages[1]}')
        check('mcp scanner -> Stage 4', stages[2] == 4, f'got {stages[2]}')
        check('no event lands in Stage 0 (would be filtered out)',
              0 not in stages, repr(stages))
    finally:
        os.unlink(path)


if __name__ == '__main__':
    print('local_to_utc_iso')
    test_local_to_utc_uses_date_specific_offset()
    print('range bounds')
    test_bounds_are_half_open()
    print('event shape')
    test_event_shape_matches_follower()
    test_scanner_lines_become_scan_events()
    print('prefix resolution')
    test_prefix_resolution()
    test_db_map_drops_ambiguous_prefixes()
    print('walk stages')
    test_replayed_events_land_in_walk_stages()

    if _FAILED:
        print(f"\n{len(_FAILED)} failure(s): {', '.join(_FAILED)}")
        sys.exit(1)
    print('\nall passed')
