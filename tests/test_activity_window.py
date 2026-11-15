"""Unit tests for tetragon-dashboard.py's activity chart windows.

Run: python3 tests/test_activity_window.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: /api/activity-window returns the 24 h whose last
15-minute bucket starts at the requested end, with event counts, run
markers and CI job history from that span only, and the end is aligned
and clamped to the last ACTIVITY_WINDOW_DAYS days.
"""
import importlib.util
import os
import sqlite3
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_DASH_PATH = os.path.join(_HERE, '..', 'bin', 'tetragon-dashboard.py')

spec = importlib.util.spec_from_file_location('tetragon_dashboard', _DASH_PATH)
td = importlib.util.module_from_spec(spec)
spec.loader.exec_module(td)

_FAILED = []


def check(name, cond, detail=''):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}{(' — ' + detail) if detail else ''}")
        _FAILED.append(name)


def sqlt(t):
    return td.time.strftime('%Y-%m-%d %H:%M:%S', td.time.gmtime(t))


def main():
    d = tempfile.mkdtemp()
    td.EVENTS_DB = os.path.join(d, 'events.db')
    td.ISSUE_ACTIONS_DB = os.path.join(d, 'ia.db')
    c = sqlite3.connect(td.EVENTS_DB)
    c.executescript("""
      CREATE TABLE events(created_at, type, policy, source, args);
      CREATE TABLE codeguard_findings(id INTEGER PRIMARY KEY, scan_time, severity, source, ref,
                                      rule_id, title, file_path);
      CREATE TABLE detector_findings(id INTEGER PRIMARY KEY, scan_time, issue_number, verdict,
                                     file_path, rationale);""")
    ia = sqlite3.connect(td.ISSUE_ACTIONS_DB)
    ia.execute("CREATE TABLE issue_actions(issue_number, action, state, outcome, detail, created_at)")
    NOW = 1_800_000_000 // 900 * 900 + 120        # 2 min into a bucket
    END = NOW // 900 * 900 - 3 * 86400            # a window three days back
    for t, ty in ((END - 95 * 900, 'EXEC'), (END - 95 * 900 + 10, 'BLOCK'), (END, 'EXEC'),
                  (END - 96 * 900, 'EXEC'), (END + 900, 'EXEC')):
        c.execute("INSERT INTO events VALUES (?,?,?,?,?)", (sqlt(t), ty, '', 'x', ''))
    c.execute("INSERT INTO codeguard_findings(scan_time,severity,source,ref,rule_id,title,file_path) "
              "VALUES (?,?,?,?,?,?,?)", (sqlt(END - 3600), 'HIGH', 'pr', '7000', 'CG-1', 't', 'f.c'))
    c.commit()
    ia.execute("INSERT INTO issue_actions VALUES (7000,'review','done','ok','',?)",
               (sqlt(END - 3600).replace(' ', 'T'),))
    ia.execute("INSERT INTO issue_actions VALUES (7001,'triage','done','ok','',?)",
               (sqlt(END + 2 * 86400).replace(' ', 'T'),))
    ia.commit()
    td._active_jobs_history.clear()
    td._active_jobs_history.extend([(END - 3600, 5, 1, 0, 0, 60), (END + 86400, 9, 0, 0, 0, 0)])

    print("activity window")
    w = td.activity_window(END + 300, now=NOW)
    a = w['activity']
    check("end aligned down to 15 min", w['end'] == END, str(w['end']))
    check("96 buckets, first 23 h 45 m before the end", len(a) == 96
          and a[0]['t'] == td.time.strftime('%Y-%m-%dT%H:%M:00Z', td.time.gmtime(END - 95 * 900))
          and a[-1]['t'] == td.time.strftime('%Y-%m-%dT%H:%M:00Z', td.time.gmtime(END)), a[0]['t'])
    check("counts from that span only", (a[0]['events'], a[0]['blocked'], a[-1]['events'],
                                          sum(b['events'] for b in a)) == (2, 1, 1, 3), str(a[0]))
    check("workflow markers in the window, with the CodeGuard summary",
          [m['num'] for m in w['workflow']] == ['7000'] and w['workflow'][0].get('codeguard'),
          str(w['workflow']))
    check("CodeGuard run markers", len(w['codeguard']) == 1 and w['codeguard'][0]['findings'] == 1)
    check("job history from that span", [h[1] for h in w['jobs']['history']] == [5]
          and w['jobs']['oldest_wait']['v'] == [60], str(w['jobs']))

    w = td.activity_window(0, now=NOW)
    check("clamped to the last 7 days", w['end'] == NOW // 900 * 900 - 6 * 86400, str(w['end']))
    w = td.activity_window(NOW + 86400, now=NOW)
    check("no later than now", w['end'] == NOW // 900 * 900, str(w['end']))

    if _FAILED:
        print(f"\n{len(_FAILED)} failure(s): {', '.join(_FAILED)}")
        sys.exit(1)
    print("\nall passed")


if __name__ == '__main__':
    main()
