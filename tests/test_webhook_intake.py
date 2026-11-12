"""Unit tests for tetragon-dashboard.py's webhook intake watch.

Run: python3 tests/test_webhook_intake.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: a burst of cloudflared "Unable to reach the origin
service" errors for the dashboard's own origin raises one critical alert,
counted once per failed request, and nothing else does.

Covers:
  - each failed request counts once (cloudflared logs two lines per request)
  - errors for other tunnel origins (ttyd on :7681) are ignored
  - the threshold within the window alerts once, then waits for the re-alert gap
  - errors older than the window age out; a clear window re-arms the alert
  - _LogTail starts at the end, returns only complete lines, follows rotation
"""
import importlib.util
import os
import shutil
import sys
import tempfile
from collections import deque

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


# Two lines per failed request, as cloudflared 2026.x writes them.
FAILED_REQUEST = [
    '2026-11-12T18:51:58Z ERR  error="Unable to reach the origin service. The service may be down or it '
    'may not be responding to traffic from cloudflared: read tcp 127.0.0.1:49967->127.0.0.1:8080: read: '
    'connection reset by peer" connIndex=1 event=1 ingressRule=0 originService=http://127.0.0.1:8080',
    '2026-11-12T18:51:58Z ERR failed to serve incoming request error="Failed to proxy HTTP: Unable to reach '
    'the origin service. The service may be down or it may not be responding to traffic from cloudflared: '
    'read tcp 127.0.0.1:49967->127.0.0.1:8080: read: connection reset by peer"',
]
TUI_FAILED = [
    '2026-11-12T18:51:58Z ERR  error="Unable to reach the origin service. The service may be down or it '
    'may not be responding to traffic from cloudflared: EOF" connIndex=1 event=1 ingressRule=1 '
    'originService=http://127.0.0.1:7681',
]
NOISE = ['2026-11-12T18:20:21Z INF Registered tunnel connection connIndex=3 event=0 location=yyc01']


def fresh():
    return {'window': deque(), 'alerted_at': None}


def test_counts_each_request_once():
    check('two-line failure counts once', td._origin_errors(FAILED_REQUEST) == 1)
    check('other origins and info lines ignored', td._origin_errors(TUI_FAILED + NOISE) == 0)


def test_threshold_alerts_once():
    s, t = fresh(), 1000.0
    below = td._webhook_intake_step(s, FAILED_REQUEST * (td.WEBHOOK_INTAKE_MAX_ERRORS - 1), t)
    check('below threshold: no alert', below is None)
    at = td._webhook_intake_step(s, FAILED_REQUEST, t + 60)
    check('reaching threshold alerts', at is not None and 'WEBHOOK INTAKE' in at, repr(at))
    check('status is failing', td.ring_stats['webhook_intake']['status'] == 'failing')
    again = td._webhook_intake_step(s, FAILED_REQUEST * 5, t + 120)
    check('ongoing burst does not re-alert inside the gap', again is None)
    later = td._webhook_intake_step(s, FAILED_REQUEST * td.WEBHOOK_INTAKE_MAX_ERRORS,
                                    t + 120 + td.WEBHOOK_INTAKE_REALERT_SECS)
    check('still failing after the re-alert gap alerts again', later is not None)


def test_window_ages_out_and_rearms():
    s, t = fresh(), 1000.0
    td._webhook_intake_step(s, FAILED_REQUEST * 6, t)
    spread = td._webhook_intake_step(s, FAILED_REQUEST * 6, t + td.WEBHOOK_INTAKE_WINDOW + 1)
    check('errors spread wider than the window do not alert', spread is None)
    s, t = fresh(), 1000.0
    check('first burst alerts',
          td._webhook_intake_step(s, FAILED_REQUEST * td.WEBHOOK_INTAKE_MAX_ERRORS, t) is not None)
    td._webhook_intake_step(s, NOISE, t + td.WEBHOOK_INTAKE_WINDOW + 1)
    check('clear window reports ok', td.ring_stats['webhook_intake']['status'] == 'ok')
    check('new burst after recovery alerts',
          td._webhook_intake_step(s, FAILED_REQUEST * td.WEBHOOK_INTAKE_MAX_ERRORS,
                                  t + td.WEBHOOK_INTAKE_WINDOW + 61) is not None)


def test_log_tail():
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, 'cloudflared-error.log')
        with open(path, 'w') as f:
            f.write('old line\n')
        tail = td._LogTail(path)
        check('first read starts at the end', tail.read() == [])
        with open(path, 'a') as f:
            f.write('one\ntwo\npart')
        check('returns complete lines only', tail.read() == ['one', 'two'])
        with open(path, 'a') as f:
            f.write('ial\n')
        check('finishes the partial line next time', tail.read() == ['partial'])
        with open(path, 'w') as f:            # copy-truncate: same inode, shrinks
            f.write('after truncate\n')
        check('follows copy-truncate', tail.read() == ['after truncate'])
        os.rename(path, path + '.1')          # rename and recreate: new inode
        with open(path, 'w') as f:
            f.write('new file, longer than before\n')
        check('follows rename-and-recreate', tail.read() == ['new file, longer than before'])
        os.remove(path)
        check('missing file tolerated', tail.read() == [])
    finally:
        shutil.rmtree(d)


if __name__ == '__main__':
    for fn in (test_counts_each_request_once, test_threshold_alerts_once,
               test_window_ages_out_and_rearms, test_log_tail):
        print(fn.__name__)
        fn()
    if _FAILED:
        print(f"{len(_FAILED)} failed: {', '.join(_FAILED)}")
        sys.exit(1)
    print('all passed')
