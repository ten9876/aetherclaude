"""Unit tests for tetragon-dashboard.py's active-CI-jobs tracker.

Run: python3 tests/test_active_jobs.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: the live counts are the GitHub-hosted jobs that
are in_progress (against the concurrency limit) and queued (queue depth),
whatever order the workflow_job webhooks arrive in, and a reconcile poll
corrects the table without undoing a webhook that is newer than the poll.

Covers:
  - queued → in_progress → completed moves a job between the counts
  - OS from labels; self-hosted jobs, 'waiting' and 'pending' are not counted
  - a late queued delivery doesn't demote an in_progress job; a late
    in_progress after completed doesn't resurrect it
  - reconcile drops jobs a webhook never closed, keeps newer webhook state,
    and doesn't resurrect a job completed after the poll began
  - each running job is mapped to its PR: from the run listing on reconcile,
    by fetching the run for jobs a webhook reported, via the head commit for
    a fork run; a push run has no PR; a failed lookup is retried later
  - minute samples are kept 7 days for the scrolled-back chart, the stats
    stay on the last 24 h
  - 24 h stats: at-limit / queued shares, queue depth mean/peak, buckets,
    wait-before-start from created_at → started_at, and the oldest queued
    job's wait sampled each minute
"""
import importlib.util
import os
import sys

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


def reset():
    td._active_jobs_jobs.clear()
    td._active_jobs_done.clear()
    td._active_jobs_history.clear()
    td._active_jobs_waits.clear()
    td._active_jobs_runs.clear()
    td._active_jobs_meta.update(last_event_at=0.0, last_poll_at=0.0, poll_error=None, polled_runs=0)
    td._active_jobs_meta['events_24h'].clear()


def ev(action, jid, labels=('ubuntu-latest',), created='2026-11-14T06:00:00Z',
       started='2026-11-14T06:03:00Z', run=1):
    return {'action': action, 'workflow_job': {
        'id': jid, 'run_id': run, 'name': f'job{jid}', 'labels': list(labels),
        'status': action, 'created_at': created,
        'started_at': started if action != 'queued' else None}}


def counts():
    c, _ = td._active_jobs_counts()
    return sum(v['active'] for v in c.values()), sum(v['queued'] for v in c.values()), c


def main():
    T = 1_800_000_000.0
    print("webhook state")
    reset()
    td.active_jobs_webhook(ev('queued', 1), now=T)
    td.active_jobs_webhook(ev('queued', 2, labels=['macos-15']), now=T)
    a, q, c = counts()
    check("queued jobs are queue depth", (a, q) == (0, 2) and c['macos']['queued'] == 1, f"{a} {q}")
    td.active_jobs_webhook(ev('in_progress', 1), now=T + 1)
    a, q, _ = counts()
    check("in_progress counts as active", (a, q) == (1, 1), f"{a} {q}")
    check("wait recorded on start", [w[1] for w in td._active_jobs_waits] == [180.0], str(list(td._active_jobs_waits)))
    td.active_jobs_webhook(ev('queued', 1), now=T + 2)
    a, q, _ = counts()
    check("late queued doesn't demote", (a, q) == (1, 1), f"{a} {q}")
    td.active_jobs_webhook(ev('completed', 1), now=T + 3)
    td.active_jobs_webhook(ev('in_progress', 1), now=T + 4)
    a, q, _ = counts()
    check("completed job not resurrected", (a, q) == (0, 1), f"{a} {q}")
    td.active_jobs_webhook(ev('in_progress', 3, labels=['self-hosted', 'linux']), now=T)
    td.active_jobs_webhook(ev('waiting', 4), now=T)
    a, q, _ = counts()
    check("self-hosted and waiting not counted", (a, q) == (0, 1), f"{a} {q}")
    check("os from labels", td._active_jobs_os(['windows-latest']) == 'windows'
          and td._active_jobs_os(['macos-15']) == 'macos' and td._active_jobs_os(['ubuntu-24.04']) == 'linux')

    print("reconcile")
    reset()
    td.active_jobs_webhook(ev('in_progress', 10), now=T)        # its completed webhook was lost
    td.active_jobs_webhook(ev('in_progress', 11), now=T)

    def fake_get(path):
        if path.startswith('actions/runs?status=in_progress') and 'page=1' in path:
            return {'workflow_runs': [{'id': 7}]}
        if path.startswith('actions/runs/7/jobs'):
            # During the poll: job 12 completes and job 13 starts by webhook.
            td.active_jobs_webhook(ev('completed', 12, run=7), now=T + 105)
            td.active_jobs_webhook(ev('in_progress', 13, run=7), now=T + 106)
            return {'jobs': [
                {'id': 11, 'run_id': 7, 'status': 'in_progress', 'labels': ['ubuntu-latest'],
                 'created_at': 'x', 'started_at': 'y'},
                {'id': 12, 'run_id': 7, 'status': 'in_progress', 'labels': ['ubuntu-latest']},
                {'id': 14, 'run_id': 7, 'status': 'queued', 'labels': ['macos-15']},
                {'id': 15, 'run_id': 7, 'status': 'completed', 'labels': ['ubuntu-latest']}]}
        return {'workflow_runs': []}
    td.active_jobs_reconcile(fake_get, now=T + 100)
    ids = sorted(td._active_jobs_jobs)
    check("reconcile: stale dropped, newer webhook kept, completed not resurrected",
          ids == [11, 13, 14], str(ids))
    check("reconcile records poll", td._active_jobs_meta['polled_runs'] == 1
          and td._active_jobs_meta['last_poll_at'] > 0)

    print("job → PR")
    reset()
    td._ci_head_pr_cache.clear()
    runs = {
        21: {'id': 21, 'name': 'CI', 'event': 'pull_request', 'head_branch': 'feat',
             'pull_requests': [{'number': 7300}]},
        22: {'id': 22, 'name': 'CI', 'event': 'pull_request', 'head_branch': 'main', 'head_sha': 'fk',
             'pull_requests': [], 'head_repository': {'owner': {'login': 'nonoo'}}},
        23: {'id': 23, 'name': 'CI', 'event': 'push', 'head_branch': 'main', 'pull_requests': []}}
    calls = []
    fail = {'on': True}

    def run_get(path):
        calls.append(path)
        if path.startswith('actions/runs/'):
            if fail['on'] and path.endswith('/23'):
                raise OSError('proxy down')
            return runs[int(path.rsplit('/', 1)[1])]
        if path.startswith('pulls?'):
            return [{'number': 7242, 'head': {'sha': 'fk'}}]
        return {}
    for jid, rid in ((31, 21), (32, 22), (33, 23)):
        e = ev('in_progress', jid, run=rid, labels=['macos-15'] if jid == 31 else ['ubuntu-latest'])
        e['workflow_job'].update(workflow_name='CI', head_branch=runs[rid]['head_branch'])
        td.active_jobs_webhook(e, now=T)
    td.active_jobs_resolve_runs(run_get, now=T)
    js = {j['run_id']: j for j in td.active_jobs_summary(now=T)['jobs']}
    check("same-repo PR from pull_requests[]", js[21]['pr'] == 7300, str(js[21]))
    check("fork PR from head commit", js[22]['pr'] == 7242, str(js[22]))
    check("failed lookup leaves the job unmapped", js[23]['pr'] is None and js[23]['event'] is None, str(js[23]))
    n = len(calls)
    td.active_jobs_resolve_runs(run_get, now=T + 60)
    check("mapped runs not fetched again; failure not retried within 5 min", len(calls) == n, str(calls[n:]))
    fail['on'] = False
    td.active_jobs_resolve_runs(run_get, now=T + 301)
    js = {j['run_id']: j for j in td.active_jobs_summary(now=T)['jobs']}
    check("push run: no PR, branch and event kept", js[23]['pr'] is None and js[23]['event'] == 'push'
          and js[23]['branch'] == 'main', str(js[23]))
    check("jobs listed in slot order (OS, then start)",
          [j['os'] for j in td.active_jobs_summary(now=T)['jobs']] == ['linux', 'linux', 'macos'])

    print("summary")
    reset()
    for i in range(20):
        td.active_jobs_webhook(ev('in_progress', 100 + i), now=T)
    for i in range(4):
        td.active_jobs_webhook(ev('queued', 200 + i), now=T)
    td.active_jobs_sample(now=T)
    for i in range(4):
        td.active_jobs_webhook(ev('completed', 200 + i), now=T + 30)
    for i in range(10):
        td.active_jobs_webhook(ev('completed', 100 + i), now=T + 30)
    td.active_jobs_sample(now=T + 60)
    s = td.active_jobs_summary(now=T + 60)
    check("live counts", (s['active'], s['queued']) == (10, 0), f"{s['active']} {s['queued']}")
    check("at-limit and queued shares", (s['at_limit_pct'], s['waiting_pct']) == (50, 50),
          f"{s['at_limit_pct']} {s['waiting_pct']}")
    check("queue depth mean and peak", (s['queue_mean'], s['peak_queued'], s['peak']) == (2.0, 4, 20),
          f"{s['queue_mean']} {s['peak_queued']} {s['peak']}")
    h = s['history']
    check("one 5-min bucket: peak/mean active, peak/mean queued",
          len(h) == 1 and h[0][1] == 20 and h[0][2] == 15.0 and h[0][3] == 4 and h[0][5] == 2.0, str(h))
    ow = s['oldest_wait']
    exp = round(T - td.datetime(2026, 11, 14, 6, 0, tzinfo=td.timezone.utc).timestamp())
    check("oldest wait per minute: age of the oldest queued job, 0 once the queue empties",
          ow and ow['step'] == 60 and ow['v'][0] == exp and ow['v'][-1] == 0 and len(ow['v']) == 2, str(ow and ow['v']))
    check("wait stats", s['waits'] and s['waits']['jobs'] == 20 and s['waits']['avg_s'] == 180, str(s['waits']))
    td.active_jobs_sample(now=T + 86400 + 61)
    s = td.active_jobs_summary(now=T + 86400 + 61)
    check("24 h stats and waits age out after 24 h", s['samples'] == 1 and s['waits'] is None
          and s['peak'] == 10 and len(s['history']) == 1, f"{s['samples']} {s['waits']} {s['peak']}")
    check("minute samples kept for scrolling back", len(td._active_jobs_history) == 3)
    w = td.active_jobs_window(T - 300, T + 900)
    check("window: buckets and wait series for that span only",
          [h[1] for h in w['history']] == [20] and w['oldest_wait']['v'][0] == exp
          and w['limit'] == 20, str(w))
    td.active_jobs_sample(now=T + 7 * 86400 + 1)
    check("samples older than 7 days dropped", td._active_jobs_history[0][0] == T + 60,
          str(td._active_jobs_history[0]))

    if _FAILED:
        print(f"\n{len(_FAILED)} failure(s): {', '.join(_FAILED)}")
        sys.exit(1)
    print("\nall passed")


if __name__ == '__main__':
    main()
