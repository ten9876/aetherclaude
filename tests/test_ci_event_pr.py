"""Unit tests for tetragon-dashboard.py's CI-completion → PR mapping.

Run: python3 tests/test_ci_event_pr.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: a completed check_run / workflow_run is keyed to
the PR it ran for, whether GitHub named the PR in pull_requests[] (same-repo
branch) or left it empty (head in a fork), and runs with no PR stay global.

Covers:
  - pull_requests[] filled in → that PR, no API call
  - fork workflow_run → owner:branch lookup, matched on head sha
  - owner:branch lookup misses the sha → falls back to scanning open PRs
  - check_run (no head repo in payload) → open-PR scan by sha, paginated
  - push-triggered, in-progress and inconclusive runs → no lookup
  - lookup errors → None (the run stays global), never raise
  - results are cached by sha; misses expire so a later PR is still found
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


class FakeGitHub:
    """Answers pulls?… queries from a list of open PRs and records calls."""

    def __init__(self, prs, fail=False):
        self.prs = prs
        self.fail = fail
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        if self.fail:
            raise OSError('proxy down')
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse('x:/' + path).query)
        prs = self.prs
        if 'head' in q:
            owner, branch = q['head'][0].split(':', 1)
            prs = [p for p in prs if p['_owner'] == owner and p['head']['ref'] == branch]
            return prs[:int(q.get('per_page', ['30'])[0])]
        per, page = int(q['per_page'][0]), int(q['page'][0])
        return prs[(page - 1) * per: page * per]


def pr(n, owner, branch, sha):
    return {'number': n, '_owner': owner, 'head': {'ref': branch, 'sha': sha}}


def wf_run(sha, owner, branch, event='pull_request', conclusion='success',
           action='completed', prs=None):
    return {'action': action, 'workflow_run': {
        'head_sha': sha, 'head_branch': branch, 'event': event,
        'conclusion': conclusion, 'pull_requests': prs or [],
        'head_repository': {'owner': {'login': owner}}}}


def resolve(event_type, payload, gh):
    td._ci_head_pr_cache.clear()
    return td._ci_event_pr_number(
        event_type, payload, lookup=lambda s, o, b: td._pr_for_head(s, o, b, get=gh))


def main():
    print("CI completion → PR number")

    gh = FakeGitHub([pr(7254, 'nonoo', 'band-applet', 'aaa')])
    n = resolve('workflow_run', wf_run('zzz', 'x', 'y', prs=[{'number': 7256}]), gh)
    check("pull_requests[] used as-is", n == 7256 and not gh.calls, f"{n} {gh.calls}")

    gh = FakeGitHub([pr(7254, 'nonoo', 'main', 'aaa'), pr(7256, 'ten9876', 'feat', 'bbb')])
    n = resolve('workflow_run', wf_run('aaa', 'nonoo', 'main'), gh)
    check("fork workflow_run → owner:branch lookup", n == 7254 and len(gh.calls) == 1
          and 'head=nonoo%3Amain' in gh.calls[0], f"{n} {gh.calls}")

    # The fork branch moved on since this run (new push): head sha differs,
    # so the owner:branch hit is not trusted and the open list is scanned.
    gh = FakeGitHub([pr(7254, 'nonoo', 'main', 'newer')])
    n = resolve('workflow_run', wf_run('older', 'nonoo', 'main'), gh)
    check("stale head sha → no PR", n is None and len(gh.calls) == 2, f"{n} {gh.calls}")

    many = [pr(i, 'u', f'b{i}', f's{i}') for i in range(1, 251)]
    gh = FakeGitHub(many)
    n = resolve('check_run', {'action': 'completed', 'check_run': {
        'head_sha': 's230', 'conclusion': 'failure', 'pull_requests': []}}, gh)
    check("check_run → open-PR scan across pages", n == 230 and len(gh.calls) == 3,
          f"{n} {gh.calls}")

    gh = FakeGitHub([pr(1, 'u', 'b', 'aaa')])
    n = resolve('check_run', {'action': 'completed', 'check_run': {
        'check_suite': {'head_sha': 'aaa'}, 'conclusion': 'success', 'pull_requests': []}}, gh)
    check("check_run head sha from check_suite", n == 1, f"{n}")

    for label, payload in (
            ("push run", wf_run('aaa', 'aethersdr', 'main', event='push')),
            ("in-progress run", wf_run('aaa', 'nonoo', 'main', action='requested')),
            ("cancelled run", wf_run('aaa', 'nonoo', 'main', conclusion='cancelled'))):
        gh = FakeGitHub([pr(9, 'nonoo', 'main', 'aaa')])
        n = resolve('workflow_run', payload, gh)
        check(f"{label} → no lookup", n is None and not gh.calls, f"{n} {gh.calls}")

    gh = FakeGitHub([], fail=True)
    logged = []
    orig = td._log_exc
    td._log_exc = lambda where, exc=None, every=60.0: logged.append(where)
    try:
        n = resolve('workflow_run', wf_run('aaa', 'nonoo', 'main'), gh)
    finally:
        td._log_exc = orig
    check("lookup error → None, logged", n is None and logged == ['ci_event_pr_number'],
          f"{n} {logged}")

    print("cache")
    td._ci_head_pr_cache.clear()
    gh = FakeGitHub([pr(5, 'u', 'b', 'aaa')])
    a = td._pr_for_head('aaa', 'u', 'b', get=gh)
    b = td._pr_for_head('aaa', 'u', 'b', get=gh)
    check("hit cached by sha", a == b == 5 and len(gh.calls) == 1, f"{a} {b} {gh.calls}")

    td._ci_head_pr_cache.clear()
    gh = FakeGitHub([])
    td._pr_for_head('ccc', 'u', 'b', get=gh)
    gh.prs = [pr(6, 'u', 'b', 'ccc')]
    again = td._pr_for_head('ccc', 'u', 'b', get=gh)
    check("fresh miss is cached", again is None, f"{again}")
    td._ci_head_pr_cache['ccc'] = (None, td.time.time() - 601)
    later = td._pr_for_head('ccc', 'u', 'b', get=gh)
    check("expired miss is retried", later == 6, f"{later}")

    if _FAILED:
        print(f"\n{len(_FAILED)} failure(s): {', '.join(_FAILED)}")
        sys.exit(1)
    print("\nall passed")


if __name__ == '__main__':
    main()
