"""Unit tests for breaking-main attribution in bin/contributor-points.py.

Run: python3 tests/test_contributor_breaks.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: a PR is blamed for a red run only when its commit
is the one commit since the run before. When a commit lands with no run of
its own (a backlogged queue), its failure first shows on the next commit's
run; that break is recorded with its range and nobody is penalized.

Covers:
  - collect_spans stores the commit count since the previous informative run,
    skipping runner (infrastructure) failures as a base and green runs as a key
  - a one-commit span blames the run's PR (author, merger, approver)
  - a two-commit span records the break, unattributed, with no penalty
  - a span that was never collected keeps the run's PR
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ['CONTRIBUTOR_DB'] = os.path.join(tempfile.mkdtemp(), 'contributors.db')
spec = importlib.util.spec_from_file_location(
    'contributor_points', os.path.join(HERE, '..', 'bin', 'contributor-points.py'))
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)

failures = []


def check(name, cond):
    if not cond:
        failures.append(name)


class FakeGh:
    """Answers compare requests from a table of (base, head) -> ahead_by."""
    def __init__(self, ahead):
        self.ahead, self.asked, self.calls = ahead, [], 0

    def get(self, path):
        self.calls += 1
        base, head = path.rsplit('/', 1)[1].split('...')
        self.asked.append((base, head))
        return {'ahead_by': self.ahead[(base, head)]}, None


def fresh(span_g1_r2):
    """main: green g1, red r1 (#21, alice), runner failure x1, red r2 (#22, bob)
    which adds a new failing test. span_g1_r2 is the commit count r1..r2."""
    path = os.path.join(tempfile.mkdtemp(), 'contributors.db')
    db = cp.db_open(path)
    runs = [(1, 'g1', '2026-10-20T10:00:00Z', 'success', None, '[]'),
            (2, 'r1', '2026-10-20T11:00:00Z', 'failure', 'tests', '["test:old_test"]'),
            (3, 'x1', '2026-10-20T11:30:00Z', 'failure', 'runner', '[]'),
            (4, 'r2', '2026-10-20T12:00:00Z', 'failure', 'tests', '["test:new_test", "test:old_test"]')]
    for rid, sha, at, concl, cause, sig in runs:
        db.execute('INSERT INTO runs(id,workflow,sha,created_at,conclusion,url,cause,sig) VALUES(?,?,?,?,?,?,?,?)',
                   (rid, 'full-suite.yml', sha, at, concl, f'https://example/runs/{rid}', cause, sig))
    for num, author, merger, sha, at in [(21, 'alice', 'carol', 'r1', '2026-10-20T10:59:00Z'),
                                         (22, 'bob', 'bob', 'r2', '2026-10-20T11:59:00Z')]:
        db.execute('INSERT INTO items(type,number,author,created_at,labels,title,merged_at,merged_by,head_sha,'
                   'merge_sha) VALUES("pr",?,?,?,?,?,?,?,?,?)',
                   (num, author, at, '[]', f'PR {num}', at, merger, f'head{num}', sha))
        db.execute('INSERT INTO state VALUES(?,?)', (f'pr_of:{sha}', str(num)))
    db.execute('INSERT INTO reviews(id,pr,login,state,commit_id,submitted_at) VALUES(1,21,?,?,?,?)',
               ('dave', 'APPROVED', 'head21', '2026-10-20T10:58:00Z'))
    gh = FakeGh({('g1', 'r1'): 1, ('r1', 'r2'): span_g1_r2})
    cp.collect_spans(gh, db)
    return db, gh


def penalties(led):
    return {(login, rule, ref) for login, rule, at, ref, *_ in led if rule in cp.BREAK_RULES}


# Span collection.
db, gh = fresh(2)
check('compare asked for each red run since the previous informative run',
      sorted(gh.asked) == [('g1', 'r1'), ('r1', 'r2')])
check('span stored', db.execute("SELECT value FROM state WHERE name='span:r1..r2'").fetchone() == ('2',))
gh2 = FakeGh({})
cp.collect_spans(gh2, db)
check('stored spans are not fetched again', gh2.asked == [])

# Two commits since the run before: recorded, nobody blamed.
led, breaks = cp.score(db)
b2 = next((b for b in breaks if b['sha'] == 'r2'), None)
check('multi-commit break recorded', b2 is not None and b2['new'] == ['new_test'])
check('multi-commit break unattributed', b2 is not None and b2['pr'] is None)
check('multi-commit break carries its range', b2 is not None and b2.get('range') == {'from': 'r1', 'commits': 2})
check('no penalty for the multi-commit run', not any(ref == 'pr#22' for _, _, ref in penalties(led)))
check('one-commit break still blamed', {('alice', 'break_author', 'pr#21'), ('carol', 'break_merger', 'pr#21'),
                                        ('dave', 'break_approver', 'pr#21')} <= penalties(led))

# One commit since the run before: the run's PR is blamed.
db, _ = fresh(1)
led, breaks = cp.score(db)
check('one-commit span blames the PR', ('bob', 'break_author', 'pr#22') in penalties(led))
check('one-commit break has no range', 'range' not in next(b for b in breaks if b['sha'] == 'r2'))

# Span never collected: unchanged behavior.
db, _ = fresh(3)
db.execute("DELETE FROM state WHERE name='span:r1..r2'")
led, _ = cp.score(db)
check('uncollected span keeps the PR', ('bob', 'break_author', 'pr#22') in penalties(led))

if failures:
    for f in failures:
        print('FAIL', f)
    sys.exit(1)
print('all contributor break checks passed')
