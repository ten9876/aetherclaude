"""Unit tests for the webhook path in bin/contributor-points.py.

Run: python3 tests/test_contributor_webhooks.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: a verified webhook is stored raw exactly once (a
redelivery is ignored) and applied to the same fact rows a REST collection
would write, so the scorer credits the right people; events for other
repositories are stored but change nothing.

Covers:
  - issues / issue_comment (on a PR) / pull_request (merged) /
    pull_request_review / discussion answered / discussion_comment / release
  - review state is upper-cased like the REST API's
  - a redelivered webhook is not applied twice
  - another repository's event is ignored
  - comment deletion removes the comment
  - the scorer turns the applied rows into the expected points
"""
import importlib.util
import json
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


REPO = {'full_name': 'aethersdr/AetherSDR'}
alice = {'login': 'alice', 'type': 'User'}
bob = {'login': 'bob', 'type': 'User'}
carol = {'login': 'carol', 'type': 'User'}

issue = {'number': 10, 'user': alice, 'created_at': '2026-10-01T10:00:00Z', 'updated_at': '2026-10-01T10:00:00Z',
         'closed_at': None, 'state_reason': None, 'labels': [{'name': 'bug'}], 'title': 'Crash', 'body': 'It crashes'}
pr = {'number': 11, 'user': bob, 'created_at': '2026-10-01T11:00:00Z', 'updated_at': '2026-10-02T09:00:00Z',
      'closed_at': '2026-10-02T09:00:00Z', 'labels': [], 'title': 'Fix crash', 'body': 'Fixes #10',
      'merged_at': '2026-10-02T09:00:00Z', 'merged_by': carol, 'head': {'sha': 'abc123'}, 'merge_commit_sha': 'def456'}
disc = {'number': 12, 'user': alice, 'created_at': '2026-10-01T12:00:00Z', 'updated_at': '2026-10-01T13:00:00Z',
        'title': 'How do I?', 'body': 'Question', 'answer_chosen_at': '2026-10-01T13:00:00Z'}

db = cp.db_open(os.environ['CONTRIBUTOR_DB'])
send = lambda d, e, p: cp.record_webhook(db, d, e, json.dumps(dict(p, repository=REPO)))

check('issue opened stored', send('d1', 'issues', {'action': 'opened', 'issue': issue, 'sender': alice}))
send('d2', 'issue_comment', {'action': 'created', 'sender': bob,
                             'issue': dict(pr, pull_request={}),
                             'comment': {'id': 501, 'user': bob, 'created_at': '2026-10-01T11:30:00Z',
                                         'body': 'Pushed a fix for the crash on startup'}})
send('d3', 'pull_request', {'action': 'closed', 'pull_request': pr, 'sender': carol})
send('d4', 'pull_request_review', {'action': 'submitted', 'pull_request': pr, 'sender': carol,
                                   'review': {'id': 601, 'user': carol, 'state': 'approved', 'commit_id': 'abc123',
                                              'submitted_at': '2026-10-02T08:00:00Z', 'body': 'Looks good'}})
send('d5', 'discussion', {'action': 'answered', 'discussion': disc, 'sender': alice,
                          'answer': {'user': bob, 'updated_at': '2026-10-01T13:00:00Z'}})
send('d6', 'discussion_comment', {'action': 'created', 'discussion': disc, 'sender': bob,
                                  'comment': {'node_id': 'DC_x', 'user': bob, 'created_at': '2026-10-01T12:30:00Z',
                                              'body': 'Use the band menu for that'}})
send('d7', 'release', {'action': 'published', 'sender': carol,
                       'release': {'tag_name': 'v9.9.9', 'published_at': '2026-10-03T00:00:00Z', 'prerelease': False,
                                   'author': carol}})

q = lambda sql, *a: db.execute(sql, a).fetchone()
check('issue row', q("SELECT author, body FROM items WHERE type='issue' AND number=10") == ('alice', 'It crashes'))
check('pr comment row', q("SELECT type, number, login, substantive FROM comments WHERE id='ic501'") == ('pr', 11, 'bob', 1))
check('pr merged state', q("SELECT merged_by, head_sha, merge_sha FROM items WHERE type='pr' AND number=11")
      == ('carol', 'abc123', 'def456'))
check('pr webhook_at', q("SELECT webhook_at FROM items WHERE type='pr' AND number=11") == ('2026-10-02T09:00:00Z',))
check('review upper-cased', q("SELECT login, state, body FROM reviews WHERE id=601") == ('carol', 'APPROVED', 'Looks good'))
check('answer row', q("SELECT login FROM answers WHERE number=12") == ('bob',))
check('discussion comment', q("SELECT number, login FROM comments WHERE id='dcDC_x'") == (12, 'bob'))
check('release author', q("SELECT author FROM releases WHERE tag='v9.9.9'") == ('carol',))
check('raw payloads kept', q('SELECT COUNT(*), SUM(applied) FROM webhook_events') == (7, 7))

check('redelivery ignored', not send('d1', 'issues', {'action': 'opened', 'issue': issue, 'sender': alice}))
other = cp.record_webhook(db, 'd8', 'issues', json.dumps({'action': 'opened', 'issue': dict(issue, number=99),
                                                          'repository': {'full_name': 'someone/else'}}))
check('other repo stored raw', other)
check('other repo not applied', q("SELECT COUNT(*) FROM items WHERE number=99") == (0,))

led, _ = cp.score(db)
pts = {}
for login, rule, *_ in led:
    pts.setdefault(login, set()).add(rule)
check('alice opened issue', 'issue_open' in pts.get('alice', set()))
check('bob merged pr', {'pr_open', 'pr_merged', 'pr_comment', 'discussion_answer'} <= pts.get('bob', set()))
check('carol approved, merged, released', {'review_approve', 'merge_other', 'release_published'} <= pts.get('carol', set()))

send('d9', 'issue_comment', {'action': 'deleted', 'sender': bob, 'issue': dict(pr, pull_request={}),
                             'comment': {'id': 501, 'user': bob}})
check('comment deletion', q("SELECT COUNT(*) FROM comments WHERE id='ic501'") == (0,))

if failures:
    for f in failures:
        print('FAIL', f)
    sys.exit(1)
print('all contributor webhook checks passed')
