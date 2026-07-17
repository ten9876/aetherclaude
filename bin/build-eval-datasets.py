#!/usr/bin/env python3
"""build-eval-datasets.py — assemble the three AetherClaude eval datasets.

Sources ground truth from the orchestrator's own action history
(/Users/aetherclaude/data/issue-actions.db, table issue_actions) and fetches
issue/PR content with `gh`. Emits JSONL datasets under .galileo/datasets/ and,
with --push, uploads them as Galileo datasets (runs OUTSIDE the sandbox — needs
GALILEO_API_KEY + gh; never invoked by the agent).

Flows / datasets:
  triage-cases     — issues + known-good classification/route + missing-info flag
  implement-cases  — fix issues + accepted-change scope (files) + must-cite-constitution
  review-cases     — PRs incl. a known stale-code regression + convention violations

Each case: {"input": {...}, "expected": {...}, "metadata": {...}}

Usage:
  build-eval-datasets.py --out .galileo/datasets            # from history via gh
  build-eval-datasets.py --demo --out .galileo/datasets     # seed cases, no gh/DB
  build-eval-datasets.py --push                              # also upload to Galileo
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys

ACTIONS_DB = os.environ.get('ACTIONS_DB', '/Users/aetherclaude/data/issue-actions.db')
REPO = os.environ.get('AETHER_REPO', 'ten9876/AetherSDR')
FLOWS = ('triage', 'implement', 'review')

# action → flow, and which actions imply a "known-good, human-accepted" outcome
_ACTION_FLOW = {
    'triaged': 'triage', 'needs_info': 'triage',
    'implemented': 'implement',
    'pr_reviewed': 'review',
}


def gh_json(args):
    """Best-effort `gh` call returning parsed JSON, or None on any failure."""
    try:
        out = subprocess.run(['gh', *args], capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def refs_for_flow(flow, limit):
    """Distinct issue/PR numbers the agent acted on for this flow, newest first."""
    actions = [a for a, f in _ACTION_FLOW.items() if f == flow]
    if not actions or not os.path.exists(ACTIONS_DB):
        return []
    q = ('SELECT DISTINCT issue_number FROM issue_actions WHERE action IN (%s) '
         'AND outcome=? ORDER BY created_at DESC LIMIT ?' % ','.join('?' * len(actions)))
    try:
        conn = sqlite3.connect(ACTIONS_DB)
        rows = conn.execute(q, (*actions, 'success', limit)).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception as e:
        print(f'refs_for_flow({flow}) DB error: {e}', file=sys.stderr)
        return []


def build_triage(limit):
    cases = []
    for n in refs_for_flow('triage', limit):
        issue = gh_json(['issue', 'view', str(n), '-R', REPO,
                         '--json', 'number,title,body,labels,state'])
        if not issue:
            continue
        labels = [l['name'] for l in issue.get('labels', [])]
        cases.append({
            'input': {'number': n, 'title': issue.get('title', ''), 'body': issue.get('body', '')[:6000]},
            'expected': {'labels': labels, 'requested_info': 'needs-info' in labels or 'waiting' in labels},
            'metadata': {'flow': 'triage', 'source': 'history'},
        })
    return cases


def build_implement(limit):
    cases = []
    for n in refs_for_flow('implement', limit):
        issue = gh_json(['issue', 'view', str(n), '-R', REPO, '--json', 'number,title,body'])
        # the PR that closed the issue holds the accepted-change scope
        prs = gh_json(['pr', 'list', '-R', REPO, '--search', f'{n} in:body', '--state', 'merged',
                       '--json', 'number,files', '--limit', '1'])
        if not issue:
            continue
        files = [f['path'] for f in (prs[0]['files'] if prs else [])] if prs else []
        cases.append({
            'input': {'number': n, 'title': issue.get('title', ''), 'body': issue.get('body', '')[:6000]},
            'expected': {'scope_files': files, 'must_cite_constitution': True},
            'metadata': {'flow': 'implement', 'source': 'history'},
        })
    return cases


def build_review(limit):
    cases = []
    for n in refs_for_flow('review', limit):
        pr = gh_json(['pr', 'view', str(n), '-R', REPO,
                      '--json', 'number,title,body,files,state'])
        if not pr:
            continue
        cases.append({
            'input': {'number': n, 'title': pr.get('title', ''),
                      'files': [f['path'] for f in pr.get('files', [])]},
            'expected': {'recommendation': 'merge' if pr.get('state') == 'MERGED' else 'no-merge',
                         'has_stale_code': False, 'convention_violations': []},
            'metadata': {'flow': 'review', 'source': 'history'},
        })
    return cases


# --- Demo seed cases (no gh/DB needed) — enough to exercise the full pipeline,
# including a review case that MUST catch stale code (the worst-fear metric). ---
DEMO = {
    'triage': [
        {'input': {'number': 9001, 'title': 'FT8 decodes but no audio to speaker',
                   'body': 'Running v4.1.5. WSJT-X shows decodes, Aether shows signal, but no speaker audio.'},
         'expected': {'labels': ['bug', 'audio'], 'requested_info': False},
         'metadata': {'flow': 'triage', 'source': 'demo', 'note': 'AGC=Off class issue'}},
        {'input': {'number': 9002, 'title': 'Add dark mode', 'body': 'Please add a dark theme.'},
         'expected': {'labels': ['enhancement'], 'requested_info': True},
         'metadata': {'flow': 'triage', 'source': 'demo', 'note': 'underspecified → ask'}},
    ],
    'implement': [
        {'input': {'number': 9101, 'title': 'Meter smoothing inconsistent across applets',
                   'body': 'S-meter jitters; other meters are smooth.'},
         'expected': {'scope_files': ['src/dsp/MeterSmoother.cpp'], 'must_cite_constitution': True},
         'metadata': {'flow': 'implement', 'source': 'demo', 'note': 'canonical MeterSmoother'}},
    ],
    'review': [
        {'input': {'number': 9201, 'title': 'Fix NR toggle', 'files': ['src/dsp/nr.cpp'],
                   'diff_summary': 'Re-adds a duplicated AGC init block already present on main (stale base).'},
         'expected': {'recommendation': 'no-merge', 'has_stale_code': True,
                      'convention_violations': ['duplicate-init']},
         'metadata': {'flow': 'review', 'source': 'demo', 'note': 'STALE-CODE regression — must catch'}},
        {'input': {'number': 9202, 'title': 'Docs: fix typo', 'files': ['README.md'],
                   'diff_summary': 'Single-word typo fix.'},
         'expected': {'recommendation': 'merge', 'has_stale_code': False, 'convention_violations': []},
         'metadata': {'flow': 'review', 'source': 'demo'}},
    ],
}


def push_to_galileo(name, cases):
    if not os.environ.get('GALILEO_API_KEY'):
        print(f'  (skip push {name}: no GALILEO_API_KEY)'); return
    try:
        from galileo.datasets import create_dataset
        create_dataset(name=name, content=[{'input': json.dumps(c['input']),
                                            'expected': json.dumps(c['expected'])} for c in cases])
        print(f'  pushed {name} → Galileo ({len(cases)} cases)')
    except Exception as e:
        print(f'  push {name} failed: {e}', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='.galileo/datasets')
    ap.add_argument('--limit', type=int, default=25)
    ap.add_argument('--demo', action='store_true', help='emit seed cases, no gh/DB')
    ap.add_argument('--push', action='store_true', help='upload to Galileo')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    builders = {'triage': build_triage, 'implement': build_implement, 'review': build_review}
    for flow in FLOWS:
        cases = DEMO[flow] if args.demo else builders[flow](args.limit)
        if not cases and not args.demo:
            print(f'{flow}: no history found — try --demo for seed cases', file=sys.stderr)
        path = os.path.join(args.out, f'{flow}-cases.jsonl')
        with open(path, 'w') as f:
            for c in cases:
                f.write(json.dumps(c) + '\n')
        print(f'{flow}: wrote {len(cases)} cases → {path}')
        if args.push:
            push_to_galileo(f'aetherclaude-{flow}-cases', cases)
    return 0


if __name__ == '__main__':
    sys.exit(main())
