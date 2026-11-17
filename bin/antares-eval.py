#!/usr/bin/env python3
"""antares-eval — measure the Antares Detector on known AetherSDR fixes.

Each corpus entry is a past fix: the commit before it (base), the source
files it changed (ground truth), the weakness class, and the text a user
would have filed (the issue, or the fix title when there was none).
Negative entries are fixes for functional bugs with no attacker-relevant
consequence; the right answer for them is "no vulnerability".

For every entry the detector is run on a clone checked out at base, in
these arms, several runs each (the model samples at temperature 0.3):
  cwe      CWE only, no context            — the nightly sweep's mode
  cwe+ctx  CWE plus the issue text         — an issue that names a CWE
  ctx      issue text only, no CWE         — the per-issue generic mode
Negative entries run in the ctx arm only.

Results append to a JSONL file one run at a time, so an interrupted run
resumes where it stopped. `summary` scores a results file.

Usage:
  antares-eval.py run --corpus config/antares/eval-corpus.json \\
      --label baseline --out data/antares/eval/baseline.jsonl
  antares-eval.py summary data/antares/eval/baseline.jsonl [...]
"""
import argparse
import json
import os
import subprocess
import sys
import time

DEFAULT_DETECTOR = '/Users/aetherclaude/bin/antares-detector.py'
DEFAULT_SOURCE = '/Users/aetherclaude/workspace/AetherSDR'
DEFAULT_EVAL_REPO = '/Users/aetherclaude/data/antares/eval/repo'
CONTEXT_BYTES = 3500          # what run_antares_detector passes (head -c 3500)
ARMS = ('cwe', 'cwe+ctx', 'ctx')


def score(candidates, truth):
    """File-level precision / recall / F1, plus a lenient hit that counts a
    candidate naming the other half of a .h/.cpp pair."""
    cands = {c.strip().lstrip('./') for c in candidates if c.strip()}
    gt = set(truth)
    tp = len(cands & gt)
    p = tp / len(cands) if cands else 0.0
    r = tp / len(gt) if gt else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    stem = lambda f: os.path.splitext(f)[0]
    lenient = bool({stem(c) for c in cands} & {stem(g) for g in gt})
    return {'tp': tp, 'precision': round(p, 4), 'recall': round(r, 4),
            'f1': round(f1, 4), 'hit': tp > 0, 'hit_lenient': lenient}


def prepare_repo(source, path):
    if not os.path.isdir(os.path.join(path, '.git')):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', source, path], check=True)
    subprocess.run(['git', '-C', path, 'fetch', '--quiet', 'origin'], check=False)


def checkout(path, sha):
    subprocess.run(['git', '-C', path, 'checkout', '--quiet', '--force', '--detach', sha],
                   check=True)


def done_keys(out):
    keys = set()
    if os.path.exists(out):
        with open(out) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                keys.add((r['id'], r['arm'], r['run']))
    return keys


def run_detector(detector, repo, entry, arm, max_commands):
    argv = ['/usr/bin/python3', detector, '--repo', repo, '--issue', f'eval-{entry["id"]}',
            '--max-commands', str(max_commands)]
    if arm in ('cwe', 'cwe+ctx'):
        argv += ['--cwe', entry['cwe']]
    if arm in ('cwe+ctx', 'ctx'):
        ctx = entry['context'].encode('utf-8')[:CONTEXT_BYTES].decode('utf-8', 'ignore')
        argv += ['--context', ctx]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return {'verdict': 'error', 'error': (proc.stderr or proc.stdout)[-400:], 'candidates': []}


def cmd_run(a):
    with open(a.corpus) as fh:
        corpus = json.load(fh)
    arms = [x for x in a.arms.split(',') if x]
    prepare_repo(a.source, a.eval_repo)
    done = done_keys(a.out)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    entries = [e for e in corpus['entries'] if not a.only or e['id'] in a.only.split(',')]
    for e in entries:
        e_arms = [x for x in arms if e['kind'] == 'positive' or x == 'ctx']
        todo = [(arm, n) for arm in e_arms for n in range(a.runs)
                if (e['id'], arm, n) not in done]
        if not todo:
            continue
        checkout(a.eval_repo, e['base'])
        for arm, n in todo:
            res = run_detector(a.detector, a.eval_repo, e, arm, a.max_commands)
            rec = {'label': a.label, 'id': e['id'], 'kind': e['kind'], 'arm': arm, 'run': n,
                   'cwe': e['cwe'], 'ground_truth': e['ground_truth'],
                   'verdict': res.get('verdict'), 'candidates': res.get('candidates') or [],
                   'commands_used': res.get('commands_used'), 'elapsed_s': res.get('elapsed_s'),
                   'error': res.get('error'), 'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
            rec.update(score(rec['candidates'], e['ground_truth']))
            with open(a.out, 'a') as fh:
                fh.write(json.dumps(rec) + '\n')
            print(f"{e['id']:28} {arm:8} #{n} {rec['verdict']:16} "
                  f"hit={int(rec['hit'])} f1={rec['f1']:.2f} {rec['candidates']}", flush=True)


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def summarize(rows):
    """Per-arm figures. F1 is the macro of per-entry means; a run that
    submitted no files scores 0."""
    out = {}
    for arm in ARMS:
        pos = [r for r in rows if r['kind'] == 'positive' and r['arm'] == arm]
        neg = [r for r in rows if r['kind'] == 'negative' and r['arm'] == arm]
        if not pos and not neg:
            continue
        by_entry = {}
        for r in pos:
            by_entry.setdefault(r['id'], []).append(r)
        verdicts = {}
        for r in pos + neg:
            verdicts[r['verdict']] = verdicts.get(r['verdict'], 0) + 1
        s = {'runs': len(pos) + len(neg), 'verdicts': verdicts}
        if pos:
            s.update({
                'entries': len(by_entry),
                'file_f1': round(_mean([_mean([r['f1'] for r in rs]) for rs in by_entry.values()]), 4),
                'gt_in_candidates': f"{sum(r['hit'] for r in pos)}/{len(pos)}",
                'gt_in_candidates_lenient': f"{sum(r['hit_lenient'] for r in pos)}/{len(pos)}",
                'flagged_vulnerable': f"{sum(r['verdict'] == 'vulnerable' for r in pos)}/{len(pos)}",
                'mean_candidates': round(_mean([len(r['candidates']) for r in pos
                                                if r['verdict'] == 'vulnerable']), 2),
            })
        if neg:
            s['negatives_flagged_vulnerable'] = f"{sum(r['verdict'] == 'vulnerable' for r in neg)}/{len(neg)}"
        s['mean_commands'] = round(_mean([r['commands_used'] or 0 for r in pos + neg]), 1)
        s['mean_elapsed_s'] = round(_mean([r['elapsed_s'] or 0 for r in pos + neg]), 1)
        out[arm] = s
    return out


def cmd_summary(a):
    for path in a.results:
        with open(path) as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
        labels = sorted({r['label'] for r in rows})
        print(json.dumps({'file': path, 'labels': labels, 'arms': summarize(rows)}, indent=2))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--corpus', required=True)
    r.add_argument('--label', required=True)
    r.add_argument('--out', required=True)
    r.add_argument('--detector', default=DEFAULT_DETECTOR)
    r.add_argument('--source', default=DEFAULT_SOURCE)
    r.add_argument('--eval-repo', default=DEFAULT_EVAL_REPO)
    r.add_argument('--arms', default=','.join(ARMS))
    r.add_argument('--runs', type=int, default=3)
    r.add_argument('--max-commands', type=int, default=15)
    r.add_argument('--only', default='', help='Comma-separated entry ids.')
    s = sub.add_parser('summary')
    s.add_argument('results', nargs='+')
    a = ap.parse_args()
    return cmd_run(a) if a.cmd == 'run' else cmd_summary(a)


if __name__ == '__main__':
    sys.exit(main() or 0)
