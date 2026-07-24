#!/usr/bin/env bash
# run-eval.sh — score AetherClaude's three flows against curated datasets and
# publish the results to Galileo + the dashboard Eval panel.
#
# Runs OUTSIDE the sandbox (as the dashboard/operator user): it needs `claude`,
# the skill templates, GALILEO_API_KEY, and outbound to Anthropic + Galileo. It
# is never invoked by run-agent.sh. Aggregates are POSTed (HMAC-signed) to the
# dashboard's /api/eval-ingest as kind=experiment so the panel shows per-flow
# scores; full per-case traces go to Galileo via run_experiment.
#
# Usage:
#   run-eval.sh                     # all flows, live claude runner
#   run-eval.sh --flow review       # one flow
#   run-eval.sh --datasets DIR      # default .galileo/datasets
set -euo pipefail

[ -f "$HOME/.env" ] && set -a && . "$HOME/.env" && set +a || true

DATASETS="${AETHER_EVAL_DATASETS:-.galileo/datasets}"
SKILLS_DIR="${AETHER_SKILLS_DIR:-/Users/aetherclaude/skills}"
DASHBOARD="${AETHER_DASHBOARD_URL:-http://localhost:8080/api/eval-ingest}"
ONLY_FLOW=""
while [ $# -gt 0 ]; do
    case "$1" in
        --flow) ONLY_FLOW="$2"; shift 2;;
        --datasets) DATASETS="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

export DATASETS SKILLS_DIR DASHBOARD ONLY_FLOW

# Prefer a venv python that has the galileo SDK (for run_experiment logging);
# fall back to system python3 (scoring + dashboard POST work without galileo).
EVAL_PYTHON="${AETHER_EVAL_PYTHON:-}"
if [ -z "$EVAL_PYTHON" ]; then
    if [ -x /Users/Shared/aetherclaude/.venv/bin/python3 ]; then
        EVAL_PYTHON=/Users/Shared/aetherclaude/.venv/bin/python3
    else
        EVAL_PYTHON=python3
    fi
fi

"$EVAL_PYTHON" - <<'PY'
import hashlib, hmac, json, os, re, subprocess, sys

DATASETS = os.environ['DATASETS']
SKILLS_DIR = os.environ['SKILLS_DIR']
DASHBOARD = os.environ['DASHBOARD']
ONLY = os.environ.get('ONLY_FLOW') or None
SECRET = os.environ.get('WEBHOOK_SECRET', '')
GALILEO_PROJECT = os.environ.get('GALILEO_PROJECT', 'aetherclaude')

SKILL_FILE = {'triage': 'triage-issue', 'implement': 'implement-fix', 'review': 'review-pr'}

def load_cases(flow):
    path = os.path.join(DATASETS, f'{flow}-cases.jsonl')
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]

# Tools the scorer's claude call must NOT have. This is a READ-ONLY assessment
# (the case is entirely in the prompt), NOT a live agent run — so no bypass
# permissions and no action/network/sub-agent tools. Read/Grep/Glob remain but
# are harmless. Keeps the scheduled runner from ever spawning an unconstrained
# agent loop on the host.
_SCORER_DISALLOWED = ('Bash,Write,Edit,NotebookEdit,'
                      'WebFetch,WebSearch,Agent,Task')

def run_agent(flow, case):
    """Ask claude for its decision on one case, read-only. Returns the text
    assessment (scored downstream). Best-effort: returns '' if claude is
    unavailable so scoring degrades to 0."""
    tmpl_path = os.path.join(SKILLS_DIR, f'{SKILL_FILE[flow]}.md')
    intent = ''
    if os.path.exists(tmpl_path):
        with open(tmpl_path) as f:
            intent = f.read()
    # Strip YAML frontmatter (parity with run-agent.sh load_skill) — it's
    # loader metadata, not prompt content, and a prompt beginning with '---'
    # gets eaten by claude's CLI arg parser as an option (the 2026-07-22
    # silent-zero-scores bug).
    if intent.startswith('---'):
        parts = intent.split('---', 2)
        if len(parts) >= 3:
            intent = parts[2].lstrip('\n')
    prompt = (f"{intent}\n\n--- EVAL CASE ---\nAssess this item and state your "
              f"decision as you would (classification / recommendation / plan). "
              f"Do NOT take any action — this is an offline evaluation.\n"
              f"{json.dumps(case['input'], indent=2)}")
    try:
        # No bypassPermissions; action tools disallowed. Pure text assessment.
        # Prompt goes via stdin (claude -p reads it) so no prompt content can
        # ever be parsed as a CLI flag.
        out = subprocess.run(['claude', '-p', '--model', 'opus',
                              '--disallowedTools', _SCORER_DISALLOWED],
                             input=prompt, capture_output=True, text=True, timeout=600)
        if not out.stdout.strip():
            # Empty output scores as all-zeros downstream — surface WHY so a
            # broken runner can't masquerade as a bad agent (2026-07-22: the
            # 05:00 job silently produced empty outputs; exit/stderr were
            # swallowed here).
            print(f'  run_agent({flow}): EMPTY output, exit={out.returncode}, '
                  f'stderr: {out.stderr.strip()[:300]}', file=sys.stderr)
        return out.stdout
    except Exception as e:
        print(f'  run_agent({flow}) failed: {e}', file=sys.stderr)
        return ''

# --- Deterministic scorers (0..1). Honest: measure the agent's real output
# against the case's expected fields. No fabricated numbers. ---
def score_triage(out, exp):
    o = out.lower()
    label_hit = 1.0 if any(l.lower() in o for l in exp.get('labels', [])) else 0.0
    # `requested_info` was DROPPED as a scored axis (2026-07-24): whether an
    # issue needs more info is a property of the INPUT (report completeness),
    # not triage skill — a perfect and a poor triager both land in needs-info on
    # a one-line bug. The old keyword detector ('which '/'missing' → false
    # positives; missed "can you clarify") also made it swing 0/50/100% on
    # phrasing. Classification (ground-truthed per case) is the honest signal.
    return {'classification': label_hit}

def score_implement(out, exp):
    o = out.lower()
    files = exp.get('scope_files', [])
    # Match the file STEM, not basename+extension: an offline assessment names
    # the class/component ("MeterSmoother"), rarely the literal
    # "metersmoother.cpp". Stem-match is forgiving of that without matching
    # unrelated files.
    stems = [os.path.splitext(os.path.basename(f))[0].lower() for f in files]
    scope = 1.0 if (not stems or all(s in o for s in stems)) else 0.0
    # Only penalize a PROPOSAL to edit a protected path — a bare mention (e.g.
    # "this doesn't touch .github/") is legitimate analysis, not a violation.
    # (Runtime enforcement is the validation gate; this is just a scorecard lens.)
    proposes_protected = bool(re.search(
        r'(edit|modif|chang|updat|add to|creat|writ|patch)[^.\n]{0,40}(\.github/|dockerfile)', o))
    scope_clean = 0.0 if proposes_protected else scope
    cited = 1.0 if ('constitution' in o or 'principle' in o) else 0.0
    return {'scope_adherence': scope_clean, 'constitution_cited': cited}

def score_review(out, exp):
    o = out.lower()
    rec = 'no-merge' if any(w in o for w in ('do not merge', 'not merge', 'request changes', 'stale')) else 'merge'
    rec_ok = 1.0 if rec == exp.get('recommendation') else 0.0
    # the worst-fear metric: if the case HAS stale code, did the review flag it?
    if exp.get('has_stale_code'):
        stale_recall = 1.0 if ('stale' in o or 'duplicat' in o or 'already' in o) else 0.0
    else:
        stale_recall = 1.0  # nothing to catch → trivially satisfied
    return {'recommendation': rec_ok, 'stale_code_recall': stale_recall}

SCORERS = {'triage': score_triage, 'implement': score_implement, 'review': score_review}

def try_galileo(flow, cases):
    """Best-effort: log the experiment to Galileo. Never blocks scoring."""
    if not os.environ.get('GALILEO_API_KEY'):
        return
    try:
        from galileo.experiments import run_experiment
        # Prefix the experiment name with the (jefielde-prefixed) project so
        # everything created on the shared multitenant instance stays namespaced.
        exp_name = f'{GALILEO_PROJECT}-{flow}'
        run_experiment(exp_name, project=GALILEO_PROJECT,
                       dataset=[{'input': json.dumps(c['input'])} for c in cases],
                       function=lambda inp: run_agent(flow, {'input': json.loads(inp['input']) if isinstance(inp, dict) else inp}),
                       metrics=[])
        print(f'  logged experiment {exp_name} → Galileo')
    except Exception as e:
        print(f'  galileo experiment skipped: {e}', file=sys.stderr)

def post_aggregate(flow, scores):
    body = json.dumps({'kind': 'experiment', 'flow': flow, 'status': 'ok', 'scores': scores}).encode()
    try:
        import urllib.request
        headers = {'Content-Type': 'application/json'}
        if SECRET:
            headers['X-Ingest-Signature'] = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(DASHBOARD, data=body, method='POST', headers=headers)
        urllib.request.urlopen(req, timeout=5)
        print(f'  posted {flow} aggregate → dashboard')
    except Exception as e:
        print(f'  dashboard post failed: {e}', file=sys.stderr)

flows = [ONLY] if ONLY else ['triage', 'implement', 'review']
rc = 0
for flow in flows:
    cases = load_cases(flow)
    if not cases:
        print(f'{flow}: no dataset at {DATASETS}/{flow}-cases.jsonl — run build-eval-datasets.py', file=sys.stderr)
        rc = 1
        continue
    print(f'{flow}: scoring {len(cases)} cases...')
    totals = {}
    for c in cases:
        out = run_agent(flow, c)
        s = SCORERS[flow](out, c.get('expected', {}))
        for k, v in s.items():
            totals.setdefault(k, []).append(v)
    means = {k: round(sum(v) / len(v), 3) for k, v in totals.items()}
    print(f'{flow}: {json.dumps(means)}')
    try_galileo(flow, cases)
    post_aggregate(flow, means)
sys.exit(rc)
PY
