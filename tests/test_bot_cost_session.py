"""Unit tests for bot-cost.py's per-session usage attribution.

Run: python3 tests/test_bot_cost_session.py
Exits non-zero on any failure with a one-line summary per case.

Verifies the bug fix for cross-session token bleed: when --session-id
is passed, bot-cost.py must sum tokens ONLY from that session's JSONL
plus its subagents/, ignoring all other concurrent sessions written
to ~/.claude/projects/**.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
_HOOK_PATH = os.path.join(_HERE, '..', 'bin', 'bot-cost.py')

spec = importlib.util.spec_from_file_location('bot_cost', _HOOK_PATH)
bc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bc)


_FAILED = []

def _check(name, cond, detail=''):
    if cond:
        print('  PASS  ' + name)
    else:
        print('  FAIL  ' + name + (' — ' + detail if detail else ''))
        _FAILED.append(name)


def _write_usage_jsonl(path, records):
    """Write a sequence of {input, output, cache_read, cache_create, model}
    dicts as Claude Code-shaped assistant records."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        for r in records:
            line = {
                'type': 'assistant',
                'message': {
                    'model': r.get('model', 'claude-opus-4-7'),
                    'usage': {
                        'input_tokens': r.get('input', 0),
                        'output_tokens': r.get('output', 0),
                        'cache_read_input_tokens': r.get('cache_read', 0),
                        'cache_creation_input_tokens': r.get('cache_create', 0),
                    },
                },
            }
            fh.write(json.dumps(line) + '\n')


# Redirect the module's SESSION_ROOT to a tmpdir for the duration of the
# test. The reader uses SESSION_ROOT directly for the per-session glob,
# so this is a clean swap.
_TMP_ROOT = tempfile.mkdtemp(prefix='bot-cost-test-')
_ORIG_ROOT = bc.SESSION_ROOT
bc.SESSION_ROOT = _TMP_ROOT


def _project_dir(name='-project-foo'):
    d = os.path.join(_TMP_ROOT, name)
    os.makedirs(d, exist_ok=True)
    return d


try:
    # ── 1. Single-session scoping ────────────────────────────────────────
    print('\n[1] Single-session attribution')

    sid_a = str(uuid.uuid4())
    sid_b = str(uuid.uuid4())
    proj = _project_dir()
    # Session A: 2 records totaling 1000 in / 500 out
    _write_usage_jsonl(
        os.path.join(proj, sid_a + '.jsonl'),
        [{'input': 600, 'output': 300, 'cache_read': 100, 'cache_create': 50},
         {'input': 400, 'output': 200, 'cache_read': 50,  'cache_create': 25}])
    # Session B (concurrent): 1 huge record — must NOT leak into A
    _write_usage_jsonl(
        os.path.join(proj, sid_b + '.jsonl'),
        [{'input': 99999, 'output': 99999,
          'cache_read': 99999, 'cache_create': 99999}])

    model, totals = bc.read_usage_for_session(sid_a)
    _check('session A totals match A only (input)',
           totals['input_tokens'] == 1000,
           'got {}'.format(totals['input_tokens']))
    _check('session A totals match A only (output)',
           totals['output_tokens'] == 500,
           'got {}'.format(totals['output_tokens']))
    _check('session A totals match A only (cache_read)',
           totals['cache_read_input_tokens'] == 150,
           'got {}'.format(totals['cache_read_input_tokens']))
    _check('session A totals match A only (cache_create)',
           totals['cache_creation_input_tokens'] == 75,
           'got {}'.format(totals['cache_creation_input_tokens']))
    _check('session A picks up model from its records',
           model == 'claude-opus-4-7', 'got {}'.format(model))

    # Sanity: B's read sees only B's data, not contaminated by A.
    _, totals_b = bc.read_usage_for_session(sid_b)
    _check('session B totals match B only (no bleed from A)',
           totals_b['input_tokens'] == 99999)


    # ── 2. Sub-agent JSONLs roll into parent session's totals ───────────
    print('\n[2] Sub-agent inclusion')

    sid_c = str(uuid.uuid4())
    _write_usage_jsonl(
        os.path.join(proj, sid_c + '.jsonl'),
        [{'input': 100, 'output': 50}])
    # Sub-agent JSONLs under <project>/<sid_c>/subagents/agent-*.jsonl
    sub_dir = os.path.join(proj, sid_c, 'subagents')
    _write_usage_jsonl(
        os.path.join(sub_dir, 'agent-aaa.jsonl'),
        [{'input': 200, 'output': 75}])
    _write_usage_jsonl(
        os.path.join(sub_dir, 'agent-bbb.jsonl'),
        [{'input': 300, 'output': 100}])

    _, totals_c = bc.read_usage_for_session(sid_c)
    _check('parent + 2 sub-agents sum into one total (input)',
           totals_c['input_tokens'] == 600,
           'got {}'.format(totals_c['input_tokens']))
    _check('parent + 2 sub-agents sum into one total (output)',
           totals_c['output_tokens'] == 225,
           'got {}'.format(totals_c['output_tokens']))


    # ── 3. Missing session returns zero, never crashes ──────────────────
    print('\n[3] Missing session is zero, not error')

    sid_ghost = str(uuid.uuid4())
    model_g, totals_g = bc.read_usage_for_session(sid_ghost)
    _check('missing session returns all-zero totals',
           all(v == 0 for v in totals_g.values()))
    _check('missing session falls back to FALLBACK_MODEL',
           model_g == bc.FALLBACK_MODEL)


    # ── 4. Cross-project scoping: same UUID in different project dirs ──
    print('\n[4] Cross-project glob')

    sid_x = str(uuid.uuid4())
    proj1 = _project_dir('-proj-one')
    proj2 = _project_dir('-proj-two')
    _write_usage_jsonl(
        os.path.join(proj1, sid_x + '.jsonl'),
        [{'input': 10, 'output': 5}])
    _write_usage_jsonl(
        os.path.join(proj2, sid_x + '.jsonl'),
        [{'input': 20, 'output': 7}])
    _, totals_x = bc.read_usage_for_session(sid_x)
    # Both project dirs contribute — same UUID, two locations. This is
    # the documented behavior of the glob; UUIDs collide effectively
    # never (random v4), so the union is fine.
    _check('UUID hit across multiple project dirs sums all matches',
           totals_x['input_tokens'] == 30 and totals_x['output_tokens'] == 12,
           'got input={} output={}'.format(
               totals_x['input_tokens'], totals_x['output_tokens']))


    # ── 5. Records without usage are ignored ────────────────────────────
    print('\n[5] Skip non-usage records')

    sid_q = str(uuid.uuid4())
    path = os.path.join(proj, sid_q + '.jsonl')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        # No usage field — must be silently skipped.
        fh.write(json.dumps({'type': 'user', 'message': {'content': 'hi'}}) + '\n')
        # Junk line — must be silently skipped.
        fh.write('not json at all\n')
        # Real usage record.
        fh.write(json.dumps({
            'type': 'assistant',
            'message': {'model': 'claude-sonnet-4-6',
                        'usage': {'input_tokens': 42}},
        }) + '\n')
    model_q, totals_q = bc.read_usage_for_session(sid_q)
    _check('non-usage lines silently skipped, real one counted',
           totals_q['input_tokens'] == 42 and model_q == 'claude-sonnet-4-6')

finally:
    bc.SESSION_ROOT = _ORIG_ROOT
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


# ── Summary ─────────────────────────────────────────────────────────────
print('')
if _FAILED:
    print('FAILED: {} test(s)'.format(len(_FAILED)))
    for n in _FAILED:
        print('  - ' + n)
    sys.exit(1)
print('OK — all session-scoping tests pass')
