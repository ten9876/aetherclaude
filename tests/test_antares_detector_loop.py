"""Unit tests for antares-detector.py's prompt rendering and loop control.

Run: python3 tests/test_antares_detector_loop.py
Exits non-zero on any failure with a one-line summary per case.

The invariants under test: the prompt is byte-identical to the model's own
chat template (config/antares/chat_template.jinja) rendered the way
transformers renders it, and the loop never charges the budget for a
repeated command or a rejected reply, closes the terminal instead of
running past the budget, and ends every run with a verdict.

Covers:
  - render_prompt == the Granite template for system + user, terminal and
    submit tool calls, consecutive tool responses (skipped without jinja2)
  - earlier turns are replayed as tool calls only, without their <think>
  - a repeated command is answered from the first run and not charged;
    three repeats in a row close the terminal; a terminal call after that
    is refused, and the run ends budget_exhausted after three such turns
  - the budget notice comes once at 80% of the budget; the terminal closes
    at the budget and a submission after that is accepted
  - the unread-search-hit notice appears while a search hit is unopened and
    names no file; it stops once the file is read
  - runaway repetition is rejected uncharged; three in a row end the run
  - candidates that are not files in the snapshot are dropped (and
    recorded); a ':line' / ':function' suffix or './' prefix is removed;
    nothing left → verdict no_candidates
  - submit_vulnerable_files{ranked_files} yields candidates and a rationale
    taken from the reasoning when there is no prose; a '<tool_call>' inside
    <think> is not taken as the call
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    'antares_detector', os.path.join(HERE, '..', 'bin', 'antares-detector.py'))
det = importlib.util.module_from_spec(spec)
spec.loader.exec_module(det)
TEMPLATE = os.path.join(HERE, '..', 'config', 'antares', 'chat_template.jinja')

failures = []


def check(name, cond, detail=''):
    if not cond:
        failures.append(name)
        print(f'FAIL {name}{(" — " + str(detail)) if detail else ""}')


def call(name, **arguments):
    return ('<think>\nreasoning about it\n</think>\n<tool_call>\n'
            + json.dumps({'name': name, 'arguments': arguments}) + '\n</tool_call>')


class Script:
    """Stands in for generate(): replays replies, records the prompts."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, prompt, timeout=None):
        self.prompts.append(prompt)
        return self.replies.pop(0) if self.replies else call('submit_no_vulnerability_found')


def run(replies, max_commands=15):
    script = Script(replies)
    real_gen, real_carto = det.generate, det.cartographer_slice
    det.generate, det.cartographer_slice = script, (lambda cwe: '')
    try:
        return det.localize(repo, 'CWE-787', 'packet parser crash', max_commands), script
    finally:
        det.generate, det.cartographer_slice = real_gen, real_carto


def last_tool_response(prompt):
    return prompt.rsplit('<tool_response>\n', 1)[1].split('\n</tool_response>', 1)[0]


repo = tempfile.mkdtemp(prefix='antares-loop-')
try:
    os.makedirs(os.path.join(repo, 'src'))
    for name in ('a.cpp', 'b.cpp'):
        with open(os.path.join(repo, 'src', name), 'w') as fh:
            fh.write('void f(char *d, const char *s, int n) { memcpy(d, s, n); }\n')

    # -- rendering against the model's template ------------------------------
    msgs = det.build_messages('CWE-787', 'issue text', 'map', 15)
    msgs += [{'role': 'assistant', 'content': '',
              'tool_calls': [{'name': 'terminal', 'arguments': {'command': 'ls src'}}]},
             {'role': 'tool', 'content': 'exit=0\na.cpp\nb.cpp'},
             {'role': 'tool', 'content': 'exit=0\nsecond'},
             {'role': 'assistant', 'content': '',
              'tool_calls': [{'name': 'submit_vulnerable_files',
                              'arguments': {'ranked_files': ['src/a.cpp']}}]},
             {'role': 'user', 'content': 'nudge'}]
    try:
        import jinja2
    except ImportError:
        jinja2 = None
        print('SKIP template comparison (jinja2 not installed)')
    if jinja2:
        env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True,
                                 extensions=['jinja2.ext.loopcontrols'])
        env.filters['tojson'] = lambda x, ensure_ascii=False, indent=None, separators=None, \
            sort_keys=False: json.dumps(x, ensure_ascii=ensure_ascii, indent=indent,
                                        separators=separators, sort_keys=sort_keys)
        with open(TEMPLATE) as fh:
            tmpl = env.from_string(fh.read())
        hf_msgs = []
        for m in msgs:
            m = dict(m)
            if m.get('tool_calls'):
                m['tool_calls'] = [{'type': 'function', 'function': {
                    'name': c['name'], 'arguments': json.dumps(c['arguments'])}}
                    for c in m['tool_calls']]
            hf_msgs.append(m)
        want = tmpl.render(messages=hf_msgs, tools=det.TOOLS, add_generation_prompt=True)
        got = det.render_prompt(msgs)
        check('render_prompt matches the model chat template', got == want,
              next((f'first diff at {i}: {got[i:i+60]!r} vs {want[i:i+60]!r}'
                    for i in range(min(len(got), len(want))) if got[i] != want[i]),
                   f'len {len(got)} vs {len(want)}'))

    # -- duplicates ----------------------------------------------------------
    res, sc = run([call('terminal', command='ls src')] * 4 + [call('terminal', command='cat src/a.cpp')]
                  + [call('submit_vulnerable_files', ranked_files=['src/a.cpp'])])
    check('first run charged, repeats not', res['commands_used'] == 1, res['commands_used'])
    check('three repeats close the terminal', res['forced_submission'] and res['duplicates_suppressed'] == 3,
          res)
    check('terminal refused after close', 'terminal is closed' in last_tool_response(sc.prompts[-1]),
          last_tool_response(sc.prompts[-1]))
    check('submission after close accepted', res['verdict'] == 'vulnerable'
          and res['candidates'] == ['src/a.cpp'], res['verdict'])
    check('history replays tool calls without reasoning',
          'reasoning about it' not in sc.prompts[-1] and sc.prompts[-1].count('<tool_call>\n{"name": "terminal"') >= 4)
    check('duplicate response repeats the first output', 'already run at turn 1' in sc.prompts[2]
          and 'a.cpp' in last_tool_response(sc.prompts[2]))

    res, sc = run([call('terminal', command='ls src')] * 4 + [call('terminal', command='pwd')] * 4)
    check('unsubmitted after three closed turns → budget_exhausted', res['verdict'] == 'budget_exhausted',
          res['verdict'])

    # -- budget --------------------------------------------------------------
    cmds = [call('terminal', command=f'echo {i}') for i in range(5)]
    res, sc = run(cmds + [call('submit_no_vulnerability_found')], max_commands=5)
    notices = [p.count(det.BUDGET_NOTICE) for p in sc.prompts]
    check('budget notice once at 80%', notices[4] == 1 and notices[3] == 0 and notices[-1] == 1, notices)
    check('terminal closes at the budget', det.CLOSED_NOTICE in last_tool_response(sc.prompts[5]))
    check('clean after the budget', res['verdict'] == 'clean' and res['commands_used'] == 5, res['verdict'])

    # -- unread search hits --------------------------------------------------
    res, sc = run([call('terminal', command='grep -rn memcpy src'),
                   call('terminal', command='cat src/a.cpp'),
                   call('terminal', command='cat src/b.cpp'),
                   call('submit_vulnerable_files', ranked_files=['src/a.cpp', 'src/b.cpp'])])
    r1, r2, r3 = (last_tool_response(sc.prompts[i]) for i in (1, 2, 3))
    check('unread notice after a search', det.UNREAD_NOTICE in r1 and 'src/' not in det.UNREAD_NOTICE)
    check('unread notice while one hit is unopened', det.UNREAD_NOTICE in r2)
    check('no unread notice once all hits are read', det.UNREAD_NOTICE not in r3, r3)
    check('exit code in tool response', r1.startswith('exit=0\n'), r1[:20])

    # -- degenerate repetition ----------------------------------------------
    loop = '<think>\n' + ' '.join(['the buffer is copied here again'] * 30)
    res, sc = run([loop, call('terminal', command='ls src'), loop, loop, loop])
    check('degenerate reply rejected uncharged', res['degenerate_rejections'] == 4
          and res['commands_used'] == 1, res)
    check('three degenerate replies in a row end the run', res['verdict'] == 'degenerate', res['verdict'])
    check('ordinary reply is not degenerate', not det.is_degenerate(call('terminal', command='ls')))

    # -- parsing and rationale ----------------------------------------------
    reply = ('<think>\nI could run <tool_call>{"name": "terminal", "arguments": {"command": "ls"}}'
             ' but memcpy in src/a.cpp copies n bytes from the packet: CWE-787.\n</think>\n'
             '<tool_call>\n{"name": "submit_vulnerable_files", "arguments": '
             '{"ranked_files": ["src/a.cpp"]}}\n</tool_call>')
    name, args = det.parse_tool_call(reply)
    check('call after </think> wins over one inside it', name == 'submit_vulnerable_files', name)
    res, _ = run([call('terminal', command='cat src/a.cpp'), reply])
    check('rationale from the reasoning', 'CWE-787' in res.get('rationale', ''), res.get('rationale'))

    res, _ = run([call('terminal', command='ls src'),
                  call('submit_vulnerable_files', ranked_files=[
                      'src/pcap_parser.cpp', 'src/a.cpp:12', './src/b.cpp', 'src/a.cpp:f',
                      'tests/test_x.cpp'])])
    check('invented paths dropped, suffixes removed', res['candidates'] == ['src/a.cpp', 'src/b.cpp']
          and res['dropped_candidates'] == ['src/pcap_parser.cpp', 'tests/test_x.cpp'], res)
    res, _ = run([call('terminal', command='ls src'),
                  call('submit_vulnerable_files', ranked_files=['src/nope.cpp'])])
    check('only invented paths → no_candidates', res['verdict'] == 'no_candidates'
          and res['candidates'] == [], res['verdict'])
finally:
    shutil.rmtree(repo, ignore_errors=True)

if failures:
    print(f'{len(failures)} failure(s)')
    sys.exit(1)
print('all antares-detector loop checks passed')
