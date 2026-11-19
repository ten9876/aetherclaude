"""Tests for the skill-template renderer in bin/run-agent.sh and
bin/batch-triage.sh (substitute_vars / render_skill / render_skill_full).

Run: python3 tests/test_render_skill.py

The function definitions are extracted from each script and run under
the local bash (5.2+ is what makes "&" in a ${t//pat/rep} replacement
expand to the match), so these tests exercise the shipped code.

Covers:
  - "&", "\\&" and "\\1" in a value are inserted verbatim
  - a value containing another placeholder is not expanded again
  - unknown and malformed placeholders are left as written
  - a value can be empty, and the same placeholder can appear twice
  - render_skill_full substitutes the goal line as well as the body
"""
import os
import re
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_BIN = os.path.join(_HERE, '..', 'bin')
BASH = os.environ.get('BASH_BIN', 'bash')


def _function(src, name):
    m = re.search(r'^%s\(\) \{\n.*?^\}\n' % re.escape(name), src, re.S | re.M)
    assert m, f'{name} not found'
    return m.group(0)


def _defs(script, names):
    with open(os.path.join(_BIN, script)) as fh:
        src = fh.read()
    return '\n'.join(_function(src, n) for n in names)


RUN_AGENT = _defs('run-agent.sh', ['substitute_vars', 'render_skill',
                                   'read_skill_goal', 'render_skill_full'])
BATCH = _defs('batch-triage.sh', ['substitute_vars', 'render_skill'])


def render(defs, template, *pairs, fn='render_skill', extra=''):
    script = defs + '\n' + extra + '\nprintf "%s" "$(' + fn + ' "$@")"\n'
    out = subprocess.run([BASH, '-c', script, 'render', template, *pairs],
                         capture_output=True, text=True, check=True)
    return out.stdout


failures = []


def check(label, got, want):
    if got != want:
        failures.append(f'{label}: got {got!r}, want {want!r}')


T = 'Body: ${ISSUE_BODY}\nComments: ${ISSUE_COMMENTS}\nN=${ISSUE_NUMBER}'
for name, defs in (('run-agent', RUN_AGENT), ('batch-triage', BATCH)):
    check(f'{name} ampersand',
          render(defs, T, 'ISSUE_BODY', 'Radio model & firmware; OS \\& \\1',
                 'ISSUE_COMMENTS', 'c', 'ISSUE_NUMBER', '7383'),
          'Body: Radio model & firmware; OS \\& \\1\nComments: c\nN=7383')
    check(f'{name} no re-expansion',
          render(defs, T, 'ISSUE_BODY', 'see ${ISSUE_COMMENTS} and ${ISSUE_NUMBER}',
                 'ISSUE_COMMENTS', 'SECRET', 'ISSUE_NUMBER', '1'),
          'Body: see ${ISSUE_COMMENTS} and ${ISSUE_NUMBER}\nComments: SECRET\nN=1')
    check(f'{name} unknown and malformed',
          render(defs, 'a ${UNKNOWN} b ${ not a var} c ${ISSUE_NUMBER} d ${open',
                 'ISSUE_NUMBER', '5'),
          'a ${UNKNOWN} b ${ not a var} c 5 d ${open')
    check(f'{name} empty value, repeated placeholder',
          render(defs, '[${X}] [${X}] [${Y}]', 'X', '', 'Y', '$HOME `id`'),
          '[] [] [$HOME `id`]')

with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, 'Users/aetherclaude/skills'))
    goal_defs = RUN_AGENT.replace('/Users/aetherclaude/skills', d + '/Users/aetherclaude/skills')
    with open(os.path.join(d, 'Users/aetherclaude/skills/demo.md'), 'w') as fh:
        fh.write('---\ngoal: comment posted on #${PR_NUMBER}\n---\nReview ${PR_NUMBER}: ${PR_TITLE}\n')
    extra = ('load_skill() { awk \'/^---$/{c++; next} c >= 2\' "%s/Users/aetherclaude/skills/$1.md"; }'
             % d)
    got = render(goal_defs, 'demo', 'PR_NUMBER', '42', 'PR_TITLE', 'A & B',
                 fn='render_skill_full', extra=extra)
    check('render_skill_full', got,
          'Review 42: A & B\n\n---\n\nCOMPLETION REQUIREMENT — do not end your turn '
          'until this holds: comment posted on #42')

for f in failures:
    print('FAIL', f)
print(f'{"FAILED" if failures else "ok"}: {len(failures)} failure(s)')
sys.exit(1 if failures else 0)
