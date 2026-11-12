"""Tests for run-agent.sh's per-issue implement lock and the closing sweep.

Run: python3 tests/test_implement_lock.py

On 2026-11-12 issue #7211 lost three implement attempts in a row: every
orchestrator run ended by deleting /tmp/aetherclaude/issue-*, and CI-triggered
runs restarted an implementation another run was still working on. The
invariant: only one live run implements an issue, a dead holder releases
the lock, and the sweep leaves a live holder's worktree alone.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/run-agent.sh').read_text()
BASH = shutil.which('bash')


def shell_function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SCRIPT, re.M | re.S)
    if not match:
        raise AssertionError('Missing shell function: ' + name)
    return match.group()


def lock_functions(lock_dir):
    one_liner = re.search(r'^implement_lock_file\(\) \{.*\}$', SCRIPT, re.M).group()
    return '\n'.join([f'IMPLEMENT_LOCK_DIR={lock_dir}', one_liner,
                      shell_function('implement_lock_holder'),
                      shell_function('implement_lock_acquire')])


def sweep(worktree_root):
    block = re.search(r'^for _wt in /tmp/aetherclaude/issue-\*; do\n.*?^done$', SCRIPT, re.M | re.S)
    if not block:
        raise AssertionError('Missing closing worktree sweep')
    return block.group().replace('/tmp/aetherclaude/issue-*', f'{worktree_root}/issue-*')


class ImplementLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='impl-lock-'))
        self.funcs = lock_functions(self.tmp)
        self.holders = []

    def tearDown(self):
        for p in self.holders:
            p.kill()
            p.wait()
        shutil.rmtree(self.tmp)

    def bash(self, body):
        return subprocess.run([BASH, '-c', 'set -euo pipefail\n' + self.funcs + '\n' + body],
                              capture_output=True, text=True, timeout=10)

    def hold(self, number):
        """Start a live run that takes issue N's lock and stays alive."""
        ready = self.tmp / f'ready-{number}-{len(self.holders)}'
        p = subprocess.Popen([BASH, '-c', self.funcs + f'\nimplement_lock_acquire {number} && '
                              f'echo ok > {ready}; exec sleep 30'])
        self.holders.append(p)
        for _ in range(200):
            if ready.exists():
                return p
            subprocess.run(['sleep', '0.02'])
        self.fail('holder never took the lock')

    def test_second_run_is_refused_while_holder_lives(self):
        holder = self.hold(7211)
        r = self.bash('if implement_lock_acquire 7211; then echo got; else echo refused; fi; '
                      'implement_lock_holder 7211')
        self.assertEqual(r.stdout.split(), ['refused', str(holder.pid)])

    def test_dead_holder_releases_the_lock(self):
        holder = self.hold(7211)
        holder.kill()
        holder.wait()
        r = self.bash('implement_lock_acquire 7211 && echo got; '
                      '[ "$(cat ' + str(self.tmp) + '/aetherclaude-implement-7211.lock)" = "$$" ] && echo mine')
        self.assertEqual(r.stdout.split(), ['got', 'mine'])

    def test_same_run_can_reacquire_and_other_issues_are_free(self):
        self.hold(7225)
        r = self.bash('implement_lock_acquire 7211 && implement_lock_acquire 7211 && echo again')
        self.assertEqual(r.stdout.split(), ['again'])

    def test_sweep_keeps_live_holders_worktree_only(self):
        wt = self.tmp / 'wt'
        for n in (7211, 7225, 7300):
            (wt / f'issue-{n}').mkdir(parents=True)
        self.hold(7211)                                   # another live run
        dead = self.hold(7300)                            # a run that died
        dead.kill()
        dead.wait()
        r = self.bash('implement_lock_acquire 7225\n' + sweep(wt))   # this run's own
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(p.name for p in wt.iterdir()), ['issue-7211'])

    def test_implement_state_takes_the_lock_before_touching_the_worktree(self):
        body = SCRIPT[SCRIPT.index('        implement)\n'):]
        lock_at = body.index('implement_lock_acquire "$number"')
        self.assertLess(lock_at, body.index('rm -rf "$WORKTREE"'))
        self.assertLess(lock_at, body.index('git -C "$WORKSPACE" worktree add'))
        self.assertNotIn('rm -rf /tmp/aetherclaude/issue-*', SCRIPT)


if __name__ == '__main__':
    unittest.main(verbosity=2)
