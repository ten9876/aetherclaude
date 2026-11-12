"""Tests for keeping committed work when the watchdog stops an implement run.

Run: python3 tests/test_implement_watchdog_commits.py

On 2026-11-12 issue #6972's run committed its fix, went quiet for three
minutes (its closing summary), and the stall watchdog killed it; the
orchestrator then failed the issue and deleted the commit. Invariant: a
watchdog stop after at least one commit continues to validation with a
clean tree; any other failure, or a stop before any commit, still fails.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/run-agent.sh').read_text()
BLOCK = re.search(r'^            local claude_ok=1\n.*?^            \}\n', SCRIPT, re.M | re.S).group()


def git(cwd, *args):
    subprocess.run(['git', '-C', str(cwd), *args], check=True, capture_output=True, text=True)


class WatchdogCommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='wd-commit-'))
        self.wt = self.tmp / 'wt'
        self.wt.mkdir()
        git(self.wt, 'init', '-q', '-b', 'main')
        git(self.wt, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'base')
        git(self.wt, 'checkout', '-q', '-b', 'aetherclaude/issue-1')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def commit(self):
        (self.wt / 'fix.cpp').write_text('fixed\n')
        git(self.wt, 'add', '-A')
        git(self.wt, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'fix (#1)')

    def run_block(self, rc, killed):
        stub = f'run_claude() {{ CLAUDE_WATCHDOG_KILLED={killed}; return {rc}; }}'
        script = '\n'.join([
            'set -euo pipefail', 'f() {', 'local number=1 issue_log=x codeguard_rules= prompt=p processed=0',
            f'local WORKTREE={self.wt} WORKSPACE={self.tmp} branch=aetherclaude/issue-1',
            'log() { echo "LOG: $1"; }', 'record_action() { :; }', 'set_state() { echo "STATE: $2"; }',
            'git() { if [ "$1" = worktree ] || [ "$1" = branch ]; then echo "GIT: $*"; else command git "$@"; fi; }',
            stub, 'while true; do', BLOCK, 'echo CONTINUED; break', 'done', '}', 'f'])
        r = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_watchdog_stop_after_commit_continues_with_clean_tree(self):
        self.commit()
        (self.wt / 'half.cpp').write_text('half-done\n')
        (self.wt / 'fix.cpp').write_text('edited after commit\n')
        out = self.run_block(1, 1)
        self.assertIn('CONTINUED', out)
        self.assertIn('stopped by the watchdog after committing', out)
        self.assertNotIn('STATE: failed', out)
        status = subprocess.run(['git', '-C', str(self.wt), 'status', '--porcelain'],
                                capture_output=True, text=True).stdout
        self.assertEqual(status, '')

    def test_watchdog_stop_without_commit_still_fails(self):
        out = self.run_block(1, 1)
        self.assertIn('STATE: failed', out)
        self.assertNotIn('CONTINUED', out)

    def test_other_failure_with_commit_still_fails(self):
        self.commit()
        out = self.run_block(1, 0)
        self.assertIn('STATE: failed', out)
        self.assertNotIn('CONTINUED', out)

    def test_success_continues(self):
        self.assertIn('CONTINUED', self.run_block(0, 0))

    def test_run_claude_flags_watchdog_kills_only(self):
        fn = re.search(r'^run_claude\(\) \{\n.*?^\}', SCRIPT, re.M | re.S).group()
        self.assertIn('    CLAUDE_WATCHDOG_KILLED=0\n', fn)
        kill_branch = fn[fn.index('if [ "$exit_code" -eq 143 ]'):]
        kill_branch = kill_branch[:kill_branch.index('return 1')]
        self.assertIn('CLAUDE_WATCHDOG_KILLED=1', kill_branch)


if __name__ == '__main__':
    unittest.main(verbosity=2)
