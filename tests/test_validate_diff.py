"""Exercise the real validation gate in disposable Git repositories.

Run: python3 tests/test_validate_diff.py
Only deployment paths are relocated; policy checks run unchanged. CodeGuard
responses are injected to test gate enforcement, not the external scanner.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


GATE = Path(__file__).resolve().parents[1] / 'bin' / 'validate-diff.sh'


class ValidateDiffTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.deployment = self.root / 'deployment'
        (self.deployment / 'logs').mkdir(parents=True)
        self.gate = self.root / 'gate.sh'
        self.gate.write_text(GATE.read_text().replace('/Users/aetherclaude', str(self.deployment)))
        self.scanner = self.root / 'codeguard.sh'
        self.scanner.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_CODEGUARD_JSON"\n')
        self.scanner.chmod(0o755)
        self.git('init', '-q', '-b', 'main')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'baseline')

    def git(self, *args):
        subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True)

    def run_gate(self, path, content='benign fixture\n', findings=None, secret=None):
        # Restore the disposable baseline so each subtest contains one diff.
        self.git('reset', '--hard', '-q', 'main')
        self.git('clean', '-fdq')
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git('add', '--', path)
        log = self.deployment / 'logs' / 'validation.log'
        log.write_text('')
        envfile = self.deployment / '.env'
        envfile.write_text('TEST_TOKEN=' + secret + '\n' if secret else '')
        env = dict(os.environ, CODEGUARD_SCAN_BIN=str(self.scanner),
                   TEST_CODEGUARD_JSON=json.dumps({'findings': findings or []}))
        bash = shutil.which('bash')
        result = subprocess.run([bash, str(self.gate), str(self.repo)], env=env,
                                capture_output=True, text=True, timeout=20)
        return result.returncode, log.read_text()

    def test_exact_paths(self):
        for path in ('cmake/AetherBuildIdentity.cmake', 'cmake/AetherQtPin.cmake',
                     'src/fixture.cpp', 'tests/fixture.cpp', 'CMakeLists.txt'):
            with self.subTest(path=path):
                code, log = self.run_gate(path)
                self.assertEqual(code, 0, log)
                self.assertIn('PASSED:', log)
        for path in ('cmake/Other.cmake', 'cmake/qt-pin.env',
                     'cmake/AetherBuildIdentity.cmake.extra',
                     'cmake/nested/AetherQtPin.cmake', 'arbitrary.txt'):
            with self.subTest(path=path):
                code, log = self.run_gate(path)
                self.assertEqual(code, 1, log)
                self.assertIn('File outside allowed directories:', log)

    def test_protected_paths(self):
        for path in ('.github/workflows/test.yml', 'scripts/test.sh',
                     'CLAUDE.md', 'Dockerfile', 'src/setup-fixture.cpp'):
            with self.subTest(path=path):
                code, log = self.run_gate(path)
                self.assertEqual(code, 1, log)
                self.assertIn('Protected file modified:', log)

    def test_credentials_in_admitted_module(self):
        # Synthetic shape only; this is not an issued credential.
        code, log = self.run_gate('cmake/AetherBuildIdentity.cmake',
                                 '# ghp_' + 'A' * 36 + '\n')
        self.assertEqual(code, 1, log)
        self.assertIn('Credential pattern found', log)

    def test_literal_secret_in_admitted_module(self):
        secret = 'synthetic-validator-fixture-value'
        code, log = self.run_gate('cmake/AetherQtPin.cmake', '# ' + secret + '\n', secret=secret)
        self.assertEqual(code, 1, log)
        self.assertIn('literal value of TEST_TOKEN', log)
        self.assertNotIn(secret, log)

    def test_binary_is_rejected(self):
        code, log = self.run_gate('src/fixture.dll')
        self.assertEqual(code, 1, log)
        self.assertIn('Binary file addition:', log)

    def test_codeguard_high_and_critical_block(self):
        for severity in ('HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                code, log = self.run_gate('cmake/AetherBuildIdentity.cmake', findings=[
                    {'severity': severity, 'id': 'fixture', 'title': 'injected gate response',
                     'file': 'cmake/AetherBuildIdentity.cmake'}])
                self.assertEqual(code, 1, log)
                self.assertIn('CodeGuard found 1 HIGH/CRITICAL', log)

    def test_codeguard_medium_remains_warning(self):
        code, log = self.run_gate('cmake/AetherQtPin.cmake', findings=[{'severity': 'MEDIUM'}])
        self.assertEqual(code, 0, log)
        self.assertIn('WARNING: CodeGuard found 1 MEDIUM', log)

    def test_suspicious_pattern_remains_warning(self):
        code, log = self.run_gate('cmake/AetherQtPin.cmake', '# QSettings\n')
        self.assertEqual(code, 0, log)
        self.assertIn('WARNING: Suspicious pattern', log)


if __name__ == '__main__':
    unittest.main(verbosity=2)
