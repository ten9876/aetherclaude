"""Tests for validate-diff.sh's CodeGuard gate (check 7).

Run: python3 tests/test_validate_codeguard_gate.py

The gate blocks on HIGH/CRITICAL findings from the CodeGuard rules (CG-*)
only. DefenseClaw's guardrail content patterns (CS-*) read C++ `|`, `&&` and
backticks as shell injection; on 2026-11-12 24 of them blocked issue #7211's
fix. They must be logged, not block.
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/validate-diff.sh').read_text()
BLOCK = re.search(r"^CG_BLOCKING=.*?^else\n.*?^fi$", SCRIPT, re.M | re.S).group()


def finding(rule, severity='CRITICAL'):
    return {'id': rule, 'severity': severity, 'title': 't', 'file': 'src/x.cpp', 'location': 'src/x.cpp:1'}


def run_gate(findings):
    with tempfile.TemporaryDirectory(prefix='cg-gate-') as tmp:
        scanner = Path(tmp) / 'scan'
        scanner.write_text('#!/bin/sh\ncat <<\'EOF\'\n' + json.dumps({'findings': findings, 'errors': []})
                           + '\nEOF\n')
        scanner.chmod(0o755)
        script = '\n'.join(['set -u', 'ERRORS=0', 'WORKSPACE=.', 'log() { echo "LOG: $1"; }',
                            f'CODEGUARD_SCAN_BIN={scanner}', BLOCK, 'echo "ERRORS=$ERRORS"'])
        r = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True, timeout=10)
        return r.stdout


class CodeGuardGateTests(unittest.TestCase):
    def test_cs_patterns_warn_but_do_not_block(self):
        out = run_gate([finding('CS-VLN-CMDI-PIPE')] * 3 + [finding('CS-VLN-CMDI-AMP')])
        self.assertIn('ERRORS=0', out)
        self.assertIn('4 HIGH/CRITICAL non-CodeGuard', out)
        self.assertIn('CS-VLN-CMDI-AMP x1, CS-VLN-CMDI-PIPE x3', out)
        self.assertNotIn('BLOCKED', out)

    def test_codeguard_high_blocks_and_is_listed(self):
        out = run_gate([finding('CG-CRED-001', 'HIGH'), finding('CS-VLN-CMDI-PIPE')])
        self.assertIn('ERRORS=1', out)
        self.assertIn('BLOCKED: CodeGuard found 1 HIGH/CRITICAL', out)
        self.assertIn('CG-CRED-001 [HIGH]', out)
        self.assertNotIn('CS-VLN-CMDI-PIPE [', out)

    def test_codeguard_medium_and_missing_id_do_not_block(self):
        out = run_gate([finding('CG-PATH-001', 'MEDIUM'), {'severity': 'CRITICAL'}])
        self.assertIn('ERRORS=0', out)
        self.assertIn('MEDIUM finding(s)', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
