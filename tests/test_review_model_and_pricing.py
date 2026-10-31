"""Offline routing and API-equivalent cost checks.

Run: python3 tests/test_review_model_and_pricing.py
Only extracted functions run: no orchestrator startup, GitHub, model API,
dashboard server, credentials, or radio is used.
"""
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from contextlib import nullcontext
from datetime import datetime
import glob
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/run-agent.sh').read_text()

# USD/MTok: input, output, cache read, one-hour cache write. Verified
# 2026-10-31 against https://platform.claude.com/docs/en/about-claude/pricing.
EXPECTED_MODEL_RATES = {
    'claude-fable-5-1': (10, 50, .25, 20),
    'claude-opus-5-5': (4, 20, .20, 8),
    'claude-sonnet-5-5': (2, 10, .10, 4),
    'claude-haiku-5-5': (.10, .50, .01, .20),
    'claude-mythos-5-1': (10, 50, .25, 20),
    'claude-fable-5': (10, 50, 1, 20),
    'claude-mythos-5': (10, 50, 1, 20),
    'claude-opus-5': (5, 25, .50, 10),
    'claude-opus-4-8': (5, 25, .50, 10),
    'claude-opus-4-7': (5, 25, .50, 10),
    'claude-opus-4-6': (5, 25, .50, 10),
    'claude-opus-4-5': (5, 25, .50, 10),
    'claude-opus-4-1': (15, 75, 1.50, 30),
    'claude-opus-4': (15, 75, 1.50, 30),
    'claude-sonnet-5': (2, 10, .20, 4),
    'claude-sonnet-4-6': (3, 15, .30, 6),
    'claude-sonnet-4-5': (3, 15, .30, 6),
    'claude-sonnet-4': (3, 15, .30, 6),
    'claude-haiku-4-5': (1, 5, .10, 2),
    'claude-3-5-haiku': (.80, 4, .08, 1.60),
}


def shell_function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SCRIPT, re.M | re.S)
    if not match:
        raise AssertionError('Missing shell function: ' + name)
    return match.group()


def pricing_functions(path, names):
    # Load just the pricing definitions, avoiding the dashboard's .env loader
    # and startup code. These are the production definitions, not copies.
    tree = ast.parse(path.read_text())
    selected = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
                selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            selected.append(node)
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


class ReviewModelTests(unittest.TestCase):
    def run_wrapper(self, extra_args):
        with tempfile.TemporaryDirectory(prefix='review-model-') as tmp:
            scratch = Path(tmp)
            capture = scratch / 'args.json'
            fake_claude = scratch / 'claude'
            fake_claude.write_text(
                '#!' + sys.executable + '\n'
                'import json, os, sys\n'
                'with open(os.environ["REVIEW_TEST_ARGS"], "w") as f:\n'
                '    json.dump(sys.argv[1:], f)\n')
            fake_claude.chmod(0o755)
            for name, body in {
                'uuidgen': 'echo 00000000-0000-4000-8000-000000000001',
                'sleep': '/bin/sleep 0.01',
            }.items():
                stub = scratch / name
                stub.write_text('#!/bin/sh\n' + body + '\n')
                stub.chmod(0o755)
            env = dict(os.environ, HOME=tmp, PATH=tmp + os.pathsep + os.environ['PATH'],
                       REVIEW_TEST_ARGS=str(capture), HTTPS_PROXY='', HTTP_PROXY='', NO_PROXY='')
            command = '\n'.join([
                'set -euo pipefail',
                'CLAUDE_ALLOWED_TOOLS_DEFAULT=Read,Glob,Grep',
                'CLAUDE_HARD_CEILING=60; CLAUDE_MAX_IDLE=60',
                'log() { :; }',
                'log_galileo_run() { :; }',
                shell_function('run_claude'),
                'run_claude "review prompt with spaces" ' + shlex.quote(str(scratch / 'run.log'))
                + ''.join(' ' + shlex.quote(arg) for arg in extra_args),
            ])
            subprocess.run([shutil.which('bash'), '-c', command], env=env,
                           check=True, capture_output=True, text=True, timeout=15)
            return json.loads(capture.read_text())

    def test_all_orchestrator_callers_use_opus_5_5(self):
        args = self.run_wrapper([])
        self.assertEqual(args[args.index('--model') + 1], 'claude-opus-5-5')
        self.assertEqual(args[args.index('--allowedTools') + 1], 'Read,Glob,Grep')

    def test_model_switch_preserves_effort_and_tools(self):
        args = self.run_wrapper([])
        self.assertEqual(args[args.index('--model') + 1], 'claude-opus-5-5')
        self.assertEqual(args[args.index('--effort') + 1], 'medium')
        self.assertEqual(args[args.index('--allowedTools') + 1], 'Read,Glob,Grep')
        self.assertIn('--strict-mcp-config', args)
        self.assertIn('--disallowedTools', args)

    def test_mention_tool_override_remains_in_third_argument(self):
        args = self.run_wrapper(['Read,Glob'])
        self.assertEqual(args[args.index('--model') + 1], 'claude-opus-5-5')
        self.assertEqual(args[args.index('--allowedTools') + 1], 'Read,Glob')

    def test_review_call_uses_shared_wrapper(self):
        invocation = next(line.strip().split(' || {')[0]
                          for line in shell_function('review_single_pr').splitlines()
                          if line.strip().startswith('run_claude '))
        script = '\n'.join([
            'prompt="review prompt"; review_log="review log"',
            'CLAUDE_ALLOWED_TOOLS_DEFAULT=Read,Glob,Grep',
            'run_claude() { printf "%s\\n" "$@"; }',
            invocation,
        ])
        result = subprocess.run([shutil.which('bash'), '-c', script],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.splitlines(),
                         ['review prompt', 'review log'])

    def test_standalone_shell_paths_select_opus_5_5(self):
        for name in ['batch-triage.sh', 'run-stale-triage.sh', 'run-release-notes.sh']:
            with self.subTest(script=name):
                source = (ROOT / 'bin' / name).read_text()
                invocation = re.search(r'claude -p .*?(?=\n[^\n]*[<>])', source, re.S)
                self.assertIsNotNone(invocation)
                self.assertEqual(re.findall(r'--model\s+(\S+)', invocation.group()),
                                 ['claude-opus-5-5'])

    def test_python_paths_pass_pinned_model_to_cli(self):
        codegraph = ast.parse((ROOT / 'bin/codegraph-extract-docs.py').read_text())
        model = next(ast.literal_eval(node.value) for node in codegraph.body
                     if isinstance(node, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'CLAUDE_MODEL'
                             for t in node.targets))
        self.assertEqual(model, 'claude-opus-5-5')
        call = next(node for node in ast.walk(codegraph)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'run')
        args = call.args[0].elts
        index = next(i for i, arg in enumerate(args)
                     if isinstance(arg, ast.Constant) and arg.value == '--model')
        self.assertEqual(args[index + 1].id, 'CLAUDE_MODEL')
        source = (ROOT / 'bin/run-eval.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        tree = ast.parse(source)
        call = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'run')
        args = call.args[0].elts
        index = next(i for i, arg in enumerate(args)
                     if isinstance(arg, ast.Constant) and arg.value == '--model')
        self.assertEqual(ast.literal_eval(args[index + 1]), 'claude-opus-5-5')

    def test_agent_manifest_matches_runtime_model(self):
        manifest = json.loads((ROOT / 'aetherclaude.oasf.json').read_text())
        self.assertIn('claude-opus-5-5', manifest['description'])
        self.assertNotRegex(json.dumps(manifest), r'claude-opus-5["\s)]')


class PricingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('bot_cost', ROOT / 'bin/bot-cost.py')
        cls.bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bot)
        cls.dashboard = pricing_functions(ROOT / 'bin/tetragon-dashboard.py',
                                          {'_MODEL_RATES', '_MODEL_RATES_DEFAULT',
                                           '_HAIKU_LONG_CONTEXT_RATES', '_turn_cost', 'scan_tokens'})

    def test_each_token_category_uses_published_rate(self):
        keys = ['input_tokens', 'output_tokens', 'cache_read_input_tokens',
                'cache_creation_input_tokens']
        self.assertEqual(set(self.bot.PRICING), set(EXPECTED_MODEL_RATES))
        self.assertEqual(set(self.dashboard['_MODEL_RATES']), set(EXPECTED_MODEL_RATES))
        for model, rates in EXPECTED_MODEL_RATES.items():
            for index, expected in enumerate(rates):
                with self.subTest(model=model, category=keys[index]):
                    counts = [0, 0, 0, 0]
                    counts[index] = 10_000
                    self.assertAlmostEqual(self.bot.cost_for(model, dict(zip(keys, counts))), expected / 100)
                    self.assertAlmostEqual(self.dashboard['_turn_cost'](model, *counts), expected / 100)

    def test_dated_legacy_snapshots_use_their_rates(self):
        for model, expected in [('claude-haiku-4-5-20251001', 1),
                                ('claude-opus-4-1-20250805', 15),
                                ('claude-opus-4-20250514', 15),
                                ('claude-opus-4-0', 15),
                                ('claude-sonnet-4-5-20250929', 3),
                                ('claude-3-5-haiku-20241022', .80)]:
            with self.subTest(model=model):
                counts = dict(zip(self.bot.TOKEN_KEYS, [1_000_000, 0, 0, 0]))
                self.assertAlmostEqual(self.bot.cost_for(model, counts), expected)
                self.assertAlmostEqual(self.dashboard['_turn_cost'](model, 1_000_000, 0, 0, 0), expected)

    def test_haiku_threshold_counts_all_input_but_not_output(self):
        # At 100k input the lower rates apply. Crossing it changes all
        # categories for this request, including its output and cache writes.
        for counts, expected in [([100_000, 0, 0, 0], .01),
                                 ([100_001, 0, 0, 0], .0500005),
                                 ([0, 1_000_000, 100_000, 0], .501),
                                 ([0, 1_000_000, 100_001, 0], 2.50500005),
                                 ([1, 1_000_000, 50_000, 50_000], 2.5525005)]:
            with self.subTest(counts=counts):
                self.assertAlmostEqual(self.bot.cost_for('claude-haiku-5-5',
                                                        dict(zip(self.bot.TOKEN_KEYS, counts))), expected)
                self.assertAlmostEqual(self.dashboard['_turn_cost']('claude-haiku-5-5', *counts), expected)

    def usage_records(self):
        return [{'type': 'assistant', 'message': {'model': model, 'usage': dict(zip(self.bot.TOKEN_KEYS, counts))}}
                for model, counts in [('claude-haiku-5-5', [100_000, 0, 0, 0]),
                                      ('claude-haiku-5-5', [100_000, 0, 0, 0]),
                                      ('claude-haiku-5-5', [100_001, 0, 0, 0]),
                                      ('claude-opus-5-5', [100_000, 0, 0, 0])]]

    def test_session_and_marker_price_each_request_before_summing(self):
        with tempfile.TemporaryDirectory(prefix='all-model-cost-') as tmp:
            project = Path(tmp) / '-project'
            project.mkdir()
            path = project / 'session.jsonl'
            path.touch()
            previous = self.bot.SESSION_ROOT, self.bot.SESSION_GLOB, self.bot.OFFSET_FILE
            self.bot.SESSION_ROOT = tmp
            self.bot.SESSION_GLOB = str(project / '*.jsonl')
            self.bot.OFFSET_FILE = str(Path(tmp) / 'offsets.json')
            try:
                _, empty = self.bot.read_usage_since_marker()
                self.assertEqual(self.bot.cost_for('', empty), 0)
                path.write_text(''.join(json.dumps(record) + '\n' for record in self.usage_records()))
                for reader in [lambda: self.bot.read_usage_for_session('session'),
                               self.bot.read_usage_since_marker]:
                    model, totals = reader()
                    self.assertEqual(totals['input_tokens'], 400_001)
                    self.assertAlmostEqual(self.bot.cost_for(model, totals), .4700005)
                _, empty = self.bot.read_usage_since_marker()
                self.assertEqual(self.bot.cost_for('', empty), 0)
            finally:
                self.bot.SESSION_ROOT, self.bot.SESSION_GLOB, self.bot.OFFSET_FILE = previous

    def test_dashboard_totals_keep_per_request_haiku_tiers(self):
        class EndScan(BaseException):
            pass

        def stop(_):
            raise EndScan()

        with tempfile.TemporaryDirectory(prefix='dashboard-cost-') as tmp:
            path = Path(tmp) / 'session.jsonl'
            path.write_text(''.join(json.dumps(record) + '\n' for record in self.usage_records()))
            start = datetime(2000, 1, 1)
            errors = []
            stats = {}
            self.dashboard.update({
                'os': os, 'glob': glob, 'json': json, 'defaultdict': defaultdict,
                'time': SimpleNamespace(sleep=stop), '_tok_cache': {}, '_tok_cache_key': None,
                '_current_cycle_start': lambda: start, '_discover_subscription_start': lambda: start,
                '_tokenomics_epoch': lambda: None, '_bill_cycles_paid': lambda _: 1,
                '_parse_record_ts': lambda _: None, '_log_exc': lambda *args: errors.append(args),
                'SESSION_DIR': tmp, 'lock': nullcontext(), 'token_stats': stats, 'tool_stats': {},
                'SUBSCRIPTION_AMOUNT_USD': 200, 'TOKEN_REFRESH_SECS': 30,
            })
            with self.assertRaises(EndScan):
                self.dashboard['scan_tokens']()
            self.assertEqual(errors, [])
            self.assertEqual(stats['input'], 400_001)
            self.assertEqual(stats['messages'], 4)
            self.assertEqual(stats['cost'], .47)
            self.assertEqual(stats['cycle_cost'], .47)
            # Reusing the cache must not reprice the session's combined
            # Haiku input at the long-context tier or double-count costs.
            with self.assertRaises(EndScan):
                self.dashboard['scan_tokens']()
            self.assertEqual(errors, [])
            self.assertEqual(stats['cost'], .47)
            with path.open('a') as stream:
                stream.write(json.dumps(self.usage_records()[0]) + '\n')
            with self.assertRaises(EndScan):
                self.dashboard['scan_tokens']()
            self.assertEqual(errors, [])
            self.assertEqual(stats['messages'], 5)
            self.assertEqual(stats['cost'], .48)
            self.assertEqual(stats['cycle_cost'], .48)

    def test_transcript_model_and_footer_use_opus_5_5(self):
        with tempfile.TemporaryDirectory(prefix='review-cost-') as tmp:
            project = Path(tmp) / '-review-project'
            project.mkdir()
            (project / 'review-session.jsonl').write_text(json.dumps({
                'type': 'assistant',
                'message': {'model': 'claude-opus-5-5', 'usage': {
                    'input_tokens': 100_000, 'output_tokens': 10_000,
                    'cache_read_input_tokens': 1_000_000,
                    'cache_creation_input_tokens': 50_000,
                }},
            }) + '\n')
            previous = self.bot.SESSION_ROOT
            self.bot.SESSION_ROOT = tmp
            try:
                model, totals = self.bot.read_usage_for_session('review-session')
            finally:
                self.bot.SESSION_ROOT = previous
            self.assertEqual(model, 'claude-opus-5-5')
            cost = self.bot.cost_for(model, totals)
            self.assertAlmostEqual(cost, 1.20)
            self.assertAlmostEqual(self.dashboard['_turn_cost'](model, 100_000, 10_000, 1_000_000, 50_000), 1.20)
            self.assertIn('cost: $1.2000 · model: claude-opus-5-5', self.bot.format_footer(model, cost))


if __name__ == '__main__':
    unittest.main(verbosity=2)
