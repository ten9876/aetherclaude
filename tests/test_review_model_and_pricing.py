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


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/run-agent.sh').read_text()


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
                                          {'_MODEL_RATES', '_MODEL_RATES_DEFAULT', '_turn_cost'})

    def test_each_token_category_uses_published_rate(self):
        keys = ['input_tokens', 'output_tokens', 'cache_read_input_tokens',
                'cache_creation_input_tokens']
        for model, rates in [('claude-opus-5-5', [4.0, 20.0, 0.20, 8.0]),
                             ('claude-opus-5', [5.0, 25.0, 0.50, 10.0])]:
            for index, expected in enumerate(rates):
                with self.subTest(model=model, category=keys[index]):
                    counts = [0, 0, 0, 0]
                    counts[index] = 1_000_000
                    self.assertAlmostEqual(self.bot.cost_for(model, dict(zip(keys, counts))), expected)
                    self.assertAlmostEqual(self.dashboard['_turn_cost'](model, *counts), expected)

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
            self.assertEqual(self.dashboard['_turn_cost'](model, 100_000, 10_000, 1_000_000, 50_000), 1.20)
            self.assertIn('cost: $1.2000 · model: claude-opus-5-5', self.bot.format_footer(model, cost))


if __name__ == '__main__':
    unittest.main(verbosity=2)
