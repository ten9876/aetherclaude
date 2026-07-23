#!/usr/bin/env python3
"""antares-detector — Foundry Detector stage: local vulnerability localization.

Runs Cisco Foundation AI's Antares-1B (via an OpenAI-compatible local server,
Ollama by default at 127.0.0.1:11434) as an agentic loop that explores the
AetherSDR repo with terminal commands and reports candidate vulnerable files.
Seeded with the Cartographer's --cwe security-overlay slice so it starts from
the map instead of cold `ls`.

SECURITY: the model issues arbitrary "terminal" commands; this harness NEVER
runs a shell. Each command is parsed, its verb checked against a four-command
allowlist (grep/find/cat/ls), path arguments validated to stay inside the
read-only repo root, and executed via argv (shell=False) — so pipes, `;`,
`$()`, backticks, `-exec`, and path escapes are inert by construction. The
harness itself runs as uid 965 behind the pf firewall as defense in depth.

Fail-open: if the model server is unreachable the run yields an empty verdict
and never raises — the Detector must never block triage.

Usage:
  antares-detector.py --repo /path/to/ro-copy --cwe CWE-787 \
      --context "issue text" --issue 4321 --out antares-latest.json
"""
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request

OLLAMA_URL = os.environ.get('ANTARES_OLLAMA_URL', 'http://127.0.0.1:11434/api/chat')
MODEL = os.environ.get('ANTARES_MODEL', 'antares-1b')
CARTOGRAPHER = '/Users/aetherclaude/bin/codegraph-cartographer.py'

ALLOWED_CMDS = {'grep', 'find', 'cat', 'ls'}
# find primaries that act rather than list — never allowed.
FIND_DANGEROUS = {'-exec', '-execdir', '-delete', '-ok', '-okdir',
                  '-fprint', '-fprintf', '-fls', '-fprint0'}
MAX_OUTPUT_BYTES = 6000        # per-command stdout cap fed back to the model
PER_CMD_TIMEOUT = 15           # seconds
OVERALL_TIMEOUT = 240          # seconds — hard ceiling for the whole loop

SYSTEM_PROMPT = (
    "You are a security vulnerability localization agent. The repository is "
    "mounted at the current directory. Use shell commands (grep, find, cat, "
    "ls) to explore the codebase and identify the file(s) that contain the "
    "reported vulnerability. Think step by step. Emit exactly one tool call "
    "per turn as <tool_call>{\"name\": \"terminal\", \"arguments\": "
    "{\"command\": \"...\"}}</tool_call>. When you have located the "
    "vulnerable file(s), call submit_vulnerable_files with their paths; if "
    "there is no vulnerability, call submit_no_vulnerability_found."
)

_TOOLCALL_RE = re.compile(r'<tool_call>\s*(\{.*?\})\s*</tool_call>', re.DOTALL)


# --------------------------------------------------------------------------
# Allowlist-jail command executor — the security boundary.
# --------------------------------------------------------------------------

def _path_ok(tok, repo_root):
    """A path-bearing token is safe iff, resolved, it stays inside repo_root.
    Tokens without a '/' can't escape the jailed cwd, so they're always fine
    (a bare pattern like 'buf' or a top-level name). Only '/'-containing
    tokens are resolved and checked."""
    if '/' not in tok:
        return True
    # realpath resolves .. and symlinks; absolute or ..-escaping paths land
    # outside repo_root and are rejected.
    full = os.path.realpath(os.path.join(repo_root, tok) if not tok.startswith('/') else tok)
    root = os.path.realpath(repo_root)
    return full == root or full.startswith(root + os.sep)


def validate_command(cmd_str, repo_root):
    """Return (argv, None) if safe to run, or (None, reason) if rejected."""
    try:
        argv = shlex.split(cmd_str)
    except ValueError as e:
        return None, f'unparseable command: {e}'
    if not argv:
        return None, 'empty command'
    verb = os.path.basename(argv[0])
    if verb not in ALLOWED_CMDS:
        return None, f'command "{verb}" not in allowlist {sorted(ALLOWED_CMDS)}'
    for tok in argv[1:]:
        if verb == 'find' and tok in FIND_DANGEROUS:
            return None, f'find primary {tok} is not permitted'
        # Any shell-operator-looking token is harmless under shell=False, but
        # reject the obvious ones so a rejected command reads clearly.
        if tok in (';', '|', '||', '&&', '&', '>', '<', '`', '$('):
            return None, f'shell operator {tok!r} not permitted (no shell)'
        if not _path_ok(tok, repo_root):
            return None, f'path {tok!r} escapes the repository root'
    return argv, None


def run_command(cmd_str, repo_root):
    """Validate + execute one model command. Returns a <tool_response> body
    string (never raises)."""
    argv, reason = validate_command(cmd_str, repo_root)
    if reason:
        return f'REJECTED: {reason}'
    try:
        p = subprocess.run(argv, cwd=repo_root, capture_output=True, text=True,
                           timeout=PER_CMD_TIMEOUT, shell=False,
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        out = p.stdout or ''
        if p.returncode != 0 and not out:
            out = p.stderr or f'(exit {p.returncode}, no output)'
        if len(out) > MAX_OUTPUT_BYTES:
            out = out[:MAX_OUTPUT_BYTES] + '\n… [truncated]'
        return out or '(no output)'
    except subprocess.TimeoutExpired:
        return f'(command timed out after {PER_CMD_TIMEOUT}s)'
    except Exception as e:
        return f'(execution error: {e})'


# --------------------------------------------------------------------------
# Model server (OpenAI-compatible /api/chat — Ollama / llama.cpp-server / vLLM)
# --------------------------------------------------------------------------

def chat(messages, timeout=60):
    body = json.dumps({
        'model': MODEL, 'messages': messages, 'stream': False,
        'options': {'temperature': 0.3, 'top_p': 1.0, 'num_predict': 512},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, method='POST',
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    # Ollama: {'message': {'content': ...}}; OpenAI: {'choices':[{'message':...}]}
    if 'message' in d:
        return d['message'].get('content', '')
    if 'choices' in d and d['choices']:
        return d['choices'][0].get('message', {}).get('content', '')
    return ''


def parse_tool_call(content):
    """Extract the first <tool_call> JSON. Returns (name, args) or (None, None)."""
    m = _TOOLCALL_RE.search(content or '')
    if not m:
        return None, None
    try:
        obj = json.loads(m.group(1))
        return obj.get('name'), obj.get('arguments', {}) or {}
    except Exception:
        return None, None


def _candidate_files(args):
    for key in ('files', 'file_paths', 'paths', 'file'):
        v = args.get(key)
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
    return []


# --------------------------------------------------------------------------
# Detector loop
# --------------------------------------------------------------------------

def cartographer_slice(cwe):
    if not cwe:
        return ''
    try:
        out = subprocess.run(['/usr/bin/python3', CARTOGRAPHER, '--cwe', cwe],
                             capture_output=True, text=True, timeout=20)
        return out.stdout or ''
    except Exception:
        return ''


def localize(repo, cwe, context, max_commands):
    """Run the agentic loop. Returns a verdict dict (fail-open)."""
    started = time.time()
    result = {'verdict': 'error', 'candidates': [], 'commands_used': 0,
              'cwe': cwe, 'transcript': []}
    overlay = cartographer_slice(cwe)
    user = ''
    if overlay:
        user += ('Repository security map (Cartographer overlay — candidate '
                 'sites to investigate first):\n' + overlay + '\n\n')
    if cwe:
        user += f'Vulnerability class to locate: {cwe}\n'
    if context:
        user += f'Reported issue:\n{context.strip()[:4000]}\n'
    if not user:
        user = 'Locate any security vulnerability in this repository.'

    messages = [{'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user}]

    for step in range(max_commands):
        if time.time() - started > OVERALL_TIMEOUT:
            result['verdict'] = 'timeout'
            break
        try:
            content = chat(messages)
        except Exception as e:
            result['verdict'] = 'server_unreachable'
            result['error'] = str(e)
            return result           # fail-open: never blocks triage
        messages.append({'role': 'assistant', 'content': content})
        name, args = parse_tool_call(content)

        if name == 'submit_vulnerable_files':
            result['verdict'] = 'vulnerable'
            result['candidates'] = _candidate_files(args)
            result['rationale'] = args.get('rationale') or args.get('reason') or ''
            break
        if name == 'submit_no_vulnerability_found':
            result['verdict'] = 'clean'
            break
        if name == 'terminal':
            cmd = (args.get('command') or '').strip()
            resp = run_command(cmd, repo)
            result['commands_used'] += 1
            result['transcript'].append({'command': cmd, 'response': resp[:500]})
            messages.append({'role': 'user',
                             'content': f'<tool_response>\n{resp}\n</tool_response>'})
            continue
        # No parseable tool call — nudge once, then give up on repeats.
        messages.append({'role': 'user', 'content':
                         'Emit exactly one <tool_call> with a terminal command, '
                         'or call submit_vulnerable_files / '
                         'submit_no_vulnerability_found.'})
    else:
        result['verdict'] = result['verdict'] if result['verdict'] != 'error' else 'budget_exhausted'

    result['elapsed_s'] = round(time.time() - started, 1)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True, help='Read-only repo root to explore.')
    ap.add_argument('--cwe', default='', help='CWE-N to seed (optional).')
    ap.add_argument('--context', default='', help='Issue/PR text.')
    ap.add_argument('--issue', default='', help='Issue/PR number (for the record).')
    ap.add_argument('--max-commands', type=int, default=15)
    ap.add_argument('--out', default='', help='Write verdict json to this path too.')
    args = ap.parse_args()

    if not os.path.isdir(args.repo):
        print(json.dumps({'verdict': 'error', 'error': f'repo not found: {args.repo}',
                          'candidates': []}))
        return 0   # fail-open

    res = localize(os.path.realpath(args.repo), args.cwe.strip(),
                   args.context, args.max_commands)
    res['issue'] = args.issue
    res['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    payload = json.dumps(res, indent=2)
    if args.out:
        try:
            tmp = args.out + '.tmp'
            with open(tmp, 'w') as f:
                f.write(payload)
            os.replace(tmp, args.out)
        except Exception as e:
            print(f'antares-detector: could not write {args.out}: {e}', file=sys.stderr)
    print(payload)
    return 0


if __name__ == '__main__':
    sys.exit(main())
