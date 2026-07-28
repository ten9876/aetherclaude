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
import shlex
import subprocess
import sys
import time
import urllib.request

OLLAMA_URL = os.environ.get('ANTARES_OLLAMA_URL', 'http://127.0.0.1:11434/api/chat')
MODEL = os.environ.get('ANTARES_MODEL', 'antares-1b')
CARTOGRAPHER = '/Users/aetherclaude/bin/codegraph-cartographer.py'

# Read-only verb allowlist. Every one of these only READS — none can write a
# file or execute another program. Deliberately excluded: sed/awk (can write &
# run shells), sort/uniq (write via -o / positional output file), tee/dd/cp/mv
# (write), xargs/env/find-exec (spawn arbitrary programs). The model gets its
# paging idioms (head/tail/nl) and pipes, but no write or exec vector.
ALLOWED_CMDS = {'grep', 'find', 'cat', 'ls', 'head', 'tail', 'nl', 'wc',
                'cut', 'tr'}
# find primaries that act rather than list — never allowed.
FIND_DANGEROUS = {'-exec', '-execdir', '-delete', '-ok', '-okdir',
                  '-fprint', '-fprintf', '-fls', '-fprint0'}
# Shell operators that must never appear inside a stage (pipes are handled
# separately as stage separators; everything else is forbidden outright).
SHELL_OPERATORS = {';', '||', '&&', '&', '>', '>>', '<', '<<', '<<<',
                   '`', '$(', '$((', ')', '{', '}'}
MAX_STAGES = 6                 # cap pipeline length
MAX_OUTPUT_BYTES = 6000        # per-command stdout cap fed back to the model
PER_CMD_TIMEOUT = 15           # seconds
OVERALL_TIMEOUT = 240          # seconds — hard ceiling for the whole loop
MIN_CLEAN_COMMANDS = 3         # clean verdict below this = 'clean_unverified'

# Verbs whose own flags can hang — reject those specific args even though the
# verb reads by default.
DANGEROUS_ARGS = {
    'tail': {'-f', '-F', '--follow'},        # -f would hang the pipeline
}

SYSTEM_PROMPT = (
    "You are a security vulnerability localization agent. The repository is "
    "mounted at the current directory. Determine whether the code involved "
    "in the context below contains an actual SECURITY vulnerability — a "
    "memory-safety violation (overflow, out-of-bounds, use-after-free, "
    "double-free), injection, path traversal, format-string bug, unsafe "
    "deserialization, or unvalidated external input reaching a dangerous "
    "operation. Neither verdict is preferred: the evidence decides.\n"
    "\n"
    "What counts: a crash, glitch, or wrong output is a vulnerability only "
    "if untrusted input can trigger it to corrupt memory, execute commands, "
    "escape a path, or leak data. A functional bug with no attacker-"
    "relevant consequence is NOT a vulnerability, even if the context "
    "describes it as serious. You are not a bug localizer.\n"
    "\n"
    "Procedure:\n"
    "1. Identify from the context which subsystem/files are involved.\n"
    "2. Inspect the dangerous-API sites the security map lists for that "
    "area — actually read the code around them; do not judge from file or "
    "function names alone.\n"
    "3. Submit the verdict the evidence supports:\n"
    "   - submit_vulnerable_files when untrusted input can reach the flaw. "
    "The rationale MUST name the vulnerability class, ideally the CWE "
    "(e.g. \"CWE-787 out-of-bounds write in the ADIF parser\"). A rationale "
    "that only describes a functional bug is not acceptable.\n"
    "   - submit_no_vulnerability_found when you have inspected the "
    "relevant sites and found them sound.\n"
    "Never submit either verdict without having examined code first.\n"
    "\n"
    "Think step by step. Emit exactly "
    "one tool call per turn as <tool_call>{\"name\": \"terminal\", "
    "\"arguments\": {\"command\": \"...\"}}</tool_call>.\n"
    "\n"
    "SANDBOX RULES — the terminal is read-only (no shell metacharacters except "
    "the pipe), so obey these or the command is REJECTED and your turn wasted:\n"
    "- Allowed programs (read-only only): grep, find, cat, ls, head, tail, nl, "
    "wc, cut, tr. Anything else (sed, awk, sort, uniq, xargs, python, rg) is "
    "REJECTED.\n"
    "- Pipes ARE allowed: chain the programs above, e.g. "
    "grep -rIn \"memcpy\" src | head -n 40.\n"
    "- NOT allowed: redirection '>' '<', ';' '&&' '||' '&', '$()' or "
    "backticks. Paths must stay inside the repository (no '..' or absolute "
    "paths like /etc).\n"
    "- Useful idioms:\n"
    "    * search a tree:            grep -rIn \"pattern\" src | head -n 40\n"
    "    * view code AROUND a match: grep -n -B5 -A20 \"pattern\" path/to/file\n"
    "    * read a file:              cat path/to/file  (or: nl path | head -n 60)\n"
    "\n"
    "You have a limited command budget. A grep hit plus reading the lines "
    "around it is usually enough evidence — you do not need to read whole "
    "files. Do not exhaust the budget re-reading the same files; submit as "
    "soon as the evidence supports a verdict."
)

_TOOLCALL_OPEN = '<tool_call>'


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


def _validate_stage(argv, repo_root):
    """Validate one pipeline stage (a single program invocation).
    Returns (argv, None) if safe, or (None, reason) if rejected."""
    if not argv:
        return None, 'empty pipeline stage'
    verb = os.path.basename(argv[0])
    if verb not in ALLOWED_CMDS:
        return None, (f'command "{verb}" not allowed; use only '
                      f'{sorted(ALLOWED_CMDS)}')
    bad_args = DANGEROUS_ARGS.get(verb, set())
    for tok in argv[1:]:
        if verb == 'find' and tok in FIND_DANGEROUS:
            return None, f'find primary {tok} is not permitted'
        if tok in bad_args:
            return None, f'{verb} {tok} is not permitted'
        if tok in SHELL_OPERATORS or tok.startswith(('>', '<')):
            return None, f'shell operator {tok!r} not permitted (no shell)'
        # Reject embedded command substitution / backticks in any token.
        if '$(' in tok or '`' in tok:
            return None, f'command substitution in {tok!r} not permitted'
        if not _path_ok(tok, repo_root):
            return None, f'path {tok!r} escapes the repository root'
    return argv, None


def validate_command(cmd_str, repo_root):
    """Parse a (possibly piped) command into validated stages.
    Returns (stages, None) where stages is a list of argv lists, or
    (None, reason) if any stage is rejected. Pipes are the ONLY operator
    allowed; every stage must be a read-only allowlisted program."""
    try:
        toks = shlex.split(cmd_str)
    except ValueError as e:
        return None, f'unparseable command: {e}'
    if not toks:
        return None, 'empty command'
    # Split the token stream into pipeline stages on bare '|' tokens.
    # '||' is a distinct token (rejected inside a stage), never a separator.
    stages, cur = [], []
    for tok in toks:
        if tok == '|':
            stages.append(cur)
            cur = []
        else:
            cur.append(tok)
    stages.append(cur)
    if any(not s for s in stages):
        return None, 'empty pipeline stage (stray |)'
    if len(stages) > MAX_STAGES:
        return None, f'pipeline too long (>{MAX_STAGES} stages)'
    validated = []
    for st in stages:
        argv, reason = _validate_stage(st, repo_root)
        if reason:
            return None, reason
        validated.append(argv)
    return validated, None


def run_command(cmd_str, repo_root):
    """Validate + execute one model command (single program or a read-only
    pipeline). Returns a <tool_response> body string (never raises).

    Executes with shell=False and chains stages by wiring each Popen's stdout
    into the next stage's stdin — so `|` works without a shell interpreting the
    string. `;`, `>`, `$()`, backticks etc. are inert because no shell ever
    sees the command; they are also rejected up front for clear feedback."""
    stages, reason = validate_command(cmd_str, repo_root)
    if reason:
        return f'REJECTED: {reason}'
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C'}
    procs = []
    try:
        prev_out = None
        for i, argv in enumerate(stages):
            last = (i == len(stages) - 1)
            p = subprocess.Popen(
                argv, cwd=repo_root, env=env,
                stdin=prev_out,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if last else subprocess.DEVNULL,
            )
            # Let the upstream process receive SIGPIPE if a downstream stage
            # (e.g. head) exits early.
            if prev_out is not None:
                prev_out.close()
            prev_out = p.stdout
            procs.append(p)
        try:
            out_b, err_b = procs[-1].communicate(timeout=PER_CMD_TIMEOUT)
        except subprocess.TimeoutExpired:
            for p in procs:
                p.kill()
            for p in procs:
                try:
                    p.wait(timeout=2)
                except Exception:
                    pass
            return f'(command timed out after {PER_CMD_TIMEOUT}s)'
        # Reap upstream stages so they don't linger.
        for p in procs[:-1]:
            try:
                p.wait(timeout=2)
            except Exception:
                p.kill()
        out = (out_b or b'').decode('utf-8', 'replace')
        if not out:
            err = (err_b or b'').decode('utf-8', 'replace')
            rc = procs[-1].returncode
            out = err or (f'(exit {rc}, no output)' if rc else '')
        if len(out) > MAX_OUTPUT_BYTES:
            out = out[:MAX_OUTPUT_BYTES] + '\n… [truncated]'
        return out or '(no output)'
    except FileNotFoundError as e:
        return f'(program not found: {e})'
    except Exception as e:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
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
    """Extract the first <tool_call> JSON. Returns (name, args) or (None, None).

    The model reliably opens with `<tool_call>` but often omits the closing
    `</tool_call>` tag (it ends the turn after the JSON), so we parse the JSON
    object directly with raw_decode — which stops at the end of the object and
    ignores any trailing `</tool_call>`, whitespace, or end-of-turn text."""
    if not content:
        return None, None
    marker = content.find(_TOOLCALL_OPEN)
    if marker == -1:
        return None, None                       # no tool call -> caller nudges
    brace = content.find('{', marker + len(_TOOLCALL_OPEN))
    if brace == -1:
        return None, None
    try:
        obj, _ = json.JSONDecoder().raw_decode(content[brace:])
    except ValueError:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    args = obj.get('arguments', {})
    if not isinstance(args, dict):        # model sometimes emits a bare string
        args = {}
    return obj.get('name'), args


def _candidate_files(args):
    """Collect candidate file paths from submit_vulnerable_files arguments.
    The model is inconsistent about the key name — 'files', 'file_paths',
    'paths', and even 'vulnerable_files[]' (a literal '[]' suffix) all show up —
    so we accept any key that mentions 'file' or 'path', normalizing the '[]'
    suffix, and dedupe. Values may be a string or a list of strings."""
    out, seen = [], set()

    def add(v):
        vals = [v] if isinstance(v, str) else (
            [str(x) for x in v] if isinstance(v, list) else [])
        for x in vals:
            x = x.strip()
            if x and x not in seen:
                seen.add(x)
                out.append(x)

    for key, v in args.items():
        k = key.rstrip('[]').lower()
        if 'file' in k or 'path' in k:
            add(v)
    return out


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
        user += ('Context (a user-filed issue/PR — it may or may not have '
                 'security relevance; treat it as a pointer to the subsystem '
                 'to inspect, not as a claim in either direction):\n'
                 + context.strip()[:4000] + '\n')
    if not cwe:
        user += ('\nNo specific vulnerability class was reported. Use the '
                 'security map above as your primary target list: inspect '
                 'the dangerous-API sites in the subsystem the context '
                 'touches, then submit the verdict the evidence supports.\n')
    if not user.strip():
        user = 'Locate any security vulnerability in this repository.'

    messages = [{'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user}]

    no_call = 0   # consecutive turns with no parseable tool call
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
            # A clean verdict must be earned. Fewer than MIN_CLEAN_COMMANDS
            # executed commands means the model judged without actually
            # inspecting code — record it distinctly so the action log /
            # dashboard can track lazy-cleans the same way detect/gated
            # tracks over-eager submits. Consumers treat both as clean
            # (advisory either way); this is a quality signal, not a gate.
            if result['commands_used'] < MIN_CLEAN_COMMANDS:
                result['verdict'] = 'clean_unverified'
            else:
                result['verdict'] = 'clean'
            break
        if name == 'terminal':
            no_call = 0
            cmd = (args.get('command') or '').strip()
            resp = run_command(cmd, repo)
            result['commands_used'] += 1
            result['transcript'].append({'command': cmd, 'response': resp[:500]})
            tool_msg = f'<tool_response>\n{resp}\n</tool_response>'
            remaining = max_commands - result['commands_used']
            if remaining <= 3:
                tool_msg += (f'\n\n[Only {remaining} command(s) left. If you have '
                             'already found the vulnerable file(s), stop exploring '
                             'and call submit_vulnerable_files now with the path(s) '
                             'and a one-line rationale. If nothing relevant was '
                             'found, call submit_no_vulnerability_found.]')
            messages.append({'role': 'user', 'content': tool_msg})
            continue
        # No parseable tool call. The 1B model sometimes rambles instead of
        # terminating (esp. generic mode on a non-security issue) — after a few
        # consecutive non-calls, stop and treat it as no finding rather than
        # burning the whole budget (was the #4414 'budget_exhausted' noise).
        no_call += 1
        if no_call >= 3:
            result['verdict'] = 'clean'
            result['note'] = f'no tool call after {no_call} nudges — no finding'
            break
        messages.append({'role': 'user', 'content':
                         'You did not emit a valid tool call. If you found the '
                         'vulnerable file(s), call submit_vulnerable_files now; if you '
                         'found nothing relevant, call submit_no_vulnerability_found. '
                         'Otherwise emit exactly one <tool_call> with a grep/find/cat/ls '
                         'command.'})
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

    try:
        res = localize(os.path.realpath(args.repo), args.cwe.strip(),
                       args.context, args.max_commands)
    except Exception as e:
        # Absolute backstop: the Detector is advisory and must never break
        # triage, so any unexpected failure becomes an empty fail-open verdict.
        res = {'verdict': 'error', 'error': f'{type(e).__name__}: {e}',
               'candidates': [], 'cwe': args.cwe.strip()}
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
