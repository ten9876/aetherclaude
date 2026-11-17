#!/usr/bin/env python3
"""antares-detector — Foundry Detector stage: local vulnerability localization.

Runs Cisco Foundation AI's Antares-1B (via an OpenAI-compatible local server,
Ollama by default at 127.0.0.1:11434) as an agentic loop that explores the
AetherSDR repo with terminal commands and reports candidate vulnerable files.
Seeded with the Cartographer's --cwe security-overlay slice so it starts from
the map instead of cold `ls`.

SECURITY: the model issues arbitrary "terminal" commands; this harness NEVER
runs a shell. Each command is parsed, its verb checked against a read-only
allowlist (ALLOWED_CMDS, with per-verb write/exec/symlink-following options
blocked), every path argument (including a path attached to an option, as
in --opt=PATH) validated to resolve inside the repo root, and executed via
argv (shell=False) — so pipes, `;`, `$()`, backticks, `-exec`, and path
escapes are inert by construction. Commands run in a snapshot that holds
only the repo's tracked regular files (no symlinks, no submodules, no
.git), never in the checkout itself, and command output is quarantined so
repo text cannot pose as agent protocol. The harness itself runs as uid 965
behind the pf firewall as defense in depth.

PROMPT FORMAT: the conversation is rendered with the model's own Granite
chat template (tools listed in a <tools> block, tool calls as <tool_call>
JSON, sandbox output as a user <tool_response>, generation primed with
<think>) and sent raw to Ollama's /api/generate, with the tool schema of
the model card (terminal / submit_vulnerable_files{ranked_files} /
submit_no_vulnerability_found). Earlier turns are replayed as their tool
calls only; their reasoning is not re-sent.

LOOP CONTROL: a repeated command is answered from the first run and not
charged; three repeats in a row, or the budget running out, close the
terminal and leave only the submit tools for a few turns. The model is
told at 80% of the budget, and when search hits it has not opened yet
remain. Runaway repetition in a reply is rejected uncharged.

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
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

GENERATE_URL = os.environ.get('ANTARES_GENERATE_URL', 'http://127.0.0.1:11434/api/generate')
MODEL = os.environ.get('ANTARES_MODEL', 'antares-1b')
CARTOGRAPHER = '/Users/aetherclaude/bin/codegraph-cartographer.py'
# Snapshots are hardlinked from the checkout, so they live on the same volume.
SNAPSHOT_DIR = os.environ.get('ANTARES_SNAPSHOT_DIR',
                              '/Users/aetherclaude/data/antares/snapshots')
SNAPSHOT_PREFIX = 'antares-snap-'
SNAPSHOT_STALE_SECS = 2 * 3600

# Read-only verb allowlist: cisco-antares-cli's SAFE_COMMAND_ALLOWLIST plus tr.
# Every one of these only READS. rg/sed/sort/uniq/tree/file have options that
# write a file, run another program or read a repo-controlled path list; those
# are blocked per verb in _verb_arg_violation, mirroring Cisco's read-only
# policy. Deliberately excluded: awk (runs shells), tee/dd/cp/mv (write),
# xargs/env/find-exec (spawn arbitrary programs).
ALLOWED_CMDS = {'basename', 'cat', 'cut', 'diff', 'dirname', 'du', 'echo',
                'false', 'file', 'find', 'grep', 'head', 'ls', 'nl', 'pwd',
                'realpath', 'rg', 'sed', 'sort', 'stat', 'tail', 'tr', 'tree',
                'true', 'uniq', 'wc'}
# Executor PATH: system tools first, Homebrew only for rg.
EXEC_PATH = '/usr/bin:/bin:/opt/homebrew/bin'
# Rejection hints for verbs the model reaches for that have no safe form.
VERB_HINTS = {
    'cd': 'cd is not supported; commands run from the repository root, so '
          'use relative paths directly (e.g. ls src/core)',
    'xargs': 'xargs is not supported; pass paths directly or use '
             'grep -rIn "pattern" dir / rg -n "pattern" dir',
}
# sed is allowed only to print line ranges: 'N,Mp', 'Np', '$p', 'N,$p'.
SED_PRINT_EXPR = re.compile(r'(?:\d+|\$)(?:,(?:\d+|\$))?p')
SED_ALLOWED_OPTIONS = {'-n', '--quiet', '--silent', '-E', '-r',
                       '--regexp-extended'}
# find primaries that act rather than list — never allowed.
FIND_DANGEROUS = {'-exec', '-execdir', '-delete', '-ok', '-okdir',
                  '-fprint', '-fprintf', '-fls', '-fprint0'}
# Shell operators that must never appear inside a stage (pipes are handled
# separately as stage separators; everything else is forbidden outright).
SHELL_OPERATORS = {';', '||', '&&', '&', '>', '>>', '<', '<<', '<<<',
                   '`', '$(', '$((', ')', '{', '}'}
MAX_STAGES = 6                 # cap pipeline length
DEFAULT_MAX_CHARS = 2000       # terminal tool's max_chars default (model card)
MAX_OUTPUT_BYTES = 6000        # ceiling on a max_chars the model asks for
PER_CMD_TIMEOUT = 15           # seconds
OVERALL_TIMEOUT = 300          # seconds — hard ceiling for the whole loop
GENERATE_TIMEOUT = 120         # seconds — one model turn
MIN_CLEAN_COMMANDS = 3         # clean verdict below this = 'clean_unverified'

# Sampling: model card temperature/top_p; the benchmark harness's
# frequency_penalty; room for the <think> block plus the call.
GEN_OPTIONS = {'temperature': 0.3, 'top_p': 1.0, 'frequency_penalty': 0.3,
               'num_predict': 2048, 'num_ctx': 32768,
               'stop': ['<|end_of_text|>', '<|start_of_role|>', '<tool_response>']}

# Loop control (counts are per run).
MAX_TERMINAL_ATTEMPTS = 20     # charged + duplicate terminal calls
DUPLICATE_STOP = 3             # consecutive repeated commands → terminal closed
FORCED_SUBMISSION_TURNS = 3    # turns allowed after the terminal closes
UNPARSEABLE_STOP = 3           # consecutive replies with no tool call
DEGENERATE_STOP = 3            # consecutive runaway-repetition replies

# Verbs whose own flags can hang — reject those specific args even though the
# verb reads by default.
DANGEROUS_ARGS = {
    'tail': {'-f', '-F', '--follow'},        # -f would hang the pipeline
}

# Options that make a verb follow symlinks. The snapshot holds no symlinks,
# so these never help the model; they are refused so a symlink can never be
# followed even if one reached the tree. (long options, short flags, value-
# taking short flags for cluster scanning)
FOLLOW_OPTIONS = {
    'rg':   ({'--follow'}, 'L', set('ABCEFefgjmMrtT')),
    'grep': (set(), 'SO', set('ABCDdefm')),
    'find': ({'-L', '-H', '-follow'}, '', set()),
    'tree': (set(), 'l', set('HLPITXo')),
    'ls':   (set(), 'LH', set()),
    'du':   ({'--dereference', '--dereference-args'}, 'LH', set('Bdt')),
    'stat': ({'--dereference'}, 'L', set('cft')),
    'file': ({'--dereference'}, 'L', set('eFfmMP')),
    'diff': (set(), '', set()),
}

# Model-protocol markers that must never reach the model from repo text: a
# file containing them would otherwise read as a tool call, a tool response,
# a submission, or a chat-template role boundary.
_PROTOCOL_MARKERS = (
    (re.compile(r'</?\s*tool_call\s*>', re.I), '[quarantined:tool_call]'),
    (re.compile(r'</?\s*tool_response\s*>', re.I), '[quarantined:tool_response]'),
    (re.compile(r'</?\s*think\s*>', re.I), '[quarantined:think]'),
    (re.compile(r'<\|[a-z_]+\|>', re.I), '[quarantined:special]'),
    (re.compile(r'submit_vulnerable_files', re.I), '[quarantined:submit_vulnerable_files]'),
    (re.compile(r'submit_no_vulnerability_found', re.I),
     '[quarantined:submit_no_vulnerability_found]'),
)


def sanitize_tool_output(text):
    for pat, repl in _PROTOCOL_MARKERS:
        text = pat.sub(repl, text)
    return text

CWE_DESCRIPTIONS = {
    'CWE-20': 'Improper Input Validation',
    'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
    'CWE-120': 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)',
    'CWE-122': 'Heap-based Buffer Overflow',
    'CWE-125': 'Out-of-bounds Read',
    'CWE-131': 'Incorrect Calculation of Buffer Size',
    'CWE-134': 'Use of Externally-Controlled Format String',
    'CWE-190': 'Integer Overflow or Wraparound',
    'CWE-191': 'Integer Underflow (Wrap or Wraparound)',
    'CWE-295': 'Improper Certificate Validation',
    'CWE-319': 'Cleartext Transmission of Sensitive Information',
    'CWE-362': 'Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)',
    'CWE-367': 'Time-of-check Time-of-use (TOCTOU) Race Condition',
    'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-401': 'Missing Release of Memory after Effective Lifetime',
    'CWE-415': 'Double Free',
    'CWE-416': 'Use After Free',
    'CWE-457': 'Use of Uninitialized Variable',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-770': 'Allocation of Resources Without Limits or Throttling',
    'CWE-787': 'Out-of-bounds Write',
    'CWE-824': 'Access of Uninitialized Pointer',
}
GENERIC_TASK = ('any', 'Any weakness that untrusted input can reach: memory safety '
                '(out-of-bounds read/write, use-after-free, double free, integer '
                'overflow), injection, path traversal, format string, unsafe '
                'deserialization, or missing input validation')

TOOLS = [
    {'type': 'function', 'function': {
        'name': 'terminal',
        'description': (
            'Execute a read-only terminal command from the repository root. Allowed: '
            'ls, tree, find, cat, head, tail, sed -n (line ranges only), grep, rg, wc, '
            'sort, uniq, cut, tr, nl, file, stat, du, pwd, basename, dirname, realpath, '
            'diff, echo, true, false. Pipes are OK. No cd, xargs, awk, interpreters, '
            ';, &&, ||, redirects, or paths outside the repository.'),
        'parameters': {'type': 'object', 'properties': {
            'command': {'type': 'string', 'description': 'The shell command to run'},
            'max_chars': {'type': 'integer', 'description': 'Max output chars (default 2000)',
                          'default': 2000}},
            'required': ['command']}}},
    {'type': 'function', 'function': {
        'name': 'submit_vulnerable_files',
        'description': (
            'Submit your answer: a ranked list of file paths you believe contain the '
            'vulnerability. Most likely vulnerable file first. Paths relative to repository root.'),
        'parameters': {'type': 'object', 'properties': {
            'ranked_files': {'type': 'array', 'items': {'type': 'string'},
                             'description': 'Ordered list of file paths, most vulnerable first'}},
            'required': ['ranked_files']}}},
    {'type': 'function', 'function': {
        'name': 'submit_no_vulnerability_found',
        'description': ('Declare that no vulnerability matching the CWE description was '
                        'found in this codebase.'),
        'parameters': {'type': 'object', 'properties': {}, 'required': []}}},
]

SYSTEM_TEMPLATE = (
    'You are Antares, a security agent that localizes vulnerabilities in source code.\n'
    'You receive a CWE identifier and description, then explore a read-only repository '
    'snapshot using terminal tools.\n'
    '\n'
    'Rules:\n'
    '- Issue up to {max_calls} read-only terminal commands (ls, find, cat, head, tail, '
    'grep, rg, tree, wc, pwd).\n'
    '- After exploration, submit exactly one final answer:\n'
    '  - submit_vulnerable_files with ranked_files (repo-relative paths), OR\n'
    '  - submit_no_vulnerability_found\n'
    '\n'
    'Task CWE: {cwe}\n'
    'CWE description: {cwe_description}\n'
    '\n'
    'Repository root: .\n'
)

# Granite 4.0 chat template (the model's chat_template.jinja), rendered for
# the message shapes this harness produces.
_TOOLS_PREFIX = ('You are a helpful assistant with access to the following tools. You may '
                 'call one or more tools to assist with the user query.\n\nYou are provided '
                 'with function signatures within <tools></tools> XML tags:\n<tools>')
_TOOLS_SUFFIX = ('\n</tools>\n\nFor each tool call, return a json object with function name '
                 'and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n'
                 '{"name": <function-name>, "arguments": <args-json-object>}\n</tool_call>. '
                 'If a tool does not exist in the provided list of tools, notify the user '
                 'that you do not have the ability to fulfill the request.')
GENERATION_PREFIX = '<|start_of_role|>assistant<|end_of_role|><think>\n'


def render_prompt(messages, tools=TOOLS):
    """Render messages ({role: system|user|assistant|tool}) exactly as the
    model's chat template does with add_generation_prompt=True. Assistant
    turns carry 'tool_calls' [{name, arguments(dict)}] and/or 'content'."""
    tools_msg = _TOOLS_PREFIX + ''.join(
        '\n' + json.dumps(t, ensure_ascii=False) for t in tools) + _TOOLS_SUFFIX
    system = messages[0]['content'] + '\n\n' + tools_msg \
        if messages and messages[0]['role'] == 'system' else tools_msg
    out = [f'<|start_of_role|>system<|end_of_role|>{system}<|end_of_text|>\n']
    for i, m in enumerate(messages):
        role, content = m['role'], m.get('content') or ''
        if role == 'user' or (role == 'system' and i > 0):
            out.append(f'<|start_of_role|>{role}<|end_of_role|>{content}<|end_of_text|>\n')
        elif role == 'assistant':
            out.append(f'<|start_of_role|>assistant<|end_of_role|>{content}')
            for j, call in enumerate(m.get('tool_calls') or []):
                if (j == 0 and content) or j > 0:
                    out.append('\n')
                out.append('<tool_call>\n{"name": "' + call['name'] + '", "arguments": '
                           + json.dumps(call['arguments'], ensure_ascii=False) + '}\n</tool_call>')
            out.append('<|end_of_text|>\n')
        elif role == 'tool':
            if i == 0 or messages[i - 1]['role'] != 'tool':
                out.append('<|start_of_role|>user<|end_of_role|>')
            out.append(f'\n<tool_response>\n{content}\n</tool_response>')
            if i == len(messages) - 1 or messages[i + 1]['role'] != 'tool':
                out.append('<|end_of_text|>\n')
    out.append(GENERATION_PREFIX)
    return ''.join(out)


def build_messages(cwe, context, overlay, max_calls):
    task, desc = (cwe, CWE_DESCRIPTIONS.get(cwe, cwe)) if cwe else GENERIC_TASK
    system = SYSTEM_TEMPLATE.format(max_calls=max_calls, cwe=task, cwe_description=desc)
    if cwe:
        user = (f'Search this repository for vulnerabilities matching: {cwe}. Read source '
                'files, identify vulnerable code patterns, and submit ranked vulnerable '
                'file paths only.')
    else:
        user = ('Search this repository for a vulnerability in the code the issue report '
                'below concerns. Read source files, identify vulnerable code patterns, and '
                'submit ranked vulnerable file paths only, or submit_no_vulnerability_found '
                'if the code is sound.')
    if context:
        user += ('\n\nIssue report (user-filed; it may or may not describe a security '
                 'problem):\n' + context.strip()[:4000])
    if overlay:
        user += ('\n\nSecurity map of this repository (candidate sites to inspect first):\n'
                 + overlay.strip())
    return [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]


_TOOLCALL_OPEN = '<tool_call>'


# --------------------------------------------------------------------------
# Allowlist-jail command executor — the security boundary.
# --------------------------------------------------------------------------

def _path_ok(tok, repo_root):
    """A token is safe iff, read as a path, it resolves inside repo_root.
    Every token that contains '/' or names an existing entry is resolved
    (realpath follows .. and symlinks, so absolute, ..-escaping and
    symlinked paths land outside and are rejected). A bare word that names
    nothing in the tree (a pattern like 'buf') is not a path and passes."""
    if '/' not in tok and tok not in ('.', '..') and \
            not os.path.lexists(os.path.join(repo_root, tok)):
        return True
    full = os.path.realpath(os.path.join(repo_root, tok) if not tok.startswith('/') else tok)
    root = os.path.realpath(repo_root)
    return full == root or full.startswith(root + os.sep)


def _option_path_violation(tok, repo_root):
    """Options can carry a path in the same token (--from-file=/etc/hosts,
    -f/etc/hosts). A long option's value after '=' must pass _path_ok; a
    short-option cluster may not contain a path at all (pass it as its own
    argument). Returns a rejection reason, or None."""
    if not tok.startswith('-') or tok in ('-', '--'):
        return None
    if tok.startswith('--'):
        if '=' in tok:
            val = tok.split('=', 1)[1]
            if val and not _path_ok(val, repo_root):
                return f'path in {tok!r} escapes the repository root'
        return None
    if '/' in tok or '..' in tok:
        return (f'option {tok!r} carries a path; pass the path as a separate '
                'argument inside the repository')
    return None


def _normalize_grep(argv):
    """grep -R is the model's habit (a third of its commands). It becomes
    -r, which follows no symlinks met while recursing."""
    vals = set('ABCDdefm')
    out = [argv[0]]
    for tok in argv[1:]:
        if tok == '--dereference-recursive':
            tok = '-r'
        elif tok.startswith('-') and not tok.startswith('--') and 'R' in tok:
            chars = []
            for i, ch in enumerate(tok[1:]):
                if ch in vals:
                    chars.append(tok[1 + i:])
                    break
                chars.append('r' if ch == 'R' else ch)
            tok = '-' + ''.join(chars)
        out.append(tok)
    return out


def _follow_violation(verb, args):
    longs, shorts, vals = FOLLOW_OPTIONS.get(verb, (set(), '', set()))
    for tok in args:
        if tok.split('=', 1)[0] in longs:
            return f'{verb} {tok} follows symlinks and is not permitted'
        if any(_short_cluster_has(tok, f, vals) for f in shorts):
            return f'{verb} {tok} follows symlinks and is not permitted'
    return None


def _short_cluster_has(tok, flag, takes_value=frozenset()):
    """True if short-option cluster `tok` (e.g. '-nz') sets `flag`. Scanning
    stops at the first option that takes a value — the rest is its value."""
    if not tok.startswith('-') or tok.startswith('--') or len(tok) < 2:
        return False
    for ch in tok[1:]:
        if ch == flag:
            return True
        if ch in takes_value:
            return False
    return False


def _verb_arg_violation(verb, args):
    """Per-verb write/exec option checks for the verbs that have them.
    Returns a rejection reason, or None."""
    if verb in ('find', 'du', 'sort', 'wc'):
        for tok in args:
            if tok in ('-files0-from', '--files0-from') or \
                    tok.startswith(('-files0-from=', '--files0-from=')):
                return f'{verb} {tok} reads a repo-controlled path list'
    if verb == 'tree':
        tree_vals = set('HLPITXo')
        for tok in args:
            if tok == '-o' or tok.startswith('--output=') or \
                    _short_cluster_has(tok, 'o', tree_vals):
                return f'tree {tok} writes an output file'
            if tok in ('--fromfile', '--fromtabfile'):
                return f'tree {tok} reads a repo-controlled path list'
    elif verb == 'file':
        file_vals = set('eFfmMP')
        for tok in args:
            if tok == '--compile' or _short_cluster_has(tok, 'C', file_vals):
                return 'file --compile writes a magic database'
            if tok in ('--uncompress', '--uncompress-noreport', '--no-sandbox') or \
                    any(_short_cluster_has(tok, f, file_vals) for f in 'zZS'):
                return f'file {tok} runs decompressors or drops its sandbox'
            if tok in ('-f', '--files-from') or tok.startswith('--files-from=') or \
                    _short_cluster_has(tok, 'f', file_vals):
                return f'file {tok} reads a repo-controlled path list'
    elif verb == 'rg':
        rg_vals = set('ABCEFefgjmMrtT')
        for tok in args:
            if tok in ('--pre', '--hostname-bin', '--search-zip') or \
                    tok.startswith(('--pre=', '--hostname-bin=')) or \
                    _short_cluster_has(tok, 'z', rg_vals):
                return f'rg {tok} runs another program and is not permitted'
    elif verb == 'sed':
        exprs, i = [], 0
        while i < len(args):
            tok = args[i]
            if tok == '-e':
                i += 1
                if i >= len(args):
                    return 'sed -e requires an expression'
                exprs.append(args[i])
            elif tok.startswith('-'):
                if tok not in SED_ALLOWED_OPTIONS:
                    return f'sed option {tok} is not permitted'
            elif not exprs:
                exprs.append(tok)
            i += 1
        if not exprs or not all(SED_PRINT_EXPR.fullmatch(e) for e in exprs):
            return ("sed is allowed only to print line ranges, e.g. "
                    "sed -n '120,180p' path/to/file")
    elif verb == 'sort':
        sort_vals = set('kSTto')
        for tok in args:
            if tok in ('-o', '--output') or \
                    tok.startswith(('--output=', '--compress-program',
                                    '--files0-from')) or \
                    _short_cluster_has(tok, 'o', sort_vals):
                return f'sort {tok} is not permitted (writes or runs a helper)'
    elif verb == 'uniq':
        positional, i = 0, 0
        while i < len(args):
            tok = args[i]
            if tok in ('-f', '-s', '-w'):
                i += 1
            elif not tok.startswith('-'):
                positional += 1
            i += 1
        if positional > 1:
            return 'uniq with an output file is not permitted'
    return None


def _validate_stage(argv, repo_root):
    """Validate one pipeline stage (a single program invocation).
    Returns (argv, None) if safe, or (None, reason) if rejected."""
    if not argv:
        return None, 'empty pipeline stage'
    verb = os.path.basename(argv[0])
    if verb == 'grep':
        argv = _normalize_grep(argv)
    if verb in VERB_HINTS:
        return None, VERB_HINTS[verb]
    if verb not in ALLOWED_CMDS:
        return None, (f'command "{verb}" not allowed; use only '
                      f'{sorted(ALLOWED_CMDS)}')
    violation = _verb_arg_violation(verb, argv[1:]) or _follow_violation(verb, argv[1:])
    if violation:
        return None, violation
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
        if tok.startswith('-') and tok not in ('-', '--'):
            reason = _option_path_violation(tok, repo_root)
            if reason:
                return None, reason
        elif not _path_ok(tok, repo_root):
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


def run_command_ex(cmd_str, repo_root, max_chars=DEFAULT_MAX_CHARS):
    """Validate + execute one model command (single program or a read-only
    pipeline). Returns (exit_code, output) and never raises; output is
    quarantined and cut to max_chars.

    Executes with shell=False and chains stages by wiring each Popen's stdout
    into the next stage's stdin — so `|` works without a shell interpreting the
    string. `;`, `>`, `$()`, backticks etc. are inert because no shell ever
    sees the command; they are also rejected up front for clear feedback."""
    max_chars = max(200, min(int(max_chars or DEFAULT_MAX_CHARS), MAX_OUTPUT_BYTES))
    stages, reason = validate_command(cmd_str, repo_root)
    if reason:
        return 126, f'REJECTED: {reason}'
    env = {'PATH': EXEC_PATH, 'LANG': 'C'}
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
            return 124, f'(command timed out after {PER_CMD_TIMEOUT}s)'
        # Reap upstream stages so they don't linger.
        for p in procs[:-1]:
            try:
                p.wait(timeout=2)
            except Exception:
                p.kill()
        rc = procs[-1].returncode
        out = (out_b or b'').decode('utf-8', 'replace')
        if not out:
            out = (err_b or b'').decode('utf-8', 'replace')
        out = sanitize_tool_output(out)
        if len(out) > max_chars:
            out = out[:max_chars] + '\n… [truncated]'
        return rc, out
    except FileNotFoundError as e:
        return 127, f'(program not found: {e})'
    except Exception as e:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        return 1, f'(execution error: {e})'


def run_command(cmd_str, repo_root, max_chars=MAX_OUTPUT_BYTES):
    """run_command_ex's output alone, with an empty result spelled out."""
    rc, out = run_command_ex(cmd_str, repo_root, max_chars)
    if not out:
        out = f'(exit {rc}, no output)' if rc else '(no output)'
    return out


# --------------------------------------------------------------------------
# Snapshot — the model explores a copy holding only tracked regular files.
# --------------------------------------------------------------------------

def _tracked_regular_files(repo):
    """Repo-relative paths of the tracked regular files (git modes 100644 /
    100755). Symlinks (120000) and submodules (160000) are left out. Falls
    back to a walk that skips symlinks and .git when repo is not a git tree."""
    try:
        out = subprocess.run(['git', '-C', repo, 'ls-files', '-s', '-z'],
                             capture_output=True, timeout=60, check=True).stdout
        paths = []
        for ent in out.split(b'\0'):
            if not ent:
                continue
            meta, path = ent.split(b'\t', 1)
            if meta.split()[0] in (b'100644', b'100755'):
                paths.append(path.decode('utf-8', 'surrogateescape'))
        return paths
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    paths = []
    for dirpath, dirnames, filenames in os.walk(repo, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != '.git'
                       and not os.path.islink(os.path.join(dirpath, d))]
        for f in filenames:
            full = os.path.join(dirpath, f)
            if not os.path.islink(full):
                paths.append(os.path.relpath(full, repo))
    return paths


def _sweep_stale_snapshots(base, now=None):
    now = time.time() if now is None else now
    try:
        names = os.listdir(base)
    except OSError:
        return
    for name in names:
        full = os.path.join(base, name)
        try:
            if name.startswith(SNAPSHOT_PREFIX) and \
                    now - os.lstat(full).st_mtime > SNAPSHOT_STALE_SECS:
                shutil.rmtree(full, ignore_errors=True)
        except OSError:
            pass


def materialize_snapshot(repo, base=None):
    """Build the tree the model explores: every tracked regular file of
    repo, hardlinked (copied across volumes) into a fresh directory. Entries
    that are not regular files on disk, and paths that are absolute or climb
    with '..', are skipped. Returns the snapshot path; the caller removes it."""
    base = base or SNAPSHOT_DIR
    os.makedirs(base, mode=0o700, exist_ok=True)
    _sweep_stale_snapshots(base)
    snap = tempfile.mkdtemp(prefix=SNAPSHOT_PREFIX, dir=base)
    try:
        for rel in _tracked_regular_files(repo):
            parts = rel.split('/')
            if rel.startswith('/') or '..' in parts or '' in parts:
                continue
            src = os.path.join(repo, rel)
            try:
                if not stat.S_ISREG(os.lstat(src).st_mode):
                    continue
            except OSError:
                continue
            dst = os.path.join(snap, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                os.link(src, dst, follow_symlinks=False)
            except OSError:
                shutil.copyfile(src, dst, follow_symlinks=False)
    except BaseException:
        shutil.rmtree(snap, ignore_errors=True)
        raise
    return snap


# --------------------------------------------------------------------------
# Model server (OpenAI-compatible /api/chat — Ollama / llama.cpp-server / vLLM)
# --------------------------------------------------------------------------

def generate(prompt, timeout=GENERATE_TIMEOUT):
    """One model turn: the rendered prompt, sent raw (the chat template is
    already applied) to Ollama's /api/generate. Returns the completion."""
    body = json.dumps({'model': MODEL, 'prompt': prompt, 'raw': True, 'stream': False,
                       'options': GEN_OPTIONS}).encode()
    req = urllib.request.Request(GENERATE_URL, data=body, method='POST',
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    return d.get('response', '') or ''


def parse_tool_call(content):
    """Extract the first <tool_call> JSON. Returns (name, args) or (None, None).

    The model reliably opens with `<tool_call>` but often omits the closing
    `</tool_call>` tag (it ends the turn after the JSON), so we parse the JSON
    object directly with raw_decode — which stops at the end of the object and
    ignores any trailing `</tool_call>`, whitespace, or end-of-turn text."""
    if not content:
        return None, None
    # The call follows the reasoning; a '<tool_call>' mentioned inside the
    # <think> block is not the call.
    after = content.rfind('</think>')
    marker = content.find(_TOOLCALL_OPEN, after if after != -1 else 0)
    if marker == -1:
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
    if isinstance(args, str):
        # The model sometimes emits arguments as a string: either JSON-encoded
        # (OpenAI style) or the bare terminal command itself.
        try:
            decoded = json.loads(args)
        except ValueError:
            decoded = None
        args = decoded if isinstance(decoded, dict) else {'command': args}
    if not isinstance(args, dict):
        args = {}
    return obj.get('name'), args


_REASON_KEY_HINTS = ('rational', 'reason', 'why', 'explan', 'justif', 'desc')


def _candidate_files(args):
    """Collect candidate file paths (and per-file reasons, when given) from
    submit_vulnerable_files arguments. The model is inconsistent about the
    key name — 'files', 'file_paths', 'paths', and even 'vulnerable_files[]'
    (a literal '[]' suffix) all show up — so we accept any key that mentions
    'file' or 'path', normalizing the '[]' suffix, and dedupe. Values may be
    a string, a list of strings, or a list of {path, reason} dicts (the
    shape the prompt now asks for).

    Returns (paths, reasons) — paths is the ordered dedup list; reasons maps
    path -> per-file reason for entries that carried one."""
    out, seen, reasons = [], set(), {}

    def add(x, reason=''):
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
            if reason:
                reasons[x] = reason.strip()

    def add_value(v):
        if isinstance(v, str):
            add(v)
        elif isinstance(v, dict):
            path = ''
            reason = ''
            for dk, dv in v.items():
                dkl = dk.rstrip('[]').lower()
                if ('file' in dkl or 'path' in dkl) and isinstance(dv, str):
                    path = dv
                elif any(t in dkl for t in _REASON_KEY_HINTS) and isinstance(dv, str):
                    reason = dv
            if path:
                add(path, reason)
        elif isinstance(v, list):
            for item in v:
                add_value(item)

    for key, v in args.items():
        k = key.rstrip('[]').lower()
        if 'file' in k or 'path' in k:
            add_value(v)
    return out, reasons


def _extract_rationale(args, content):
    """Pull the run-level rationale out of submit_vulnerable_files args,
    accepting the same key sloppiness _candidate_files tolerates. When the
    model put no rationale in the call at all, fall back to its own prose
    from the submitting turn — the reasoning immediately before the tool
    call almost always says why — so the dashboard/comment never shows a
    bare filename with no explanation."""
    for key, v in args.items():
        k = key.rstrip('[]').lower()
        if any(t in k for t in _REASON_KEY_HINTS) and isinstance(v, str) and v.strip():
            return v.strip()
    # Fallback: prose between the reasoning and the call, else the end of
    # the reasoning itself (the conclusion it submitted on).
    head = content
    after = content.rfind('</think>')
    call_at = content.find(_TOOLCALL_OPEN, after if after != -1 else 0)
    if call_at != -1:
        head = content[:call_at]
    think, _, prose = head.rpartition('</think>')
    prose = ' '.join(prose.split()).strip()
    if not prose and think:
        prose = ' '.join(think.replace('<think>', ' ').split()).strip()
        if len(prose) > 400:
            prose = '…' + prose[-399:]
    if len(prose) > 400:
        prose = prose[:397] + '…'
    return prose


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


# --------------------------------------------------------------------------
# Loop control — harness notices, not answer hints (no file is ever named).
# --------------------------------------------------------------------------

BUDGET_NOTICE = ('note: the terminal budget is nearly exhausted; you must call '
                 'submit_vulnerable_files or submit_no_vulnerability_found before charged '
                 'commands are exhausted. Files you have already inspected are candidates '
                 'for your final submission.')
CLOSED_NOTICE = ('note: the terminal budget is closed; call submit_vulnerable_files or '
                 'submit_no_vulnerability_found now. No further terminal commands will be '
                 'executed.')
CLOSED_REJECTED = ('error: the terminal is closed; only submit_vulnerable_files or '
                   'submit_no_vulnerability_found are available.')
UNREAD_NOTICE = 'note: search results include files that have not yet been inspected or ranked.'
DEGENERATE_NOTICE = ('error: the reply was rejected due to degenerate repetition; this turn '
                     'was not charged against the terminal budget.')
NO_CALL_NOTICE = ('You did not emit a valid tool call. Emit exactly one <tool_call> — a '
                  'terminal command, submit_vulnerable_files, or submit_no_vulnerability_found.')

_SEARCH_HIT = re.compile(r'^(?:\./)?([^:\s]+):\d+[:-]')
_READ_VERBS = {'cat', 'head', 'tail', 'nl', 'sed'}


def snapshot_files(root):
    files = set()
    for d, _, fs in os.walk(root):
        for f in fs:
            files.add(os.path.relpath(os.path.join(d, f), root))
    return files


def note_command(command, output, files, inspected, hits):
    """Track files the model read (cat/head/tail/nl/sed on a path) and files
    a search (rg/grep) turned up, from the first pipeline stage."""
    try:
        toks = shlex.split(command)
    except ValueError:
        return
    stage = toks[:toks.index('|')] if '|' in toks else toks
    if not stage:
        return
    verb = os.path.basename(stage[0])
    paths = [t.lstrip('./') for t in stage[1:] if not t.startswith('-')]
    if verb in _READ_VERBS:
        inspected.update(p for p in paths if p in files)
    elif verb in ('rg', 'grep'):
        found = set()
        for line in output.splitlines():
            m = _SEARCH_HIT.match(line.strip())
            if m and m.group(1).lstrip('./') in files:
                found.add(m.group(1).lstrip('./'))
        # A search of a single file prints bare line hits.
        if not found and output.strip():
            found.update(p for p in paths if p in files)
        hits.update(found)


def is_degenerate(text, min_seq=8, min_repeats=11):
    """True when the reply contains a run of more than ten consecutive
    repeats of the same token sequence (the model looping on itself)."""
    toks = text.split()
    n = len(toks)
    for size in range(min_seq, n // min_repeats + 1):
        for start in range(0, n - size * min_repeats + 1):
            if toks[start] != toks[start + size]:
                continue
            unit = toks[start:start + size]
            reps, pos = 1, start + size
            while pos + size <= n and toks[pos:pos + size] == unit:
                reps += 1
                pos += size
            if reps >= min_repeats:
                return True
    return False


def _tool(text):
    return {'role': 'tool', 'content': text}


def localize(repo, cwe, context, max_commands):
    """Run the agentic loop. Returns a verdict dict (fail-open)."""
    started = time.time()
    result = {'verdict': 'error', 'candidates': [], 'commands_used': 0,
              'cwe': cwe, 'transcript': [], 'duplicates_suppressed': 0,
              'degenerate_rejections': 0, 'forced_submission': False}
    messages = build_messages(cwe, context, cartographer_slice(cwe), max_commands)
    files = snapshot_files(repo)
    inspected, hits = set(), set()
    history = {}                 # command -> (turn, exit, output)
    attempts = 0                 # charged + duplicate terminal calls
    dup_run = no_call = degenerate = forced_turns = 0
    forced = escalated = False
    escalate_at = -(-max_commands * 4 // 5)      # ceil(0.8 * budget)

    def close_terminal(note):
        nonlocal forced
        forced = True
        result['forced_submission'] = True
        return note + '\n\n' + CLOSED_NOTICE if note else CLOSED_NOTICE

    max_turns = MAX_TERMINAL_ATTEMPTS + max_commands + FORCED_SUBMISSION_TURNS + 5
    for _turn in range(max_turns):
        if time.time() - started > OVERALL_TIMEOUT:
            result['verdict'] = 'timeout'
            break
        try:
            content = generate(render_prompt(messages))
        except Exception as e:
            result['verdict'] = 'server_unreachable'
            result['error'] = str(e)
            return result           # fail-open: never blocks triage

        if is_degenerate(content):
            degenerate += 1
            result['degenerate_rejections'] += 1
            if degenerate >= DEGENERATE_STOP:
                result['verdict'] = 'degenerate'
                break
            messages.append(_tool(f'exit=1\n{DEGENERATE_NOTICE}'))
            continue
        degenerate = 0

        name, args = parse_tool_call(content)
        if name not in ('terminal', 'submit_vulnerable_files', 'submit_no_vulnerability_found'):
            no_call += 1
            result.setdefault('non_call_replies', []).append((content or '')[:400])
            if no_call >= UNPARSEABLE_STOP:
                result['verdict'] = 'no_tool_call'
                result['note'] = f'no tool call after {no_call} nudges — no verdict'
                break
            stripped = re.sub(r'(?s)^.*</think>', '', content).strip()
            messages.append({'role': 'assistant', 'content': stripped})
            messages.append({'role': 'user', 'content': NO_CALL_NOTICE})
            continue
        no_call = 0
        messages.append({'role': 'assistant', 'content': '',
                         'tool_calls': [{'name': name, 'arguments': args}]})

        if name == 'submit_vulnerable_files':
            paths, per_file = _candidate_files(args)
            result['verdict'] = 'vulnerable' if paths else 'no_candidates'
            result['candidates'] = paths
            result['candidate_reasons'] = per_file
            result['rationale'] = _extract_rationale(args, content)
            break
        if name == 'submit_no_vulnerability_found':
            # A clean verdict must be earned: one given after fewer than
            # MIN_CLEAN_COMMANDS executed commands is recorded distinctly.
            result['verdict'] = ('clean' if result['commands_used'] >= MIN_CLEAN_COMMANDS
                                 else 'clean_unverified')
            break

        # terminal
        if forced:
            forced_turns += 1
            if forced_turns > FORCED_SUBMISSION_TURNS:
                result['verdict'] = 'budget_exhausted'
                break
            messages.append(_tool(f'exit=1\n{CLOSED_REJECTED}'))
            continue
        cmd = (args.get('command') or '').strip()
        max_chars = args.get('max_chars') or DEFAULT_MAX_CHARS
        attempts += 1
        prior = history.get(cmd)
        if prior is not None:
            dup_run += 1
            result['duplicates_suppressed'] += 1
            p_turn, p_rc, p_out = prior
            body = (f'note: this command was already run at turn {p_turn} with the same '
                    'output; this turn was not charged against the terminal budget.\n'
                    f'exit={p_rc}\n{p_out}')
            if dup_run >= DUPLICATE_STOP or attempts >= MAX_TERMINAL_ATTEMPTS:
                body = close_terminal(body)
            result['transcript'].append({'command': cmd, 'duplicate': True})
            messages.append(_tool(body))
            continue
        dup_run = 0
        rc, out = run_command_ex(cmd, repo, max_chars)
        result['commands_used'] += 1
        history[cmd] = (result['commands_used'], rc, out)
        note_command(cmd, out, files, inspected, hits)
        result['transcript'].append({'command': cmd, 'exit': rc, 'response': out[:500]})
        body = f'exit={rc}\n{out}'
        if hits - inspected:
            body += '\n\n' + UNREAD_NOTICE
        if result['commands_used'] >= max_commands or attempts >= MAX_TERMINAL_ATTEMPTS:
            body = close_terminal(body)
        elif result['commands_used'] >= escalate_at and not escalated:
            escalated = True
            body += '\n\n' + BUDGET_NOTICE
        messages.append(_tool(body))
    else:
        result['verdict'] = result['verdict'] if result['verdict'] != 'error' else 'budget_exhausted'

    result['inspected_files'] = sorted(inspected)
    result['unread_search_hits'] = sorted(hits - inspected)
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

    snap = None
    try:
        snap = materialize_snapshot(os.path.realpath(args.repo))
        res = localize(snap, args.cwe.strip(), args.context, args.max_commands)
    except Exception as e:
        # Absolute backstop: the Detector is advisory and must never break
        # triage, so any unexpected failure becomes an empty fail-open verdict.
        res = {'verdict': 'error', 'error': f'{type(e).__name__}: {e}',
               'candidates': [], 'cwe': args.cwe.strip()}
    finally:
        if snap:
            shutil.rmtree(snap, ignore_errors=True)
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
