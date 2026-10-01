"""Unit tests for antares-detector.py's read-only command allowlist.

Run: python3 tests/test_antares_detector_allowlist.py
Exits non-zero on any failure with a one-line summary per case.

The invariant under test: every command the model can get executed only
reads inside the repository. rg, sed, sort and uniq are allowed, but each
has options that write a file or run another program; those options must
be rejected while the read-only forms the model actually uses go through.

Covers:
  - validate_command accepts the read-only forms of every allowlisted verb
  - rg --pre / --hostname-bin / --search-zip / -z (incl. clusters) rejected
  - sed accepts only line-range printing; -i, w, e and s/// are rejected
  - sort -o / --output / --compress-program and uniq output files rejected
  - tree output files / --fromfile, file --compile / decompression / sandbox
    escape / path lists, and --files0-from on find/du/sort/wc rejected
  - path arguments outside the repo rejected for the new verbs too
  - cd and xargs are rejected with a usage hint, not the generic message
  - parse_tool_call keeps the command when arguments is a bare or
    JSON-encoded string instead of an object
  - three replies without a tool call end as verdict no_tool_call (not
    clean) and the replies are kept in the result
  - run_command executes rg and sed against a temp repo (skipped if rg absent)
"""
import importlib.util
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    'antares_detector', os.path.join(HERE, '..', 'bin', 'antares-detector.py'))
det = importlib.util.module_from_spec(spec)
spec.loader.exec_module(det)

failures = []


def check(name, cond):
    if not cond:
        failures.append(name)
        print(f'FAIL {name}')


repo = tempfile.mkdtemp(prefix='antares-allowlist-')
try:
    os.makedirs(os.path.join(repo, 'src'))
    with open(os.path.join(repo, 'src', 'a.cpp'), 'w') as fh:
        fh.write(''.join(f'line {n} memcpy(dst, src, len);\n' for n in range(1, 21)))

    allowed = [
        'rg -n "memcpy" src',
        'rg -n -B5 -A20 "memcpy" src/a.cpp',
        'rg -n "memcpy" src | head -n 5',
        'rg -nA3 "z" src',               # 'z' here is the -A value, not --search-zip
        "sed -n '3,8p' src/a.cpp",
        "sed -n -e '3p' -e '$p' src/a.cpp",
        'grep -rIn "memcpy" src | sort | uniq -c',
        'sort -k2 src/a.cpp',
        'uniq src/a.cpp',
        'pwd',
        'tree -L 2 src',
        'diff src/a.cpp src/a.cpp',
        'file src/a.cpp',
        'stat src/a.cpp',
        'du -sh src',
        'basename src/a.cpp',
        'dirname src/a.cpp',
        'realpath src/a.cpp',
        'echo hi',
        'true',
        'false',
    ]
    for cmd in allowed:
        stages, reason = det.validate_command(cmd, repo)
        check(f'allowed: {cmd} ({reason})', stages is not None)

    rejected = [
        'rg --pre cat x src',
        'rg --pre=/bin/sh x src',
        'rg --hostname-bin=/bin/sh x src',
        'rg --search-zip x src',
        'rg -z x src',
        'rg -nz x src',
        "sed -i 's/a/b/' src/a.cpp",
        "sed -n '1w out' src/a.cpp",
        "sed 's/a/b/' src/a.cpp",
        "sed -n '1e id' src/a.cpp",
        "sed -f script.sed src/a.cpp",
        'sort -o out src/a.cpp',
        'sort --output=out src/a.cpp',
        'sort -uo out src/a.cpp',
        'sort --compress-program=sh src/a.cpp',
        'uniq src/a.cpp out',
        'tree -o out src',
        'tree --output=out src',
        'tree -ao out src',
        'tree --fromfile src/list',
        'file --compile -m src/a.cpp',
        'file -C -m src/a.cpp',
        'file -z src/a.cpp',
        'file --no-sandbox src/a.cpp',
        'file -f src/list',
        'file --files-from=src/list',
        'du --files0-from=src/list',
        'wc --files0-from=src/list',
        'find --files0-from=src/list',
        'diff src/a.cpp /etc/passwd',
        'realpath ../outside',
        'xargs cat',
        'cd src',
        'awk 1 src/a.cpp',
    ]
    for cmd in rejected:
        stages, reason = det.validate_command(cmd, repo)
        check(f'rejected: {cmd}', stages is None)

    _, reason = det.validate_command('cd src', repo)
    check('cd gets a usage hint', reason is not None and 'relative paths' in reason)
    _, reason = det.validate_command('find src -name "*.cpp" | xargs grep x', repo)
    check('xargs gets a usage hint', reason is not None and 'xargs is not supported' in reason)

    if shutil.which('rg', path=det.EXEC_PATH) or shutil.which('rg'):
        if not shutil.which('rg', path=det.EXEC_PATH):
            det.EXEC_PATH += os.pathsep + os.path.dirname(shutil.which('rg'))
        out = det.run_command('rg -n "line 7 " src/a.cpp', repo)
        check(f'rg executes ({out!r})', '7:line 7 memcpy' in out)
    else:
        print('SKIP rg execution (rg not installed)')
    parse_cases = [
        ('<tool_call>{"name": "terminal", "arguments": {"command": "ls src"}}',
         'ls src'),
        ('<tool_call>{"name": "terminal", "arguments": "rg -n \\"free\\\\(\\" src"}}\n</think>',
         'rg -n "free\\(" src'),
        ('<tool_call>{"name": "terminal", "arguments": "{\\"command\\": \\"ls src\\"}"}',
         'ls src'),
    ]
    for content, want in parse_cases:
        name, args = det.parse_tool_call(content)
        check(f'parse_tool_call {content[:60]!r} -> {args!r}',
              name == 'terminal' and args.get('command') == want)

    real_chat = det.chat
    det.chat = lambda messages, timeout=60: 'I think the bug is somewhere in src.'
    try:
        res = det.localize(repo, '', 'test context', 15)
    finally:
        det.chat = real_chat
    check(f'no tool call -> no_tool_call verdict ({res.get("verdict")})',
          res.get('verdict') == 'no_tool_call')
    check('non-call replies are kept for diagnosis',
          res.get('non_call_replies') == ['I think the bug is somewhere in src.'] * 3)

    out = det.run_command("sed -n '4,5p' src/a.cpp", repo)
    check(f'sed prints a line range ({out!r})', out.splitlines() == [
        'line 4 memcpy(dst, src, len);', 'line 5 memcpy(dst, src, len);'])
finally:
    shutil.rmtree(repo, ignore_errors=True)

if failures:
    print(f'{len(failures)} failure(s)')
    sys.exit(1)
print('all antares-detector allowlist checks passed')
