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
  - cd and xargs are rejected with a usage hint, not the generic message
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
    out = det.run_command("sed -n '4,5p' src/a.cpp", repo)
    check(f'sed prints a line range ({out!r})', out.splitlines() == [
        'line 4 memcpy(dst, src, len);', 'line 5 memcpy(dst, src, len);'])
finally:
    shutil.rmtree(repo, ignore_errors=True)

if failures:
    print(f'{len(failures)} failure(s)')
    sys.exit(1)
print('all antares-detector allowlist checks passed')
