"""CI job-log failure classifier shared by the dashboard and the
contributor scorer: the most likely cause of a failed GitHub Actions job,
from its log text."""
import re

_LOG_TS_RE = re.compile(r'^\d{4}-\d\d-\d\dT[\d:.]+Z ?')
_SRC_RE = r'([\w./+-]+\.(?:cpp|cc|cxx|c|h|hpp|mm|m))'

def _diagnose_log(log):
    """Most likely cause of a failed job, from its log. Infrastructure
    failures (disk, memory, time, runner) outrank code errors because they
    produce misleading secondary errors (a full disk shows up as missing
    object files)."""
    lines = [_LOG_TS_RE.sub('', l).rstrip() for l in (log or '').splitlines()]
    text = '\n'.join(lines)
    def file_near(i):
        for k in range(i, max(-1, i - 40), -1):
            m = re.search(r'FAILED: \S*?(src/[\w./+-]+?)\.o\b', lines[k]) or re.search(_SRC_RE + r':\d+', lines[k])
            if m:
                return m.group(1)
        return None
    def first(pat):
        rx = re.compile(pat)
        for i, l in enumerate(lines):
            m = rx.search(l)
            if m:
                return i, m
        return None, None
    i, m = first(r'No space left on device')
    if m:
        return {'kind': 'disk', 'summary': 'runner out of disk', 'file': file_near(i),
                'detail': lines[i].strip()[:240]}
    i, m = first(r'Killed signal terminated program (\S+)|fatal error: Killed|virtual memory exhausted|Cannot allocate memory')
    if m:
        return {'kind': 'oom', 'summary': 'out of memory (compiler killed)', 'file': file_near(i),
                'detail': lines[i].strip()[:240]}
    i, m = first(r'has exceeded the maximum execution time|The job was canceled because .*timeout|timed out after')
    if m:
        return {'kind': 'timeout', 'summary': 'timed out', 'file': None, 'detail': lines[i].strip()[:240]}
    i, m = first(r'lost communication with the server|The runner has received a shutdown signal|runner .* did not respond')
    if m:
        return {'kind': 'runner', 'summary': 'runner lost', 'file': None, 'detail': lines[i].strip()[:240]}
    i, m = first(r'internal compiler error')
    if m:
        return {'kind': 'ice', 'summary': 'internal compiler error', 'file': file_near(i),
                'detail': lines[i].strip()[:240]}
    i, m = first(_SRC_RE + r':(\d+)(?::\d+)?: (?:fatal )?error: (.*)')
    if m:
        return {'kind': 'compile', 'summary': 'compile error', 'file': f'{m.group(1)}:{m.group(2)}',
                'detail': m.group(3).strip()[:240]}
    i, m = first(r'([\w.:\\/+-]+\.(?:cpp|cc|cxx|c|h|hpp))\((\d+)(?:,\d+)?\): (?:fatal )?error (C\d+): (.*)')
    if m:
        return {'kind': 'compile', 'summary': f'compile error {m.group(3)}', 'file': f'{m.group(1)}:{m.group(2)}',
                'detail': m.group(4).strip()[:240]}
    i, m = first(r'([\w.:\\/+-]+\.obj) : error (LNK\d+): (.*)|LINK : fatal error (LNK\d+)')
    if m:
        return {'kind': 'link', 'summary': 'link error', 'file': None, 'detail': lines[i].strip()[:240]}
    i, m = first(r'undefined reference to [`\'](.+?)\'|ld(?:\.\w+)?: error: (.*)|collect2: error')
    if m:
        return {'kind': 'link', 'summary': 'link error', 'file': None, 'detail': lines[i].strip()[:240]}
    i, m = first(r'CMake Error at (\S+)')
    if m:
        nxt = next((l.strip() for l in lines[i + 1:i + 6] if l.strip()), '')
        return {'kind': 'configure', 'summary': 'CMake configure error', 'file': m.group(1).rstrip(':'),
                'detail': nxt[:240]}
    i, m = first(r'(?:ERROR: (AddressSanitizer|ThreadSanitizer|LeakSanitizer|MemorySanitizer)|WARNING: (ThreadSanitizer)): ?(.*)')
    if m:
        san = m.group(1) or m.group(2)
        return {'kind': 'sanitizer', 'summary': f'{san} report', 'file': file_near(i),
                'detail': (m.group(3) or '').strip()[:240]}
    i, m = first(_SRC_RE + r':(\d+):\d+: runtime error: (.*)')
    if m:
        return {'kind': 'sanitizer', 'summary': 'UBSan runtime error', 'file': f'{m.group(1)}:{m.group(2)}',
                'detail': m.group(3).strip()[:240]}
    i, m = first(r'(\d+)% tests passed, ([1-9]\d*) tests? failed out of (\d+)')
    if m:
        return {'kind': 'tests', 'summary': f'{m.group(2)} of {m.group(3)} tests failed', 'file': None,
                'detail': ''}
    errs = [l for l in lines if l.startswith('##[error]')]
    if errs:
        return {'kind': 'other', 'summary': errs[0][9:].strip()[:120] or 'failed', 'file': None, 'detail': ''}
    return None

def _diagnose_log_clean(log):
    """_diagnose_log with runner workspace prefixes trimmed from paths."""
    d = _diagnose_log(log)
    if d:
        for k in ('file', 'detail'):
            if d.get(k):
                d[k] = re.sub(r'(?:[A-Za-z]:)?[/\\][^\s:]*?[/\\](?=(?:src|tests|tools|third_party|CMakeLists)\b)', '', d[k])
    return d


_FAILED_TEST_RE = re.compile(r'^\s*\d+\s+-\s+([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)')


def failed_tests_from_log(log):
    """Test names from ctest's last 'The following tests FAILED:' block."""
    out, inside = [], False
    for raw in (log or '').splitlines():
        line = _LOG_TS_RE.sub('', raw)
        # The exact ctest header only: a step's script source, echoed into
        # the log, quotes this phrase too.
        if line.strip() == 'The following tests FAILED:':
            inside, out = True, []
            continue
        if inside:
            m = _FAILED_TEST_RE.match(line)
            if m:
                out.append(m.group(1))
            elif line.strip():
                inside = False
    return sorted(set(out))
