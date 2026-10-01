#!/usr/bin/env python3
"""security-triage — decide whether a change needs a security audit.

Deterministic and harness-side: the caller (run-agent.sh) runs this on a
change, and only a `required` verdict lets the agent launch the read-only
`security-audit` subagent. Signals, each recorded as a reason:

  codeguard   CodeGuard findings on the changed files (codeguard-scan.sh
              JSON passed in); CG-PATH-001 is ignored
  api:<cat>   added lines call a dangerous API (categories mirror the
              call-site tagger in codegraph-extract-clangd.py)
  boundary    a changed hunk falls inside a function holding input /
              deserialization / command-exec call sites (codegraph, main)
  path        a non-GUI source file whose name has a protocol, network,
              parsing or auth word (tests/, docs/, src/gui/ ignored)

STRONG signals alone require an audit; WEAK ones (memory/format/path APIs,
which are common in ordinary C++ edits) only together with a strong one.

Fail-open: any error yields {"required": false, "error": ...} so triage
never blocks a review or a fix.

Usage:
  security-triage.py --worktree DIR [--base main] [--codeguard-json FILE]
  security-triage.py --diff-file PATH [--codeguard-json FILE]
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys

DEFAULT_DB = os.environ.get('CODEGRAPH_DB', '/Users/Shared/aetherclaude/data/codegraph.db')

CODE_EXT = ('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.m', '.mm')

# Lexical twins of DANGEROUS_C_FUNCS / DANGEROUS_QT_METHODS in
# codegraph-extract-clangd.py (that file imports clang, so it is not imported
# here). Qt entries match on the class name, since a diff line rarely spells
# the qualified method.
C_FUNCS = {
    'buffer_ops': ('strcpy', 'strcat', 'sprintf', 'vsprintf', 'memcpy', 'memmove',
                   'memset', 'strncpy', 'strncat', 'snprintf', 'gets'),
    'format': ('printf', 'fprintf', 'vprintf', 'vfprintf', 'syslog'),
    'cmd_exec': ('system', 'popen', 'execl', 'execlp', 'execle', 'execv',
                 'execvp', 'execve'),
    'path_ops': ('fopen', 'remove', 'rename', 'mkdir', 'unlink'),
    'alloc_free': ('malloc', 'calloc', 'realloc', 'free'),
    'input_read': ('recv', 'recvfrom', 'recvmsg', 'fread'),
}
QT_CLASSES = {
    'cmd_exec': ('QProcess',),
    'deserial': ('QDataStream', 'QJsonDocument', 'QCborValue', 'QXmlStreamReader'),
    'input_read': ('QTcpSocket', 'QUdpSocket', 'QSslSocket', 'QWebSocket',
                   'QLocalSocket', 'QTcpServer', 'QLocalServer', 'QWebSocketServer',
                   'QSerialPort', 'QNetworkReply', 'QNetworkAccessManager'),
}
STRONG_API = {'cmd_exec', 'deserial', 'input_read'}
WEAK_API = {'buffer_ops', 'format', 'path_ops', 'alloc_free'}

BOUNDARY_CATEGORIES = ('input_read', 'deserial', 'cmd_exec')

# Whole CamelCase words of a non-GUI source file's basename.
SENSITIVE_WORDS = {'protocol', 'server', 'client', 'socket', 'parser', 'auth',
                   'login', 'token', 'crypto', 'tls', 'ssl', 'keychain',
                   'credential', 'credentials', 'secret', 'secrets', 'wan',
                   'discovery', 'tci', 'rigctl', 'mqtt', 'http', 'download',
                   'downloader', 'updater'}
# Not product code, or UI-only: never a signal source.
EXCLUDED_PREFIXES = ('tests/', 'test/', 'docs/', 'third_party/', 'src/gui/')
_CAMEL = re.compile(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+')

_API_RES = []
for _cat, _names in C_FUNCS.items():
    _API_RES.append((_cat, re.compile(r'(?<![\w.>:])(?:std::)?(' + '|'.join(_names) + r')\s*\(')))
for _cat, _names in QT_CLASSES.items():
    _API_RES.append((_cat, re.compile(r'\b(' + '|'.join(_names) + r')\b')))


_HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@')


def parse_diff(text):
    """Return ({path: [added lines]}, {path: [(start, end) old-side ranges]})
    from a unified diff. Old-side ranges are in the base (main) coordinates
    the codegraph DB was built from."""
    files, ranges, cur = {}, {}, None
    for line in text.splitlines():
        if line.startswith('+++ '):
            path = line[4:].strip()
            if path == '/dev/null':
                cur = None
                continue
            if path.startswith('b/'):
                path = path[2:]
            cur = path
            files.setdefault(path, [])
            ranges.setdefault(path, [])
        elif line.startswith('diff --git '):
            cur = None
        elif cur is not None and line.startswith('@@'):
            m = _HUNK.match(line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                ranges[cur].append((start, start + max(count, 1) - 1))
        elif cur is not None and line.startswith('+') and not line.startswith('+++'):
            files[cur].append(line[1:])
    return files, ranges


def _in_scope(path):
    return path.endswith(CODE_EXT) and not path.startswith(EXCLUDED_PREFIXES)


def worktree_diff(worktree, base):
    mb = subprocess.run(['git', '-C', worktree, 'merge-base', base, 'HEAD'],
                        capture_output=True, text=True, timeout=30)
    ref = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else base
    out = subprocess.run(['git', '-C', worktree, 'diff', '-U0', ref],
                         capture_output=True, text=True, timeout=60)
    return out.stdout


def _strip_comment(line):
    return line.split('//', 1)[0]


def api_hits(files):
    """{category: [(path, api)]} for dangerous APIs on added code lines."""
    hits = {}
    for path, lines in files.items():
        if not _in_scope(path):
            continue
        for raw in lines:
            line = _strip_comment(raw)
            for cat, rx in _API_RES:
                m = rx.search(line)
                if m:
                    hits.setdefault(cat, []).append((path, m.group(1)))
    return hits


def boundary_functions(ranges, db_path):
    """[(path, function)] for changed hunks that overlap a function holding
    an input / deserialization / command-exec call site."""
    if not ranges or not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True, timeout=5)
    found = []
    try:
        q = ('SELECT DISTINCT s.qualified_name, s.line_number, s.end_line '
             'FROM call_tags ct JOIN symbols s ON s.id = ct.symbol_id '
             'WHERE ct.file_path = ? AND ct.category IN (%s)'
             % ','.join('?' * len(BOUNDARY_CATEGORIES)))
        for path, spans in ranges.items():
            for name, lo, hi in conn.execute(q, (path,) + BOUNDARY_CATEGORIES):
                if lo is None:
                    continue
                hi = hi if hi is not None else lo
                if any(a <= hi and b >= lo for a, b in spans):
                    found.append((path, name))
    finally:
        conn.close()
    return sorted(set(found))


def sensitive_path(path):
    if not _in_scope(path):
        return False
    stem = os.path.splitext(os.path.basename(path))[0]
    return any(w.lower() in SENSITIVE_WORDS for w in _CAMEL.findall(stem))


# CG-PATH-001 matches '../' and so also every relative #include and every
# '...' ellipsis; it fired on 131 of 132 reviewed PRs over 30 days.
CODEGUARD_IGNORED_RULES = {'CG-PATH-001'}


def codeguard_signal(findings):
    """CodeGuard findings that count toward an audit."""
    return [f for f in findings or []
            if (f.get('id') or f.get('rule_id') or '') not in CODEGUARD_IGNORED_RULES]


def triage(diff_text, codeguard_findings=None, db_path=DEFAULT_DB):
    files, ranges = parse_diff(diff_text)
    paths = sorted(files)
    reasons, strong, weak, flagged = [], False, False, set()

    cg = codeguard_signal(codeguard_findings)
    if cg:
        strong = True
        rules = sorted({f.get('id') or f.get('rule_id') or '?' for f in cg})
        reasons.append(f'codeguard: {len(cg)} finding(s) ({", ".join(rules)}) on the changed files')
        flagged.update(f['file'] for f in cg if f.get('file'))

    hits = api_hits(files)
    categories = sorted(hits)
    for cat in categories:
        apis = sorted({a for _, a in hits[cat]})
        where = sorted({p for p, _ in hits[cat]})
        reasons.append(f'api:{cat}: {", ".join(apis[:6])} added in {", ".join(where[:4])}')
        flagged.update(where)
        if cat in STRONG_API:
            strong = True
        else:
            weak = True

    try:
        bfuncs = boundary_functions({p: r for p, r in ranges.items() if _in_scope(p)}, db_path)
    except sqlite3.Error:
        bfuncs = []
    if bfuncs:
        strong = True
        flagged.update(p for p, _ in bfuncs)
        reasons.append('boundary: changes inside ' + ', '.join(f'{f} ({p})' for p, f in bfuncs[:5])
                       + ' — input/deserialization/command-exec call sites')

    spath = [p for p in paths if sensitive_path(p)]
    if spath:
        strong = True
        flagged.update(spath)
        reasons.append(f'path: {", ".join(spath[:6])}')

    required = strong
    if weak and not strong:
        reasons.append('weak signals only (memory/format/path APIs) — no audit')
    return {'required': required, 'reasons': reasons, 'categories': categories,
            'files': sorted(flagged), 'changed_files': len(paths)}


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--worktree')
    src.add_argument('--diff-file')
    ap.add_argument('--base', default='main')
    ap.add_argument('--codeguard-json', help='codeguard-scan.sh output ({"findings": [...]})')
    ap.add_argument('--db', default=DEFAULT_DB)
    a = ap.parse_args()
    try:
        if a.diff_file:
            with open(a.diff_file, errors='replace') as fh:
                diff = fh.read()
        else:
            diff = worktree_diff(a.worktree, a.base)
        findings = []
        if a.codeguard_json:
            try:
                with open(a.codeguard_json) as fh:
                    findings = json.load(fh).get('findings') or []
            except (OSError, ValueError):
                findings = []
        result = triage(diff, findings, a.db)
    except Exception as e:  # fail-open: triage must never block the caller
        result = {'required': False, 'reasons': [], 'categories': [], 'files': [],
                  'error': f'{type(e).__name__}: {e}'}
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
