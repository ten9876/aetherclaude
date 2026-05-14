#!/usr/bin/env python3
"""
codegraph-extract — universal-ctags-driven C++ symbol extractor.

Walks an AetherSDR src/ tree, runs ctags to enumerate every named C++
symbol (class, struct, function, method, Qt signal/slot), then derives
relationship edges (calls, inheritance, Qt signal-slot connections)
and writes the result to a SQLite database.

This is the Phase 1 MVP extractor per docs/codegraph-plan. Trades
template-instantiation and virtual-dispatch precision for ~3 s runtime
and zero AST-toolchain setup. Phase 2 swaps in clangd for AST-accurate
edges; the output schema doesn't change so the dashboard side is
unaffected by the upgrade.

Usage:
    codegraph-extract.py <src_root> [<output_db>]

Defaults:
    src_root  = /Users/aetherclaude/workspace/AetherSDR/src
    output_db = /Users/aetherclaude/data/codegraph.db

Idempotent. Truncates and rebuilds the db on every run.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable

# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;

DROP TABLE IF EXISTS edges;
DROP TABLE IF EXISTS file_to_symbols;
DROP TABLE IF EXISTS symbols;
DROP TABLE IF EXISTS metadata;

CREATE TABLE symbols (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    qualified_name  TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,           -- class/struct/function/method/signal/slot
    file_path       TEXT NOT NULL,           -- relative to src_root.parent (e.g. 'src/gui/Foo.cpp')
    line_number     INTEGER,
    end_line        INTEGER,
    parent_scope    TEXT,                    -- enclosing class/namespace, NULL for free symbols
    signature       TEXT,
    community_id    INTEGER,
    community_label TEXT,
    degree          INTEGER DEFAULT 0,
    in_degree       INTEGER DEFAULT 0,
    out_degree      INTEGER DEFAULT 0,
    x_coord         REAL,
    y_coord         REAL
);
CREATE INDEX idx_symbols_name ON symbols(name);
CREATE INDEX idx_symbols_file ON symbols(file_path);
CREATE INDEX idx_symbols_community ON symbols(community_id);

CREATE TABLE edges (
    id      INTEGER PRIMARY KEY,
    src_id  INTEGER NOT NULL REFERENCES symbols(id),
    dst_id  INTEGER NOT NULL REFERENCES symbols(id),
    kind    TEXT NOT NULL,                   -- calls / inherits / signal-slot
    UNIQUE(src_id, dst_id, kind)
);
CREATE INDEX idx_edges_src ON edges(src_id);
CREATE INDEX idx_edges_dst ON edges(dst_id);
CREATE INDEX idx_edges_kind ON edges(kind);

-- Phase-3 live-overlay support: map a file path to every symbol declared
-- in it. A single claude:Read or claude:Edit event referencing a file
-- can then pulse all the symbols at once.
CREATE TABLE file_to_symbols (
    file_path  TEXT NOT NULL,
    symbol_id  INTEGER NOT NULL REFERENCES symbols(id),
    UNIQUE(file_path, symbol_id)
);
CREATE INDEX idx_f2s_file ON file_to_symbols(file_path);

CREATE TABLE metadata (
    key    TEXT PRIMARY KEY,
    value  TEXT
);
"""

# --------------------------------------------------------------------------
# ctags driver
# --------------------------------------------------------------------------

# The kinds we keep as graph nodes. ctags emits many more (member,
# variable, enumerator, typedef…); those add visual clutter without
# adding structural insight at this granularity.
NODE_KINDS = {'class', 'struct', 'function', 'method', 'signal', 'slot'}

# When a name appears with both 'function' and 'prototype' kinds (the
# usual definition-in-cpp + declaration-in-header pattern), prefer the
# function row. ctags can also report 'prototype' for header-only
# functions where there's no separate definition; for those we promote
# to 'function' so they end up as nodes.
PROMOTE_PROTOTYPE = True

# Ctags fields we ask for. The output format is text, tab-delimited,
# with extension fields after `;"` as `name:value` pairs.
#   l = language
#   n = line number
#   e = end line  (requires --fields-c++=+{end} or --fields=+e in newer)
#   K = full-kind name (e.g., "function" instead of "f")
#   S = signature
#   i = inherits (for class/struct)
#   s = scope    (e.g., "class:Foo::Bar")
CTAGS_FIELDS = '+lneKSis'
CTAGS_KINDS = '+pmfcsg'   # prototype, member, function, class, struct, signal+slot via Qt extension

# `c++-kinds` already includes signal/slot when the source uses Q_OBJECT,
# but we explicitly enable them just in case.


def find_ctags_binary() -> str:
    """Prefer brew's ctags (universal-ctags on Mac Mini) over the
    BSD ctags at /usr/bin/ctags."""
    candidates = [
        '/opt/homebrew/bin/ctags',
        '/usr/local/bin/ctags',
        '/usr/bin/ctags',
    ]
    for c in candidates:
        if os.path.exists(c):
            # Quick sniff — universal-ctags responds to --version with
            # 'Universal Ctags'. BSD ctags will exit non-zero on that flag.
            try:
                r = subprocess.run(
                    [c, '--version'],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and (
                    'Universal Ctags' in r.stdout
                    or 'Exuberant Ctags' in r.stdout
                ):
                    return c
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    # PATH fallback
    return 'ctags'


def run_ctags(src_root: Path, ctags_bin: str) -> Iterable[dict]:
    """Yield one dict per ctags row, with parsed extension fields."""
    # DO NOT pass --extras=+q. It emits a *second* row per symbol with
    # the name already qualified, which (1) doubles the symbol count
    # via dedup-by-qname mismatch, and (2) breaks call-site lookup
    # because the unqualified-name index ends up keyed by qualified
    # names that won't match `foo(` patterns in source.
    cmd = [
        ctags_bin,
        '-R',
        f'--c++-kinds={CTAGS_KINDS}',
        f'--fields={CTAGS_FIELDS}',
        '-f', '-',
        str(src_root),
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip('\n')
        if not line or line.startswith('!'):
            continue
        row = _parse_ctags_line(line)
        if row is not None:
            yield row
    rc = proc.wait()
    if rc != 0:
        stderr = proc.stderr.read() if proc.stderr else ''
        raise RuntimeError(f'ctags exited {rc}: {stderr[:200]}')


def _parse_ctags_line(line: str) -> dict | None:
    """Parse a single ctags-format line into a structured dict, or
    return None if the line doesn't match the expected shape."""
    # Format: name\tpath\t/^pattern$/;"\tkind\tk:v\tk:v...
    # The `;"` terminates the search pattern. After that, the rest is
    # tab-separated extension fields. The first field is the kind.
    tab_idx_1 = line.find('\t')
    if tab_idx_1 < 0:
        return None
    tab_idx_2 = line.find('\t', tab_idx_1 + 1)
    if tab_idx_2 < 0:
        return None
    sep = line.find(';"\t', tab_idx_2 + 1)
    if sep < 0:
        return None
    name = line[:tab_idx_1]
    path = line[tab_idx_1 + 1:tab_idx_2]
    # Skip the search pattern; jump straight to extension fields.
    after = line[sep + 3:]
    parts = after.split('\t')
    if not parts:
        return None
    kind = parts[0]
    fields: dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition(':')
        if _:
            fields[k] = v
    return {
        'name': name,
        'path': path,
        'kind': kind,
        # Match the symbols-table column names so downstream code can
        # pass the dict straight through.
        'line_number': int(fields.get('line', '0') or '0') or None,
        'end_line': int(fields.get('end', '0') or '0') or None,
        'parent_scope': _extract_scope(fields),
        'signature': fields.get('signature'),
        'inherits': fields.get('inherits'),
        'language': fields.get('language'),
    }


def _extract_scope(fields: dict[str, str]) -> str | None:
    """ctags emits scope as multiple possible keys: class:, struct:,
    namespace:. Return the value of whichever is present."""
    for key in ('class', 'struct', 'namespace', 'union'):
        if key in fields:
            return fields[key]
    # Combined form: scope as 'class:Foo::Bar' in some configs
    if 'scope' in fields:
        # 'class:Foo' or just 'Foo'
        s = fields['scope']
        return s.split(':', 1)[-1]
    return None


# --------------------------------------------------------------------------
# Call edge extraction (Phase 1 simplified)
# --------------------------------------------------------------------------

# Strip C/C++ block + line comments AND string/char literals before
# scanning for call sites. Preserves newline positions so line numbers
# line up.
RE_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
RE_LINE_COMMENT  = re.compile(r'//[^\n]*')
RE_STRING_LIT    = re.compile(r'"(?:\\.|[^"\\])*"')
RE_CHAR_LIT      = re.compile(r"'(?:\\.|[^'\\])*'")

KEYWORDS = {
    'if', 'while', 'for', 'switch', 'return', 'sizeof', 'alignof',
    'static_cast', 'dynamic_cast', 'const_cast', 'reinterpret_cast',
    'new', 'delete', 'throw', 'catch', 'typeid', 'noexcept',
    'decltype', 'typeof', 'goto', 'case',
    'default', 'break', 'continue', 'do', 'else',
    'true', 'false', 'nullptr', 'this', 'operator',
    # C++ stdlib noise we don't want as call targets:
    'static_assert',
}

# A "call" candidate: an identifier followed by an open paren.
RE_CALL_SITE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

# Qt connect with member-pointer syntax:
#   connect(sender, &Sender::sig, receiver, &Receiver::slot)
RE_QT_CONNECT = re.compile(
    r'\bconnect\s*\(\s*'
    r'[^,]+,\s*'
    r'&([A-Za-z_][\w]*)::([A-Za-z_][\w]*)\s*,\s*'
    r'[^,]+,\s*'
    r'&([A-Za-z_][\w]*)::([A-Za-z_][\w]*)'
)


def strip_comments_and_strings(text: str) -> str:
    def _blank_keep_newlines(m: re.Match) -> str:
        return re.sub(r'[^\n]', ' ', m.group(0))
    text = RE_BLOCK_COMMENT.sub(_blank_keep_newlines, text)
    text = RE_LINE_COMMENT.sub('', text)
    text = RE_STRING_LIT.sub('""', text)
    text = RE_CHAR_LIT.sub("''", text)
    return text


def line_of_offset(text: str, offset: int) -> int:
    return text.count('\n', 0, offset) + 1


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src_root', nargs='?',
                    default='/Users/aetherclaude/workspace/AetherSDR/src',
                    help='Path to AetherSDR src/ directory')
    ap.add_argument('output_db', nargs='?',
                    default='/Users/aetherclaude/data/codegraph.db',
                    help='Output SQLite database path')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    src_root = Path(args.src_root).resolve()
    if not src_root.exists():
        print(f'ERROR: src_root does not exist: {src_root}', file=sys.stderr)
        sys.exit(1)
    out_db = Path(args.output_db).resolve()
    out_db.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    ctags_bin = find_ctags_binary()
    print(f'codegraph-extract: ctags={ctags_bin}  src={src_root}',
          file=sys.stderr)

    # ------------------------------------------------------------------
    # Pass 1 — collect ctags rows. Build a flat list, then dedupe.
    # ------------------------------------------------------------------
    raw_rows: list[dict] = []
    for r in run_ctags(src_root, ctags_bin):
        # Filter to node-worthy kinds. Promote prototype → function so
        # header-only declarations still appear as nodes (they're real
        # callable surface area).
        if r['kind'] == 'prototype' and PROMOTE_PROTOTYPE:
            r['kind'] = 'function'
        if r['kind'] not in NODE_KINDS:
            continue
        raw_rows.append(r)
    print(f'  {len(raw_rows)} ctags rows after kind filter', file=sys.stderr)

    # Build symbols by qualified_name (dedupe). When the same name
    # appears as both 'function' definition AND 'prototype' (now
    # promoted to function), the FIRST one wins, but we prefer rows
    # with a body (end_line > line_number) — those are definitions
    # rather than declarations.
    by_qname: dict[str, dict] = {}
    for r in raw_rows:
        qn = f"{r['parent_scope']}::{r['name']}" if r['parent_scope'] else r['name']
        existing = by_qname.get(qn)
        if existing is None:
            r['qualified_name'] = qn
            by_qname[qn] = r
            continue
        # Prefer the row with an end-line (full definition) over a
        # prototype/declaration.
        if r.get('end_line') and not existing.get('end_line'):
            r['qualified_name'] = qn
            by_qname[qn] = r
    symbols = list(by_qname.values())
    for i, s in enumerate(symbols, start=1):
        s['id'] = i

    # Compute rel paths for everything (file_path stored as 'src/.../Foo.cpp')
    src_parent = src_root.parent
    for s in symbols:
        try:
            s['file_path'] = str(Path(s['path']).resolve().relative_to(src_parent))
        except ValueError:
            s['file_path'] = s['path']

    print(f'  {len(symbols)} unique symbols after dedupe', file=sys.stderr)

    # Indexes for edge resolution
    name_to_id: dict[str, int] = {s['qualified_name']: s['id'] for s in symbols}
    unqualified_to_ids: dict[str, list[int]] = defaultdict(list)
    for s in symbols:
        unqualified_to_ids[s['name']].append(s['id'])

    # Group symbols by file for per-file call extraction
    symbols_by_file: dict[str, list[dict]] = defaultdict(list)
    for s in symbols:
        symbols_by_file[s['file_path']].append(s)

    # ------------------------------------------------------------------
    # Pass 2 — extract edges.
    # ------------------------------------------------------------------
    edges: set[tuple[int, int, str]] = set()

    # 2a. Inheritance: from ctags 'inherits:' field on class/struct rows.
    # The field is a comma-separated list of base class names.
    for s in symbols:
        if s['kind'] not in ('class', 'struct'):
            continue
        inh_raw = s.get('inherits') or ''
        if not inh_raw:
            continue
        for base in (b.strip() for b in inh_raw.split(',')):
            if not base:
                continue
            # Strip template args, leading qualifier
            base = base.split('<')[0].split('::')[-1]
            for dst_id in unqualified_to_ids.get(base, []):
                if dst_id == s['id']:
                    continue
                edges.add((s['id'], dst_id, 'inherits'))

    # 2b. Calls + signal-slot: walk file contents.
    # For Phase 1 we attribute every call to "the function/method
    # whose [line, end_line] range contains the call site". When end_line
    # is missing (header-only declarations), the symbol gets no
    # call edges from this pass (it's an interface, not an
    # implementation — fair to leave edge-less).
    files_scanned = 0
    defined_names = set(unqualified_to_ids.keys())
    for file_path, file_symbols in symbols_by_file.items():
        # Only scan source files we have on disk
        abs_path = src_parent / file_path
        if not abs_path.exists():
            continue
        try:
            text = abs_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        text = strip_comments_and_strings(text)
        files_scanned += 1

        # Build a sorted list of (line, end, id) for callable symbols
        # in this file. Used to attribute each call site to its
        # enclosing function.
        callable_ranges = sorted(
            (s['line_number'], s['end_line'] or s['line_number'], s['id'])
            for s in file_symbols
            if s['kind'] in ('function', 'method', 'signal', 'slot')
            and s.get('line_number')
        )

        def enclosing_function_id(call_line: int) -> int | None:
            # Linear scan — small range list (~hundreds per file).
            best = None
            for start, end, sid in callable_ranges:
                if start <= call_line <= end:
                    if best is None or start > best[0]:
                        best = (start, end, sid)
            return best[2] if best else None

        # Call sites
        for m in RE_CALL_SITE.finditer(text):
            callee_name = m.group(1)
            if callee_name in KEYWORDS:
                continue
            target_ids = unqualified_to_ids.get(callee_name)
            if not target_ids:
                continue
            call_line = line_of_offset(text, m.start())
            src_id = enclosing_function_id(call_line)
            if src_id is None:
                continue
            for dst_id in target_ids:
                if dst_id == src_id:
                    continue
                edges.add((src_id, dst_id, 'calls'))

        # Qt signal-slot
        for sender_cls, sig, recv_cls, slot in RE_QT_CONNECT.findall(text):
            sig_qn = f'{sender_cls}::{sig}'
            slot_qn = f'{recv_cls}::{slot}'
            src_id = name_to_id.get(sig_qn)
            dst_id = name_to_id.get(slot_qn)
            if src_id and dst_id and src_id != dst_id:
                edges.add((src_id, dst_id, 'signal-slot'))

    print(f'  {files_scanned} files scanned, {len(edges)} edges',
          file=sys.stderr)

    # Degree counts
    in_deg: dict[int, int] = defaultdict(int)
    out_deg: dict[int, int] = defaultdict(int)
    for src_id, dst_id, _ in edges:
        out_deg[src_id] += 1
        in_deg[dst_id] += 1

    # ------------------------------------------------------------------
    # Write SQLite
    # ------------------------------------------------------------------
    if out_db.exists():
        out_db.unlink()
    conn = sqlite3.connect(out_db)
    conn.executescript(SCHEMA)
    conn.executemany(
        'INSERT INTO symbols (id, name, qualified_name, kind, file_path, '
        'line_number, end_line, parent_scope, signature, '
        'degree, in_degree, out_degree) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        [
            (s['id'], s['name'], s['qualified_name'], s['kind'],
             s['file_path'], s.get('line_number'),
             s.get('end_line'),
             s.get('parent_scope'), s.get('signature'),
             out_deg.get(s['id'], 0) + in_deg.get(s['id'], 0),
             in_deg.get(s['id'], 0), out_deg.get(s['id'], 0))
            for s in symbols
        ],
    )
    conn.executemany(
        'INSERT OR IGNORE INTO edges (src_id, dst_id, kind) VALUES (?,?,?)',
        list(edges),
    )
    conn.executemany(
        'INSERT OR IGNORE INTO file_to_symbols (file_path, symbol_id) VALUES (?,?)',
        [(s['file_path'], s['id']) for s in symbols],
    )

    metadata = {
        'extracted_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'src_root': str(src_root),
        'ctags_binary': ctags_bin,
        'extractor_version': '2.0.0-ctags',
        'symbol_count': str(len(symbols)),
        'edge_count': str(len(edges)),
        'file_count': str(files_scanned),
        'extraction_seconds': f'{time.time() - t0:.2f}',
        # community + layout are filled in by codegraph-analyze.py
        'community_count': '0',
        'layout_computed': 'false',
    }
    conn.executemany(
        'INSERT INTO metadata (key, value) VALUES (?,?)',
        list(metadata.items()),
    )
    conn.commit()
    conn.close()

    print(
        f'codegraph-extract done in {time.time()-t0:.1f}s — '
        f'{len(symbols)} symbols, {len(edges)} edges → {out_db}',
        file=sys.stderr,
    )
    print('Next: run codegraph-analyze.py to compute communities + layout.',
          file=sys.stderr)


if __name__ == '__main__':
    main()
