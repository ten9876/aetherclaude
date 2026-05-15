#!/usr/bin/env python3
"""
codegraph-extract-clangd — libclang-based C++ symbol/call extractor.

Phase-2 successor to codegraph-extract.py (ctags). Uses libclang's AST
via the python-clang bindings, driven by a compile_commands.json
produced by `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.

Why this exists:
  ctags resolves call edges by *name*. AetherSDR has ~10 free-function
  `instance()` singletons that ctags collapses into a single "instance"
  node with degree 483 — a phantom hub that doesn't exist in the actual
  call graph. libclang resolves each call to the *defined* symbol
  (via clang's USR — Unified Symbol Resolution), eliminating these
  false hubs. It also picks up:
    - Qt signal-slot connections (parsed from `connect(...)` arg lists)
    - Inheritance through templates
    - Virtual dispatch

Schema is identical to the ctags extractor's so the dashboard and
codegraph-analyze.py work unchanged.

Runtime: ~3-4 minutes for the full AetherSDR src/ on 8 cores. Too slow
for per-PR, fine for nightly. Memory: ~300 MB peak (parallel workers).

Usage:
    codegraph-extract-clangd.py <src_root> <db_path> [<compile_commands.json>]

If compile_commands.json is omitted, the script searches for it at
  <src_root>/../build/compile_commands.json
which is the standard cmake build dir for AetherSDR.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import shlex
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# Defer libclang import to inside main() / workers so that the worker
# child processes get fresh Index instances. Top-level Config.set_library_file
# is idempotent and cheap.
try:
    from clang.cindex import Config, Index, CursorKind, TranslationUnit
except ImportError as e:
    print(f'ERROR: python-clang not available ({e}).', file=sys.stderr)
    print('Install with: pip install --user clang', file=sys.stderr)
    sys.exit(1)

# Try common libclang paths. On Arch the unversioned .so exists; on
# Mac with brew llvm it's under /opt/homebrew/opt/llvm/lib.
_LIBCLANG_CANDIDATES = [
    '/usr/lib/libclang.so',
    '/usr/lib64/libclang.so',
    '/opt/homebrew/opt/llvm/lib/libclang.dylib',
    '/usr/local/opt/llvm/lib/libclang.dylib',
]
for _p in _LIBCLANG_CANDIDATES:
    if os.path.exists(_p):
        Config.set_library_file(_p)
        break


# --------------------------------------------------------------------------
# Schema (identical to codegraph-extract.py — dashboard/analyzer agnostic)
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
    kind            TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_number     INTEGER,
    end_line        INTEGER,
    parent_scope    TEXT,
    signature       TEXT,
    community_id    INTEGER,
    community_label TEXT,
    degree          INTEGER DEFAULT 0,
    in_degree       INTEGER DEFAULT 0,
    out_degree      INTEGER DEFAULT 0,
    -- Betweenness centrality (0..1). Computed by codegraph-analyze.py.
    -- High betweenness = symbol sits on many shortest paths between
    -- other pairs → "bridge" / refactor watch-list candidate.
    betweenness     REAL DEFAULT 0,
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
    kind    TEXT NOT NULL,
    UNIQUE(src_id, dst_id, kind)
);
CREATE INDEX idx_edges_src ON edges(src_id);
CREATE INDEX idx_edges_dst ON edges(dst_id);
CREATE INDEX idx_edges_kind ON edges(kind);

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
# Cursor classification
# --------------------------------------------------------------------------

# Cursor kinds we record as graph nodes. Variable decls, enumerators,
# typedefs, and template parameters are skipped — they add clutter
# without structural value at this granularity.
SYMBOL_KINDS = {
    CursorKind.FUNCTION_DECL: 'function',
    CursorKind.CXX_METHOD: 'method',
    CursorKind.CONSTRUCTOR: 'method',
    CursorKind.DESTRUCTOR: 'method',
    CursorKind.CLASS_DECL: 'class',
    CursorKind.CLASS_TEMPLATE: 'class',
    CursorKind.STRUCT_DECL: 'struct',
    CursorKind.FUNCTION_TEMPLATE: 'function',
}


def _safe_kind(cursor):
    """Return cursor.kind or None on unknown-kind ValueError. The
    python-clang bindings in Ubuntu 24.04 (18.1.3) raise when the
    underlying libclang reports kinds the bindings don't know about
    (e.g. ConceptDecl from C++20). Skipping the cursor is fine —
    we can't extract semantic info we don't have a mapping for."""
    try:
        return cursor.kind
    except ValueError:
        return None


def _kind_for(cursor):
    """Map a libclang cursor to our schema's kind string, with Qt
    signal/slot detection. Signals/slots are CXX_METHOD with an
    annotation comment or located inside a `signals:` / `slots:`
    section. libclang doesn't expose the access-specifier kind
    directly, so we approximate via ANNOTATE_ATTR children."""
    k = _safe_kind(cursor)
    if k is None:
        return None
    base = SYMBOL_KINDS.get(k)
    if base != 'method':
        return base
    for child in cursor.get_children():
        ck = _safe_kind(child)
        if ck == CursorKind.ANNOTATE_ATTR:
            sp = child.spelling
            if 'qt_signal' in sp:
                return 'signal'
            if 'qt_slot' in sp:
                return 'slot'
    return 'method'


def _qualified_name(cursor):
    """Walk up semantic parents to build a `Ns::Class::method`-style
    qualified name. Stops at the translation unit."""
    parts = [cursor.spelling or '<anon>']
    p = cursor.semantic_parent
    while p is not None and p.kind != CursorKind.TRANSLATION_UNIT:
        if p.spelling:
            parts.append(p.spelling)
        p = p.semantic_parent
    return '::'.join(reversed(parts))


def _parent_scope(cursor):
    """The immediate enclosing class/namespace name, or None."""
    p = cursor.semantic_parent
    while p is not None and p.kind != CursorKind.TRANSLATION_UNIT:
        if p.kind in (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL,
                      CursorKind.CLASS_TEMPLATE, CursorKind.NAMESPACE):
            return p.spelling
        p = p.semantic_parent
    return None


def _signature(cursor):
    """Best-effort signature string. clang gives us return type +
    display name (`Foo::bar(int) const`)."""
    try:
        return cursor.displayname or cursor.spelling
    except Exception:
        return cursor.spelling or ''


# --------------------------------------------------------------------------
# Per-TU walker (runs in a worker process)
# --------------------------------------------------------------------------

_FUNC_KINDS = (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD,
               CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR,
               CursorKind.FUNCTION_TEMPLATE)


def _detect_resource_dir():
    """Resolve clang's resource directory (where its builtin headers
    like stddef.h, stdint.h live). libclang doesn't auto-discover this
    the way the clang driver does — without it, parsing fails on any
    TU that includes the C/C++ standard library."""
    try:
        out = subprocess.run(['clang', '-print-resource-dir'],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip()
    except Exception:
        return None


_RESOURCE_DIR_CACHE = None


def _process_tu(args_tuple):
    """Worker entry point. Parses one TU, returns (symbols, edges,
    qt_connect_sites). symbols and edges keyed by USR strings."""
    tu_file, compile_args, src_root, work_dir, resource_dir = args_tuple

    # With fork(), the parent's libclang Config state is inherited
    # (Config.loaded is True). Calling set_library_file again would
    # raise. Only set it if not already loaded — covers forkserver/
    # spawn fallback paths where the worker is a fresh interpreter.
    if not getattr(Config, 'loaded', False):
        for p in _LIBCLANG_CANDIDATES:
            if os.path.exists(p):
                Config.set_library_file(p)
                break

    # ccdb stores compile commands with relative -I paths anchored at
    # `directory`. chdir so libclang resolves them correctly.
    if work_dir:
        try:
            os.chdir(work_dir)
        except OSError:
            pass

    # Prepend resource-dir flags so clang finds its own builtin headers
    # (stddef.h, stdint.h, etc.). Without these, every TU that includes
    # the C/C++ stdlib fails to parse.
    effective_args = list(compile_args)
    if resource_dir:
        effective_args = [f'-resource-dir={resource_dir}',
                          f'-isystem{resource_dir}/include'] + effective_args

    idx = Index.create()
    try:
        tu = idx.parse(
            tu_file,
            args=effective_args,
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                    | TranslationUnit.PARSE_INCOMPLETE,
        )
    except Exception as e:
        return ({}, [], [], f'parse failed: {e}')

    symbols = {}     # usr -> dict
    edges = []       # (src_usr, dst_usr, kind)
    qt_connects = []

    src_root_str = str(src_root)

    def record_symbol(c, fpath, prefer_overwrite=False):
        """Record a symbol by USR. If we already have this USR and
        prefer_overwrite is True (caller saw the actual definition
        rather than a forward declaration), replace the file/line with
        the definition's location so the dashboard navigates to the
        body, not the prototype."""
        usr = c.get_usr()
        if not usr:
            return None
        if usr in symbols and not prefer_overwrite:
            return usr
        try:
            rel = os.path.relpath(fpath, src_root.parent)
        except ValueError:
            rel = fpath
        end_line = c.extent.end.line if c.extent else c.location.line
        symbols[usr] = {
            'usr': usr,
            'name': c.spelling or '<anon>',
            'qualified_name': _qualified_name(c),
            'kind': _kind_for(c) or 'function',
            'file_path': rel,
            'line': c.location.line,
            'end_line': end_line,
            'parent_scope': _parent_scope(c),
            'signature': _signature(c),
        }
        return usr

    def handle_connect_call(c):
        """Pair method refs inside connect(...) as (signal, slot)
        edges. The walk_preorder yields the `connect` method itself
        first (it's the call's callee reference), then the signal,
        then the slot. Lambda slots leave only the signal — skipped."""
        refs = []
        for child in c.walk_preorder():
            ck = _safe_kind(child)
            if ck == CursorKind.DECL_REF_EXPR and child.referenced is not None:
                rk = _safe_kind(child.referenced)
                if rk in (CursorKind.CXX_METHOD, CursorKind.FUNCTION_DECL):
                    if child.referenced.spelling == 'connect':
                        continue
                    refs.append(child.referenced.get_usr())
        if len(refs) >= 2 and refs[0] and refs[1] and refs[0] != refs[1]:
            edges.append((refs[0], refs[1], 'signal-slot'))

    _CLASS_KINDS = (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL,
                    CursorKind.CLASS_TEMPLATE)

    # Explicit recursive walk: libclang's *_parent attributes don't
    # chain the way you'd expect (CALL_EXPR.lexical_parent jumps to TU;
    # CXX_BASE_SPECIFIER.semantic_parent returns an unspelled cursor),
    # so we maintain our own enclosing-function AND enclosing-class
    # stacks for attribution.
    def walk(c, enc_func_usr, enc_class_usr):
        # Catch unknown CursorKind IDs from the libclang binary that
        # python-clang doesn't have entries for. Common when running
        # ubuntu's python3-clang 18.1.3 against a newer libclang
        # binary (kind 154 = ConceptDecl / OMP*, etc.). Skipping the
        # cursor entirely is the right call — it can't carry semantic
        # info we know how to use anyway.
        try:
            cur_kind = c.kind
        except ValueError:
            return
        if c.location.file is None:
            for child in c.get_children():
                walk(child, enc_func_usr, enc_class_usr)
            return
        fpath = str(c.location.file)
        in_src = fpath.startswith(src_root_str)

        new_func = enc_func_usr
        new_class = enc_class_usr
        if cur_kind in SYMBOL_KINDS:
            if in_src:
                # Record declarations as well as definitions. Qt signals
                # are declared but never defined in C++ source (MOC
                # generates the bodies), so gating on is_definition()
                # drops every signal — and with it every signal-slot
                # edge. record_symbol dedups by USR, so decl+def from
                # different TUs collapse to one row. Prefer the def
                # location if we see it; otherwise the decl is fine.
                is_def = c.is_definition()
                usr = record_symbol(c, fpath, prefer_overwrite=is_def)
                if cur_kind in _FUNC_KINDS and usr:
                    new_func = usr
                elif cur_kind in _CLASS_KINDS and usr:
                    new_class = usr
        elif cur_kind == CursorKind.CALL_EXPR and in_src and enc_func_usr:
            ref = c.referenced
            if ref is not None:
                callee_usr = ref.get_usr()
                if callee_usr and callee_usr != enc_func_usr:
                    if ref.spelling == 'connect':
                        handle_connect_call(c)
                    else:
                        edges.append((enc_func_usr, callee_usr, 'calls'))
        elif cur_kind == CursorKind.CXX_BASE_SPECIFIER and in_src and enc_class_usr:
            base = c.referenced
            if base is not None:
                base_usr = base.get_usr()
                if base_usr and base_usr != enc_class_usr:
                    edges.append((enc_class_usr, base_usr, 'inherits'))

        for child in c.get_children():
            walk(child, new_func, new_class)

    walk(tu.cursor, None, None)

    # Surface any fatal-level diagnostics for the caller's log. We don't
    # fail the TU — incomplete parses still yield useful partial data.
    fatal = sum(1 for d in tu.diagnostics if d.severity >= 4)

    return (symbols, edges, qt_connects, None if fatal == 0 else f'{fatal} fatal diags')


# --------------------------------------------------------------------------
# ccdb loading
# --------------------------------------------------------------------------

def load_ccdb(ccdb_path):
    """Parse compile_commands.json into a list of (file, compile_args,
    directory) tuples ready for libclang. Strips the compiler executable,
    the `-c <file>` and `-o <out>` pairs. `directory` is the working
    directory cmake recorded — needed because some `-I` paths in
    ccdb are relative to that directory."""
    with open(ccdb_path) as f:
        entries = json.load(f)
    out = []
    for e in entries:
        parts = shlex.split(e['command'])
        args = []
        i = 1
        while i < len(parts):
            p = parts[i]
            if p == '-c' or p == '-o':
                i += 2
                continue
            if p.endswith('.cpp') or p.endswith('.cc') or p.endswith('.cxx') \
                    or p.endswith('.o') or p.endswith('.obj'):
                i += 1
                continue
            args.append(p)
            i += 1
        out.append((e['file'], args, e.get('directory', '')))
    return out


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src_root')
    ap.add_argument('db_path')
    ap.add_argument('ccdb', nargs='?',
                    help='Path to compile_commands.json. Defaults to '
                         '<src_root>/../build/compile_commands.json.')
    ap.add_argument('-j', '--jobs', type=int, default=None,
                    help='Parallel TU parses. Defaults to os.cpu_count().')
    ap.add_argument('--limit', type=int, default=None,
                    help='Process only first N TUs (debug).')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    src_root = Path(args.src_root).resolve()
    if not src_root.exists():
        print(f'ERROR: src_root not found: {src_root}', file=sys.stderr)
        sys.exit(1)
    db_path = Path(args.db_path).resolve()

    ccdb_path = args.ccdb or (src_root.parent / 'build' / 'compile_commands.json')
    ccdb_path = Path(ccdb_path).resolve()
    if not ccdb_path.exists():
        print(f'ERROR: ccdb not found: {ccdb_path}', file=sys.stderr)
        print('Run: cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
              file=sys.stderr)
        sys.exit(1)

    print(f'codegraph-extract-clangd: src={src_root} ccdb={ccdb_path}',
          file=sys.stderr)

    t0 = time.time()
    resource_dir = _detect_resource_dir()
    if not resource_dir:
        print('WARNING: failed to detect clang resource-dir; parses may '
              'fail with missing builtin headers', file=sys.stderr)
    else:
        print(f'  clang resource-dir: {resource_dir}', file=sys.stderr)

    ccdb = load_ccdb(ccdb_path)
    # Only .cpp/.cc TUs — header-only declarations get pulled in via
    # #includes. Also include MOC-generated mocs_compilation.cpp under
    # the build dir, which contains the moc'd signal/slot metadata.
    tus = [(f, a, src_root, wd, resource_dir) for f, a, wd in ccdb
           if (f.endswith('.cpp') or f.endswith('.cc') or f.endswith('.cxx'))]
    if args.limit:
        tus = tus[:args.limit]
    print(f'  {len(tus)} TUs to parse', file=sys.stderr)

    jobs = args.jobs or os.cpu_count() or 4
    # No upper cap — each worker uses ~200 MB peak so a 32-core box
    # with 64+ GB is fine. The Mac Mini M4 / Pi 5 will get auto-sized
    # by os.cpu_count() naturally.
    # Use 'fork' so workers inherit the parent's libclang Config state.
    # The default on Python 3.14 ('forkserver') runs the worker as a
    # fresh process — Config.set_library_file gets called via module
    # import but the binding is fragile and has been observed to fail
    # ("library file must be set before before using..."). fork is
    # the historical default, fast on Linux, and we don't have any
    # multi-threading inside the parent that would make fork unsafe.
    mp_ctx = multiprocessing.get_context('fork')
    print(f'  parsing with {jobs} workers (fork)', file=sys.stderr)

    # Aggregate
    all_symbols = {}             # usr -> dict
    edge_set = set()             # (src_usr, dst_usr, kind) deduped
    n_parsed = 0
    parse_errors = []
    t_parse_start = time.time()

    with mp_ctx.Pool(processes=jobs) as pool:
        for syms, edges, _qt, err in pool.imap_unordered(_process_tu, tus, chunksize=4):
            n_parsed += 1
            if err and args.verbose:
                parse_errors.append(err)
            for usr, info in syms.items():
                if usr not in all_symbols:
                    all_symbols[usr] = info
            for tup in edges:
                edge_set.add(tup)
            if n_parsed % 50 == 0:
                print(f'    {n_parsed}/{len(tus)} TUs '
                      f'({time.time()-t_parse_start:.1f}s, '
                      f'sym={len(all_symbols)} edges={len(edge_set)})',
                      file=sys.stderr)

    print(f'  parse phase: {time.time()-t_parse_start:.1f}s '
          f'({len(all_symbols)} symbols, {len(edge_set)} edges)',
          file=sys.stderr)
    if parse_errors and args.verbose:
        print(f'  parse errors: {len(parse_errors)} (first 5):', file=sys.stderr)
        for e in parse_errors[:5]:
            print(f'    {e}', file=sys.stderr)

    # ---- Assign integer IDs (deterministic by qualified_name) ----
    t_write = time.time()
    sorted_usrs = sorted(all_symbols.keys(),
                         key=lambda u: (all_symbols[u]['qualified_name'], u))
    usr_to_id = {usr: i + 1 for i, usr in enumerate(sorted_usrs)}

    # qualified_name UNIQUE constraint: if two distinct USRs share a
    # qualified_name (template specializations, anon namespaces collapsing,
    # different overloads with same display name), dedup with a stable
    # short hash of the full USR. 8-char hex suffix is collision-safe
    # for the ~10K-symbol scale.
    import hashlib
    seen_qn = {}
    for usr in sorted_usrs:
        qn = all_symbols[usr]['qualified_name']
        if qn in seen_qn:
            h = hashlib.sha1(usr.encode()).hexdigest()[:8]
            all_symbols[usr]['qualified_name'] = f'{qn}#{h}'
        else:
            seen_qn[qn] = usr

    # ---- Write DB ----
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    conn.executemany(
        'INSERT INTO symbols (id, name, qualified_name, kind, file_path, '
        'line_number, end_line, parent_scope, signature) '
        'VALUES (?,?,?,?,?,?,?,?,?)',
        [
            (usr_to_id[usr], s['name'], s['qualified_name'], s['kind'],
             s['file_path'], s['line'], s['end_line'], s['parent_scope'],
             s['signature'])
            for usr, s in all_symbols.items()
        ],
    )

    # Edges — only keep those whose endpoints both resolved to a symbol.
    edge_rows = []
    edge_count_by_kind = defaultdict(int)
    for src_usr, dst_usr, kind in edge_set:
        sid = usr_to_id.get(src_usr)
        did = usr_to_id.get(dst_usr)
        if sid is None or did is None:
            continue
        edge_rows.append((sid, did, kind))
        edge_count_by_kind[kind] += 1
    conn.executemany(
        'INSERT OR IGNORE INTO edges (src_id, dst_id, kind) VALUES (?,?,?)',
        edge_rows,
    )

    # file_to_symbols
    file_to_syms = defaultdict(set)
    for usr, s in all_symbols.items():
        file_to_syms[s['file_path']].add(usr_to_id[usr])
    f2s_rows = [(fp, sid) for fp, ids in file_to_syms.items() for sid in ids]
    conn.executemany(
        'INSERT OR IGNORE INTO file_to_symbols (file_path, symbol_id) VALUES (?,?)',
        f2s_rows,
    )

    # Recompute degree counters (in-degree, out-degree, total). Skip
    # weighted versions — analyzer will recompute community/etc.
    conn.execute(
        'UPDATE symbols SET out_degree = (SELECT COUNT(*) FROM edges WHERE src_id=symbols.id), '
        'in_degree = (SELECT COUNT(*) FROM edges WHERE dst_id=symbols.id)'
    )
    conn.execute('UPDATE symbols SET degree = in_degree + out_degree')

    # Metadata
    elapsed = time.time() - t0
    meta = {
        'extracted_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'src_root': str(src_root),
        'ccdb_path': str(ccdb_path),
        'extractor_version': '3.0.0-clangd',
        'symbol_count': str(len(all_symbols)),
        'edge_count': str(len(edge_rows)),
        'edges_calls': str(edge_count_by_kind.get('calls', 0)),
        'edges_inherits': str(edge_count_by_kind.get('inherits', 0)),
        'edges_signal_slot': str(edge_count_by_kind.get('signal-slot', 0)),
        'tu_count': str(len(tus)),
        'extraction_seconds': f'{elapsed:.2f}',
    }
    conn.executemany(
        'INSERT INTO metadata (key, value) VALUES (?,?)',
        list(meta.items()),
    )

    conn.commit()
    conn.close()

    print(
        f'codegraph-extract-clangd done in {elapsed:.1f}s — '
        f'{len(all_symbols)} symbols, {len(edge_rows)} edges '
        f'(calls={edge_count_by_kind.get("calls", 0)}, '
        f'inherits={edge_count_by_kind.get("inherits", 0)}, '
        f'signal-slot={edge_count_by_kind.get("signal-slot", 0)})',
        file=sys.stderr,
    )


if __name__ == '__main__':
    main()
