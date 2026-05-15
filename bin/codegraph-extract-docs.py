#!/usr/bin/env python3
"""
codegraph-extract-docs — LLM extraction of concept nodes + relations
from AetherSDR's docs/ tree (Phase 2 of the graphify-incorporation plan).

Reads a curated list of docs (architecture, dialog patterns, multi-pan
pitfalls, CLAUDE.md, CHANGELOG, …) and asks Claude to emit a JSON
fragment of:

  - concept nodes: subsystem/pattern/protocol/feature/principle names
  - edges from concept → code-symbol (rationale_for, documented_in,
    motivates, implements_pattern, obsolesces)

Writes the results into the existing codegraph.db:

  - new symbols rows with kind='concept', qualified_name prefixed
    with `concept:` to avoid collisions with real C++ names
  - new edges rows with confidence='INFERRED' and the model's own
    confidence_score

Each doc gets one Claude --print call with --json-schema for
structured output. The prompt is seeded with the top-20 betweenness
"god nodes" so the model anchors concepts to symbols the codebase
treats as structurally important. (Same trick graphify uses.)

The script is idempotent: a prior set of INFERRED edges (and their
concept nodes) is deleted before re-insertion. EXTRACTED edges from
the AST extractor are NEVER touched.

Auth: uses the `claude` CLI's existing OAuth session (no API key
required). Spend cap per doc via --max-budget-usd. Total per run
should land around $0.10–$0.30 on opus.

Run nightly alongside extract+analyze:
    /Users/Shared/aetherclaude/bin/codegraph-extract-docs.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

CODEGRAPH_DB = os.environ.get(
    'CODEGRAPH_DB',
    '/Users/Shared/aetherclaude/data/codegraph.db',
)
# The AetherSDR repo on Mac Mini (read-only for this script).
AETHERSDR_ROOT = os.environ.get(
    'AETHERSDR_ROOT',
    '/Users/aetherclaude/workspace/AetherSDR',
)
# Curated list of docs to extract from. Limit to load-bearing
# documents — auto-discovery would pull in CHANGELOG noise and PR
# templates. Files that don't exist are skipped without error.
DEFAULT_DOCS = [
    'CLAUDE.md',
    'CONTRIBUTING.md',
    'docs/architecture-pipelines.md',
    'docs/dialog-patterns.md',
    'docs/multi-pan-pitfalls.md',
    'docs/vita49-format.md',
    '.specify/memory/constitution.md',
]
# Per-doc spend cap. First call eats ~$0.15 on Claude Code's
# cache-creation tokens (system + tool defs); subsequent docs reuse
# the cache and cost ~$0.03 each. Cap generously per doc but the
# total run sits around $0.50-1.00 on opus.
MAX_BUDGET_USD = 1.00
CLAUDE_BIN = '/opt/homebrew/bin/claude'
CLAUDE_MODEL = 'opus'
# Cap docs to ~40KB so we don't blow context on the biggest ones
# (CHANGELOG can be 100K+ chars). Truncate cleanly at a heading.
MAX_DOC_BYTES = 40_000


JSON_SCHEMA = {
    'type': 'object',
    'properties': {
        'concepts': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'description': {'type': 'string'},
                    'kind': {
                        'type': 'string',
                        'enum': ['subsystem', 'pattern', 'protocol',
                                 'feature', 'principle'],
                    },
                },
                'required': ['name', 'description', 'kind'],
            },
        },
        'edges': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'source': {'type': 'string'},
                    'target': {'type': 'string'},
                    'relation': {
                        'type': 'string',
                        'enum': ['documented_in', 'rationale_for',
                                 'motivates', 'implements_pattern',
                                 'obsolesces'],
                    },
                    'confidence_score': {
                        'type': 'number',
                        'minimum': 0,
                        'maximum': 1,
                    },
                },
                'required': ['source', 'target', 'relation'],
            },
        },
    },
    'required': ['concepts', 'edges'],
}


SYSTEM_INSTRUCTIONS = """\
You are a code-knowledge-graph extractor. Read the supplied AetherSDR
documentation file and emit a JSON object matching the provided schema.

EXTRACT:
  - **concepts**: named architectural ideas (subsystems like "Multi-Pan
    Routing"; patterns like "Frameless Window Chrome"; protocols like
    "SmartSDR v1.4.0.0"; features like "TX Interlock"; principles like
    "Radio-Authoritative Settings"). Each gets a 1–2 sentence
    description and a `kind` from the schema's enum.
  - **edges**: relationships between concepts and existing code symbols.
    Source/target can be either a concept name (from your own emitted
    list above) or a fully-qualified C++ symbol name (e.g.
    "AetherSDR::MainWindow::buildUI", "AetherSDR::AppSettings::value").
    Relation must be one of:
      - documented_in: a concept is described/specified in another concept
      - rationale_for: a concept explains why a code symbol exists
      - motivates:     a concept drove the design of a code symbol
      - implements_pattern: a code symbol implements a pattern concept
      - obsolesces:    a newer concept/symbol replaces an older one
    Include `confidence_score` 0.0–1.0 reflecting how directly the doc
    asserts the relation (1.0 = explicit, 0.5 = inferred, 0.2 = guess).

RULES:
  - Emit ONLY the JSON object. No commentary, no markdown wrappers.
  - Prefer concepts the doc names explicitly (headers, bold terms,
    "Principle X" markers). Do not invent.
  - Edges must reference real code symbols when targeting code. The
    god-node primer below lists the codebase's structural hubs as
    grounding. If unsure a symbol exists, skip the edge — never invent.
  - Limit: at most 30 concepts and 60 edges per doc.
"""


def load_top_betweenness(db_path: str, n: int = 20) -> list[dict]:
    """Pull the top-N high-betweenness code symbols. Used to seed the
    extraction prompt — same idea as graphify's god-nodes."""
    if not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        rows = conn.execute(
            'SELECT qualified_name, betweenness, file_path FROM symbols '
            ' WHERE kind != "concept" AND betweenness > 0 '
            ' ORDER BY betweenness DESC LIMIT ?',
            (n,)
        ).fetchall()
        conn.close()
        return [
            {'name': r[0], 'bw': r[1], 'file': r[2]} for r in rows
        ]
    except sqlite3.Error:
        return []


def read_doc(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    if len(text) > MAX_DOC_BYTES:
        # Truncate at the closest paragraph break before the limit
        cut = text.rfind('\n\n', 0, MAX_DOC_BYTES)
        if cut < MAX_DOC_BYTES // 2:
            cut = MAX_DOC_BYTES
        text = text[:cut] + '\n\n[... truncated ...]\n'
    return text


def build_prompt(doc_rel_path: str, doc_text: str,
                 god_nodes: list[dict]) -> str:
    primer = '\n'.join(
        f'  - {g["name"]} (bw={g["bw"]:.3f}, in {g["file"]})'
        for g in god_nodes
    )
    return (
        f'{SYSTEM_INSTRUCTIONS}\n\n'
        f'## God-node primer (structural hubs in the codebase)\n\n'
        f'These symbols are the highest-betweenness centrality nodes; '
        f'concepts often anchor to them.\n\n'
        f'{primer}\n\n'
        f'## Documentation file: {doc_rel_path}\n\n'
        f'```\n{doc_text}\n```\n\n'
        f'Emit the JSON now.'
    )


def call_claude(prompt: str) -> dict | None:
    """Run `claude --print --output-format json --json-schema …` and
    return the parsed model output, or None on failure."""
    try:
        # --disallowedTools: this is a pure extraction; the model
        # has everything it needs in the prompt. Blocking Read/Grep/
        # Bash/etc. trims context bloat AND prevents the model from
        # wandering off into tool calls.
        # Pipe the prompt on stdin instead of as the last positional —
        # large prompts (40 KB) make the command-line argument parsing
        # behave inconsistently; stdin sidesteps that.
        proc = subprocess.run(
            [
                CLAUDE_BIN, '--print',
                '--model', CLAUDE_MODEL,
                '--output-format', 'json',
                '--json-schema', json.dumps(JSON_SCHEMA),
                '--max-budget-usd', str(MAX_BUDGET_USD),
                '--no-session-persistence',
                '--disallowedTools',
                'Read,Edit,Write,Bash,Grep,Glob,WebFetch,WebSearch,Task,Agent,TodoWrite,ToolSearch',
            ],
            input=prompt,
            capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f'  ! claude invocation failed: {e}', file=sys.stderr)
        return None
    if proc.returncode != 0:
        # claude --output-format json writes error details into stdout's
        # wrapper, not stderr. Surface both for diagnosis.
        err_detail = proc.stderr.strip() or proc.stdout[:600]
        print(f'  ! claude exit {proc.returncode}: {err_detail}',
              file=sys.stderr)
        return None
    # --output-format json wraps the response in a top-level object.
    # When --json-schema is set, the validated structured output lives
    # in wrapper.structured_output (an actual JSON object). Older
    # versions put a stringified payload in wrapper.result.
    try:
        wrapper = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f'  ! could not parse wrapper: {proc.stdout[:200]}',
              file=sys.stderr)
        return None
    so = wrapper.get('structured_output')
    if isinstance(so, dict):
        return so
    # Fallback: result/content text that may be JSON-with-fences
    payload = wrapper.get('result') or wrapper.get('content') or ''
    if isinstance(payload, list):
        payload = ''.join(p.get('text', '') for p in payload
                          if isinstance(p, dict))
    if not isinstance(payload, str):
        payload = str(payload)
    payload = payload.strip()
    if payload.startswith('```'):
        payload = re.sub(r'^```[a-zA-Z]*\n?|\n?```$', '', payload).strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        print(f'  ! model output not JSON: {e} :: {payload[:200]}',
              file=sys.stderr)
        return None


def resolve_symbol(conn: sqlite3.Connection, name: str,
                   concept_id_by_name: dict[str, int]) -> int | None:
    """Map a name (concept label OR C++ qualified name) to a symbols.id.
    Tries: in-flight concept dict → exact qualified_name → suffix
    match. Returns None if no resolution (we drop edges to invented
    symbols rather than create dangling rows)."""
    if name in concept_id_by_name:
        return concept_id_by_name[name]
    # Concept names may have been emitted with the 'concept:' prefix
    # by the model or by us — try both.
    prefixed = f'concept:{name}'
    if prefixed in concept_id_by_name:
        return concept_id_by_name[prefixed]
    row = conn.execute(
        'SELECT id FROM symbols WHERE qualified_name = ?', (name,)
    ).fetchone()
    if row:
        return row[0]
    row = conn.execute(
        'SELECT id FROM symbols WHERE qualified_name = ?', (prefixed,)
    ).fetchone()
    if row:
        return row[0]
    # Suffix match (e.g. "MainWindow::buildUI" → "AetherSDR::MainWindow::buildUI")
    row = conn.execute(
        'SELECT id FROM symbols WHERE qualified_name LIKE ? '
        ' ORDER BY degree DESC LIMIT 1',
        (f'%{name}',)
    ).fetchone()
    if row:
        return row[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default=CODEGRAPH_DB)
    ap.add_argument('--root', default=AETHERSDR_ROOT,
                    help='AetherSDR repo root containing docs')
    ap.add_argument('--docs', nargs='+', default=None,
                    help='Override the doc list (paths relative to --root)')
    ap.add_argument('--dry-run', action='store_true',
                    help='Run extraction, print summary, do not write to db')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f'ERROR: codegraph db not found: {args.db}', file=sys.stderr)
        return 2
    root = Path(args.root)
    if not root.exists():
        print(f'ERROR: AetherSDR root not found: {root}', file=sys.stderr)
        return 2

    docs = args.docs or DEFAULT_DOCS
    god_nodes = load_top_betweenness(args.db, n=20)
    if not god_nodes:
        print('WARNING: no god-nodes loaded (betweenness not computed?)',
              file=sys.stderr)

    t0 = time.time()
    all_concepts: list[dict] = []
    all_edges: list[dict] = []
    n_called = n_ok = 0
    for rel in docs:
        path = root / rel
        text = read_doc(path)
        if text is None:
            print(f'  - skip {rel} (missing or unreadable)', file=sys.stderr)
            continue
        print(f'  extracting from {rel} ({len(text)} chars)', file=sys.stderr)
        prompt = build_prompt(rel, text, god_nodes)
        n_called += 1
        result = call_claude(prompt)
        if result is None:
            continue
        n_ok += 1
        concepts = result.get('concepts') or []
        edges = result.get('edges') or []
        for c in concepts:
            c['_source_doc'] = rel
            all_concepts.append(c)
        for e in edges:
            e['_source_doc'] = rel
            all_edges.append(e)
        print(f'    + {len(concepts)} concepts, {len(edges)} edges',
              file=sys.stderr)

    print(f'\nExtraction done — {n_ok}/{n_called} docs processed, '
          f'{len(all_concepts)} concepts, {len(all_edges)} edges in '
          f'{time.time()-t0:.1f}s', file=sys.stderr)

    if args.dry_run:
        print('--- dry-run summary ---')
        print(f'concepts: {len(all_concepts)}')
        for c in all_concepts[:10]:
            print(f'  [{c["kind"]}] {c["name"]} — {c["description"][:80]}')
        print(f'edges: {len(all_edges)}')
        for e in all_edges[:10]:
            print(f'  {e["source"]} --[{e["relation"]}]--> {e["target"]}')
        return 0

    # ---- Write to db ----
    conn = sqlite3.connect(args.db)
    try:
        # Wipe prior INFERRED edges + concept rows so re-runs are
        # idempotent. EXTRACTED edges from the AST extractor are
        # never touched.
        conn.execute(
            "DELETE FROM edges WHERE confidence = 'INFERRED'"
        )
        conn.execute(
            "DELETE FROM symbols WHERE kind = 'concept'"
        )
        # Dedup concepts by name (keep first description).
        concept_rows: dict[str, dict] = {}
        for c in all_concepts:
            name = c['name'].strip()
            if not name:
                continue
            qn = f'concept:{name}'
            if qn in concept_rows:
                continue
            concept_rows[qn] = {
                'qualified_name': qn, 'name': name,
                'kind': 'concept',
                'file_path': c.get('_source_doc', ''),
                'line_number': 0,
                'parent_scope': c.get('kind', 'concept'),
                'signature': c.get('description', '')[:500],
            }
        # Allocate IDs starting after the max code-symbol id so we
        # don't collide if a re-extraction has happened in parallel.
        max_id = conn.execute('SELECT COALESCE(MAX(id), 0) FROM symbols') \
                     .fetchone()[0]
        concept_id_by_name: dict[str, int] = {}
        for qn, row in concept_rows.items():
            max_id += 1
            row['id'] = max_id
            concept_id_by_name[qn] = max_id
            concept_id_by_name[row['name']] = max_id
        conn.executemany(
            'INSERT INTO symbols (id, name, qualified_name, kind, '
            'file_path, line_number, parent_scope, signature) '
            'VALUES (?,?,?,?,?,?,?,?)',
            [
                (r['id'], r['name'], r['qualified_name'], r['kind'],
                 r['file_path'], r['line_number'], r['parent_scope'],
                 r['signature'])
                for r in concept_rows.values()
            ],
        )
        print(f'  + {len(concept_rows)} concept rows inserted',
              file=sys.stderr)

        # Resolve + insert edges
        n_edge_ok = 0
        n_edge_drop = 0
        edge_rows: list[tuple] = []
        for e in all_edges:
            src = resolve_symbol(conn, e['source'].strip(),
                                 concept_id_by_name)
            dst = resolve_symbol(conn, e['target'].strip(),
                                 concept_id_by_name)
            if src is None or dst is None or src == dst:
                n_edge_drop += 1
                if args.verbose:
                    print(f'    drop: {e["source"]!r} --[{e["relation"]}]--> '
                          f'{e["target"]!r} (unresolved)', file=sys.stderr)
                continue
            score = float(e.get('confidence_score') or 0.5)
            edge_rows.append((src, dst, e['relation'], 'INFERRED',
                              max(0.0, min(1.0, score))))
            n_edge_ok += 1
        # Some edges may already exist from the AST pass (e.g. a
        # concept→symbol edge whose target previously connected via
        # a code edge); the UNIQUE(src, dst, kind) constraint will
        # ignore duplicates via OR IGNORE.
        conn.executemany(
            'INSERT OR IGNORE INTO edges '
            '  (src_id, dst_id, kind, confidence, confidence_score) '
            ' VALUES (?,?,?,?,?)',
            edge_rows,
        )
        print(f'  + {n_edge_ok} INFERRED edges inserted, '
              f'{n_edge_drop} dropped (unresolved targets)',
              file=sys.stderr)

        # Stamp metadata
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?,?)",
            ('docs_extracted_at',
             time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?,?)",
            ('docs_concept_count', str(len(concept_rows))),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?,?)",
            ('docs_inferred_edge_count', str(n_edge_ok)),
        )
        conn.commit()
    finally:
        conn.close()

    print(f'\ndocs extraction complete in {time.time()-t0:.1f}s',
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
