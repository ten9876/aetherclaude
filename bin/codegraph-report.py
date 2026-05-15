#!/usr/bin/env python3
"""
codegraph-report — emit a Markdown audit doc for the current codegraph.

Reads codegraph.db and writes GRAPH_REPORT.md summarizing:

  - Counts (symbols by kind, edges by kind+confidence, communities,
    concepts by kind)
  - Freshness (extraction timestamp, source HEAD, last doc-extraction)
  - Top-20 high-betweenness symbols (refactor watch-list)
  - Top-20 communities by size with labels
  - Top-20 most-connected concepts (the real architectural anchors)
  - Concept extraction breakdown by kind

This is the GRAPH_REPORT.md artifact graphify ships; we generate
ours from our own libclang+LLM data so a human reviewer can see
the architectural state of the codebase at the time of the index.

Read-only: opens db with mode=ro. Safe to run alongside the live
dashboard. Output lands at /Users/Shared/aetherclaude/data/
GRAPH_REPORT.md by default; override with --out.

Designed to run as a final step in both:
  - docker codegraph-run.sh (after extract + analyze)
  - codegraph-extract-docs.py (after concept-extraction)
Both write the same path; second overwrites first.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

DEFAULT_DB = '/Users/Shared/aetherclaude/data/codegraph.db'
DEFAULT_OUT = '/Users/Shared/aetherclaude/data/GRAPH_REPORT.md'


def _md_escape(s: str) -> str:
    """Escape pipe + backtick + underscore for safe Markdown table cells."""
    return (s or '').replace('|', '\\|').replace('`', "'").replace('_', r'\_')


def _md_short(s: str, n: int = 60) -> str:
    s = (s or '').replace('\n', ' ').strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + '…'


def render(db_path: str) -> str:
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row

    # ---- counts ----
    sym_counts = dict(conn.execute(
        "SELECT kind, COUNT(*) FROM symbols GROUP BY kind"
    ).fetchall())
    total_symbols = sum(sym_counts.values())
    code_symbols = total_symbols - sym_counts.get('concept', 0)

    edge_by_kind = dict(conn.execute(
        "SELECT kind, COUNT(*) FROM edges GROUP BY kind"
    ).fetchall())
    edge_by_conf = dict(conn.execute(
        "SELECT confidence, COUNT(*) FROM edges GROUP BY confidence"
    ).fetchall())
    total_edges = sum(edge_by_kind.values())

    n_communities = conn.execute(
        "SELECT COUNT(DISTINCT community_id) FROM symbols "
        " WHERE community_id IS NOT NULL"
    ).fetchone()[0]
    n_communities_meaningful = conn.execute(
        "SELECT COUNT(*) FROM ("
        "  SELECT community_id, COUNT(*) c FROM symbols "
        "    WHERE community_id IS NOT NULL "
        "    GROUP BY community_id HAVING c >= 3"
        ")"
    ).fetchone()[0]

    concept_by_kind = dict(conn.execute(
        "SELECT parent_scope, COUNT(*) FROM symbols "
        " WHERE kind='concept' GROUP BY parent_scope"
    ).fetchall())

    # ---- freshness ----
    metadata = dict(conn.execute(
        "SELECT key, value FROM metadata"
    ).fetchall())
    extracted_at = metadata.get('extracted_at', '?')
    src_head = (metadata.get('src_head_sha') or '?')[:12]
    docs_at = metadata.get('docs_extracted_at', '(not yet run)')

    # ---- top betweenness ----
    top_bw = conn.execute(
        "SELECT qualified_name, betweenness, file_path, community_label, "
        "       degree FROM symbols "
        " WHERE betweenness IS NOT NULL AND betweenness > 0 "
        "   AND kind != 'concept' "
        " ORDER BY betweenness DESC LIMIT 20"
    ).fetchall()

    # ---- top communities ----
    top_comms = conn.execute(
        "SELECT community_id, community_label, COUNT(*) AS members "
        "  FROM symbols WHERE community_id IS NOT NULL AND kind != 'concept' "
        " GROUP BY community_id ORDER BY members DESC LIMIT 20"
    ).fetchall()
    # For each community, find a representative symbol (highest degree).
    rep_by_cid: dict[int, str] = {}
    for row in top_comms:
        rep = conn.execute(
            "SELECT qualified_name FROM symbols "
            " WHERE community_id=? AND kind != 'concept' "
            " ORDER BY degree DESC LIMIT 1",
            (row['community_id'],)
        ).fetchone()
        rep_by_cid[row['community_id']] = (
            rep['qualified_name'] if rep else '—'
        )

    # ---- top concepts ----
    # Most-connected concepts (out + in edge degree as concept).
    top_concepts = conn.execute(
        "SELECT s.id, s.name, s.signature AS description, "
        "       s.parent_scope AS concept_kind, COUNT(*) AS edges "
        "  FROM edges e JOIN symbols s ON e.src_id=s.id "
        " WHERE s.kind='concept' AND e.confidence='INFERRED' "
        " GROUP BY s.id ORDER BY edges DESC LIMIT 20"
    ).fetchall()
    # Plus the top inbound symbol per concept for context.
    top_anchor_for: dict[int, str] = {}
    for c in top_concepts:
        anchor = conn.execute(
            "SELECT s.qualified_name FROM edges e "
            "  JOIN symbols s ON e.dst_id=s.id "
            " WHERE e.src_id=? AND e.confidence='INFERRED' "
            "   AND s.kind != 'concept' "
            " ORDER BY s.degree DESC LIMIT 1",
            (c['id'],)
        ).fetchone()
        top_anchor_for[c['id']] = anchor['qualified_name'] if anchor else '—'

    conn.close()

    # ---- compose markdown ----
    lines: list[str] = []
    lines.append('# AetherSDR Codegraph Audit')
    lines.append('')
    lines.append(f'_Generated {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}_')
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append(f'- **{total_symbols:,} symbols**  ({code_symbols:,} code, '
                 f'{sym_counts.get("concept", 0):,} concepts)')
    for kind, count in sorted(sym_counts.items()):
        if kind == 'concept':
            continue
        lines.append(f'    - {kind}: {count:,}')
    lines.append(f'- **{total_edges:,} edges**')
    for kind, count in sorted(edge_by_kind.items()):
        lines.append(f'    - {kind}: {count:,}')
    lines.append(f'- **By confidence**')
    for conf, count in sorted(edge_by_conf.items()):
        lines.append(f'    - {conf}: {count:,}')
    lines.append(f'- **{n_communities:,} Louvain communities** '
                 f'({n_communities_meaningful:,} with size ≥ 3)')
    if concept_by_kind:
        lines.append(f'- **{sym_counts.get("concept", 0):,} concepts by kind**')
        for k, v in sorted(concept_by_kind.items(),
                           key=lambda x: -x[1]):
            lines.append(f'    - {k}: {v}')
    lines.append('')

    lines.append('## Freshness')
    lines.append('')
    lines.append(f'- Source HEAD at extraction: `{src_head}`')
    lines.append(f'- Indexed at: {extracted_at}')
    lines.append(f'- Doc-extraction last run: {docs_at}')
    lines.append(f'- Extractor: {metadata.get("extractor_version", "?")}')
    lines.append('')

    lines.append('## Top-20 high-betweenness symbols (refactor watch-list)')
    lines.append('')
    lines.append('Touch one of these and the change ripples wide. '
                 '`betweenness × 1000` shown for readability.')
    lines.append('')
    lines.append('| rank | symbol | bw×1000 | degree | community |')
    lines.append('|------|--------|--------:|-------:|-----------|')
    for i, row in enumerate(top_bw, 1):
        lines.append(
            f'| {i} | `{_md_escape(row["qualified_name"])}` '
            f'| {row["betweenness"] * 1000:.2f} '
            f'| {row["degree"]} '
            f'| {_md_escape(_md_short(row["community_label"] or "—", 40))} |'
        )
    lines.append('')

    lines.append('## Top-20 communities by size')
    lines.append('')
    lines.append('| members | label | representative symbol |')
    lines.append('|--------:|-------|----------------------|')
    for row in top_comms:
        lines.append(
            f'| {row["members"]} '
            f'| {_md_escape(_md_short(row["community_label"] or "—", 50))} '
            f'| `{_md_escape(rep_by_cid[row["community_id"]])}` |'
        )
    lines.append('')

    if top_concepts:
        lines.append('## Top-20 documented concepts')
        lines.append('')
        lines.append('Architectural anchors extracted by '
                     '`codegraph-extract-docs.py` from CLAUDE.md, '
                     'CONTRIBUTING.md, the `docs/` tree, the '
                     '`.specify/` constitution, and `src/{core,models,gui}/` '
                     'header comments. Edge count is concept→symbol '
                     'INFERRED links.')
        lines.append('')
        lines.append('| concept | kind | edges | top anchor symbol |')
        lines.append('|---------|------|------:|-------------------|')
        for c in top_concepts:
            lines.append(
                f'| **{_md_escape(c["name"])}** '
                f'| {c["concept_kind"] or "—"} '
                f'| {c["edges"]} '
                f'| `{_md_escape(top_anchor_for[c["id"]])}` |'
            )
        lines.append('')

    lines.append('---')
    lines.append('')
    lines.append('_Regenerate with `python3 /Users/Shared/aetherclaude/'
                 'bin/codegraph-report.py`. Auto-emitted by the nightly '
                 '`com.aetherclaude.codegraph-refresh` job and by '
                 '`codegraph-extract-docs.py`._')

    return '\n'.join(lines) + '\n'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default=DEFAULT_DB)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--stdout', action='store_true',
                    help='Print to stdout instead of writing --out')
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f'ERROR: db not found: {args.db}', file=sys.stderr)
        return 2
    md = render(args.db)
    if args.stdout:
        sys.stdout.write(md)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write via tmp+rename so a partial flush doesn't leave
        # a half-written report visible to readers.
        tmp = out.with_suffix(out.suffix + '.tmp')
        tmp.write_text(md, encoding='utf-8')
        os.replace(tmp, out)
        print(f'wrote {out} ({len(md):,} bytes)', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
