#!/usr/bin/env python3
"""
codegraph-migrate-phase1 — one-shot schema bump for edge confidence.

Adds two columns to the edges table on an EXISTING codegraph.db so
the schema doesn't have to wait for the next full extraction:

  confidence       TEXT NOT NULL DEFAULT 'EXTRACTED'
  confidence_score REAL NOT NULL DEFAULT 1.0

All existing rows backfill via the column DEFAULTs. Idempotent —
safe to re-run; a second invocation no-ops once the columns exist.

Run on the Mac Mini:
  python3 /Users/Shared/aetherclaude/bin/codegraph-migrate-phase1.py
"""

from __future__ import annotations

import os
import sqlite3
import sys

DB = os.environ.get('CODEGRAPH_DB', '/Users/Shared/aetherclaude/data/codegraph.db')


def has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM pragma_table_info(?) WHERE name=?",
        (table, column),
    ).fetchone())


def main() -> int:
    if not os.path.exists(DB):
        print(f'ERROR: db not found: {DB}', file=sys.stderr)
        return 2
    conn = sqlite3.connect(DB)
    changed = False
    try:
        if not has_column(conn, 'edges', 'confidence'):
            conn.execute(
                "ALTER TABLE edges ADD COLUMN confidence TEXT NOT NULL DEFAULT 'EXTRACTED'"
            )
            changed = True
            print('+ added edges.confidence')
        else:
            print('= edges.confidence already present')

        if not has_column(conn, 'edges', 'confidence_score'):
            conn.execute(
                "ALTER TABLE edges ADD COLUMN confidence_score REAL NOT NULL DEFAULT 1.0"
            )
            changed = True
            print('+ added edges.confidence_score')
        else:
            print('= edges.confidence_score already present')

        if changed:
            conn.commit()
            # Sanity check: confirm both columns now exist and every
            # existing row holds the EXTRACTED default.
            n_total = conn.execute('SELECT COUNT(*) FROM edges').fetchone()[0]
            n_default = conn.execute(
                "SELECT COUNT(*) FROM edges "
                " WHERE confidence='EXTRACTED' AND confidence_score=1.0"
            ).fetchone()[0]
            print(f'  {n_default}/{n_total} edges backfilled as EXTRACTED@1.0')
    finally:
        conn.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
