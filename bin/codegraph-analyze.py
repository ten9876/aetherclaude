#!/usr/bin/env python3
"""
codegraph-analyze — community detection.

Reads codegraph.db (produced by codegraph-extract.py), runs Louvain
modularity-based community detection (via python-louvain), and writes
community_id + community_label columns back to the same database.

Layout (x_coord, y_coord) is intentionally NOT precomputed here:
networkx's pure-Python ForceAtlas2 takes ~7 minutes on 9K nodes /
50K edges, which is too slow for nightly refresh. The Sigma.js
client-side ForceAtlas2 (WebGL) handles it in 5-10 seconds in the
browser, and adapts to user interaction. The x_coord/y_coord columns
remain in the schema for a future Phase-2 server-side precompute
upgrade if needed.

Designed to be idempotent: re-running re-computes everything. The
random seed is fixed (seed=42) so Louvain community ids are stable
across runs unless the underlying edge set changes, and the
ForceAtlas2 layout is deterministic given the same input graph.

Usage:
    codegraph-analyze.py [<db_path>]

Default db_path: /Users/aetherclaude/data/codegraph.db
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx
import community as louvain  # python-louvain


def load_graph(conn: sqlite3.Connection) -> nx.Graph:
    """Build an undirected networkx graph from the symbols + edges
    tables. Direction is dropped — community detection doesn't need it
    and ForceAtlas2 lays out undirected graphs."""
    G = nx.Graph()
    for sid, in conn.execute('SELECT id FROM symbols'):
        G.add_node(sid)
    # Weight = number of edge kinds between the same pair (max 3:
    # calls, inherits, signal-slot). Treats multi-kind ties as
    # slightly stronger relationships in the layout.
    weights: dict[tuple[int, int], int] = defaultdict(int)
    for src, dst in conn.execute('SELECT src_id, dst_id FROM edges'):
        a, b = (src, dst) if src < dst else (dst, src)
        weights[(a, b)] += 1
    for (a, b), w in weights.items():
        G.add_edge(a, b, weight=w)
    return G


def detect_communities(G: nx.Graph, seed: int = 42) -> dict[int, int]:
    """Run Louvain. Returns {symbol_id: community_id}.

    Two python-louvain APIs to handle:
      - Newer (≥0.16): best_partition(..., random_state=int)
      - Older Ubuntu pkg: best_partition(..., randomize=bool)
        — no per-call seed; seed via the stdlib's random.seed() so
        runs stay reproducible.
    """
    import random
    random.seed(seed)
    try:
        return louvain.best_partition(G, random_state=seed, weight='weight')
    except TypeError:
        return louvain.best_partition(G, randomize=False, weight='weight')


def label_community(file_paths: list[str], member_names: list[str]) -> str:
    """Pick a human-readable label for a community.

    Heuristic: take the most common 'src/<dir>' or 'src/<dir>/<subdir>'
    prefix across members. Falls back to the most common bigram in
    member names if files are spread across many directories.
    """
    dir_counter: Counter[str] = Counter()
    for fp in file_paths:
        parts = Path(fp).parts
        # parts[0] is 'src', parts[1] is the subsystem
        if len(parts) >= 3:
            key = f'{parts[1]}/{parts[2]}'
        elif len(parts) >= 2:
            key = parts[1]
        else:
            key = 'root'
        dir_counter[key] += 1
    if not dir_counter:
        return 'misc'
    top, count = dir_counter.most_common(1)[0]
    # If the top directory dominates (>= 50% of members), use it.
    if count >= max(1, len(file_paths) // 2):
        return top
    # Otherwise the community spans subsystems — name it after the
    # most common name prefix across members (e.g., 'Spectrum*' if
    # symbols are named SpectrumModel, SpectrumWidget, ...).
    prefixes: Counter[str] = Counter()
    for name in member_names:
        # Take the leading CamelCase prefix up to but not past a digit.
        prefix = ''
        for c in name:
            if c.isupper() or (prefix and (c.isalpha() or c == '_')):
                prefix += c
            else:
                break
            if len(prefix) >= 12:
                break
        if len(prefix) >= 3:
            prefixes[prefix] += 1
    if prefixes:
        top_prefix, _ = prefixes.most_common(1)[0]
        return f'{top}+{top_prefix}*'
    return top


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('db_path', nargs='?',
                    default='/Users/aetherclaude/data/codegraph.db')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    db_path = Path(args.db_path).resolve()
    if not db_path.exists():
        print(f'ERROR: db not found: {db_path}', file=sys.stderr)
        print('Run codegraph-extract.py first.', file=sys.stderr)
        sys.exit(1)

    t0 = time.time()
    conn = sqlite3.connect(db_path)

    # ---- Load graph ----
    G = load_graph(conn)
    print(f'codegraph-analyze: {G.number_of_nodes()} nodes, '
          f'{G.number_of_edges()} edges', file=sys.stderr)

    # ---- Community detection ----
    t1 = time.time()
    partition = detect_communities(G, seed=args.seed)
    n_communities = len(set(partition.values()))
    print(f'  Louvain: {n_communities} communities in '
          f'{time.time()-t1:.1f}s', file=sys.stderr)

    # ---- Label communities by majority directory ----
    members_by_community: dict[int, list[int]] = defaultdict(list)
    for sid, cid in partition.items():
        members_by_community[cid].append(sid)

    # Pull file_path + name for every symbol in one query
    sym_data: dict[int, tuple[str, str]] = {}
    for sid, fp, name in conn.execute(
        'SELECT id, file_path, name FROM symbols'
    ):
        sym_data[sid] = (fp, name)

    community_labels: dict[int, str] = {}
    for cid, members in members_by_community.items():
        files = [sym_data[m][0] for m in members if m in sym_data]
        names = [sym_data[m][1] for m in members if m in sym_data]
        community_labels[cid] = label_community(files, names)

    # Layout intentionally not computed here — see module docstring.
    # x_coord/y_coord stay NULL; Sigma.js does client-side ForceAtlas2.

    # ---- Write back ----
    t3 = time.time()
    updates = [
        (cid, community_labels.get(cid, 'misc'), sid)
        for sid, cid in partition.items()
    ]
    conn.executemany(
        'UPDATE symbols SET community_id=?, community_label=? WHERE id=?',
        updates,
    )
    # Metadata
    conn.execute('UPDATE metadata SET value=? WHERE key=?',
                 (str(n_communities), 'community_count'))
    conn.execute('UPDATE metadata SET value=? WHERE key=?',
                 ('false', 'layout_computed'))
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?,?)",
        ('analyzed_at', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())),
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?,?)",
        ('analyze_seconds', f'{time.time() - t0:.2f}'),
    )
    conn.commit()
    print(f'  wrote updates in {time.time()-t3:.1f}s', file=sys.stderr)
    conn.close()

    # ---- Summary print ----
    sizes = [len(m) for m in members_by_community.values()]
    print(
        f'codegraph-analyze done in {time.time()-t0:.1f}s — '
        f'{n_communities} communities '
        f'(largest={max(sizes)}, median={sorted(sizes)[len(sizes)//2]}, '
        f'smallest={min(sizes)})',
        file=sys.stderr,
    )


if __name__ == '__main__':
    main()
