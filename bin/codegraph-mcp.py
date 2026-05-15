#!/usr/bin/env python3
"""
codegraph-mcp — Model Context Protocol server over the codegraph SQLite db.

Exposes the AetherSDR symbol graph as MCP tools so AI coding assistants
(Claude Code, Cursor, …) can pull architectural context on demand
instead of reading 30 files to figure out what a symbol does and who
depends on it.

Tools:
  search_symbols(query, limit=20)        — substring match on name/qualified_name
  get_symbol(name_or_id)                 — fetch one symbol record
  get_neighbors(symbol, depth=1)         — k-step BFS, with edge kinds
  impact(symbol, max_depth=3)            — blast-radius: upstream + downstream
                                           callers, with betweenness-weighted
                                           risk score and a "high_risk" subset

Transport: stdio JSON-RPC 2.0 (the canonical MCP transport for local
editor integrations). Every Claude Code invocation spawns this script,
talks to it for the duration of the session, then it exits.

Database: reads /Users/Shared/aetherclaude/data/codegraph.db (the path
the dashboard and the nightly launchd job already use). Read-only —
all queries open the db with `mode=ro`.

Wire it into Claude Code with:
    claude mcp add codegraph -- /Users/Shared/aetherclaude/bin/codegraph-mcp.py

Or in ~/.claude/settings.json:
    {"mcpServers": {"codegraph": {"command": "/path/to/codegraph-mcp.py"}}}
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from typing import Any

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEFAULT_DB = os.environ.get(
    'CODEGRAPH_DB',
    '/Users/Shared/aetherclaude/data/codegraph.db',
)

# Risk threshold: callers/callees with betweenness above this are flagged
# as "high_risk" in impact() output. Tuned against AetherSDR — top-20
# bridges have betweenness 0.01–0.20; 0.005 catches the long-tail of
# meaningful structural nodes without spamming.
HIGH_RISK_BETWEENNESS = 0.005

PROTOCOL_VERSION = '2024-11-05'  # Current MCP spec version
SERVER_NAME = 'codegraph'
SERVER_VERSION = '1.0.0'


# --------------------------------------------------------------------------
# DB helpers
# --------------------------------------------------------------------------

def open_db(path: str) -> sqlite3.Connection:
    """Open codegraph.db read-only. Read-only protects against accidental
    writes from the MCP server and lets us run alongside the nightly
    refresh job without lock contention."""
    uri = f'file:{path}?mode=ro'
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def resolve_symbol(conn, name_or_id) -> dict | None:
    """Look up a symbol by integer id, exact qualified_name, exact name,
    or qualified_name suffix. Returns the row dict or None."""
    if isinstance(name_or_id, int) or (isinstance(name_or_id, str) and name_or_id.isdigit()):
        row = conn.execute(
            'SELECT * FROM symbols WHERE id = ?', (int(name_or_id),)
        ).fetchone()
        if row:
            return dict(row)

    s = str(name_or_id)
    # Exact qualified_name first (most precise)
    row = conn.execute(
        'SELECT * FROM symbols WHERE qualified_name = ?', (s,)
    ).fetchone()
    if row:
        return dict(row)
    # Exact name (could be ambiguous; pick highest-degree)
    row = conn.execute(
        'SELECT * FROM symbols WHERE name = ? ORDER BY degree DESC LIMIT 1',
        (s,)
    ).fetchone()
    if row:
        return dict(row)
    # Suffix match on qualified_name (`MainWindow::buildUI` matches
    # `AetherSDR::MainWindow::buildUI`)
    row = conn.execute(
        'SELECT * FROM symbols WHERE qualified_name LIKE ? '
        'ORDER BY degree DESC LIMIT 1',
        (f'%{s}',)
    ).fetchone()
    if row:
        return dict(row)
    return None


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------

def tool_search_symbols(conn, query: str, limit: int = 20) -> dict:
    """Substring search across name and qualified_name. Returns the most
    structurally relevant matches by degree."""
    limit = max(1, min(100, int(limit)))
    q = f'%{query}%'
    rows = conn.execute(
        'SELECT id, qualified_name, name, kind, file_path, line_number, '
        '       degree, betweenness, community_label '
        '  FROM symbols '
        ' WHERE qualified_name LIKE ? OR name LIKE ? '
        ' ORDER BY degree DESC LIMIT ?',
        (q, q, limit)
    ).fetchall()
    return {
        'query': query,
        'count': len(rows),
        'symbols': [dict(r) for r in rows],
    }


def tool_get_symbol(conn, name_or_id) -> dict:
    """Return a single symbol with adjacency counts."""
    sym = resolve_symbol(conn, name_or_id)
    if not sym:
        return {'error': f'symbol not found: {name_or_id!r}'}
    sid = sym['id']
    sym['callers_count'] = conn.execute(
        'SELECT COUNT(*) FROM edges WHERE dst_id=? AND kind="calls"', (sid,)
    ).fetchone()[0]
    sym['callees_count'] = conn.execute(
        'SELECT COUNT(*) FROM edges WHERE src_id=? AND kind="calls"', (sid,)
    ).fetchone()[0]
    sym['inherits_from'] = [
        r['qualified_name'] for r in conn.execute(
            'SELECT s.qualified_name FROM edges e JOIN symbols s ON e.dst_id=s.id '
            ' WHERE e.src_id=? AND e.kind="inherits"', (sid,)
        )
    ]
    sym['inherited_by'] = [
        r['qualified_name'] for r in conn.execute(
            'SELECT s.qualified_name FROM edges e JOIN symbols s ON e.src_id=s.id '
            ' WHERE e.dst_id=? AND e.kind="inherits"', (sid,)
        )
    ]
    return sym


def tool_get_neighbors(conn, symbol, depth: int = 1, edge_kinds: list[str] | None = None) -> dict:
    """k-step BFS from `symbol`, undirected. Returns a list of
    {symbol, distance, edge_kind}. `edge_kinds` filters which edge
    types are followed (default: all)."""
    sym = resolve_symbol(conn, symbol)
    if not sym:
        return {'error': f'symbol not found: {symbol!r}'}
    depth = max(1, min(5, int(depth)))
    edge_kinds = edge_kinds or ['calls', 'inherits', 'signal-slot']
    placeholders = ','.join('?' * len(edge_kinds))

    visited = {sym['id']: (0, None, None)}  # id -> (distance, via_kind, direction)
    frontier = [sym['id']]
    for d in range(1, depth + 1):
        next_frontier = []
        if not frontier:
            break
        for nid in frontier:
            # Outgoing
            for r in conn.execute(
                f'SELECT dst_id, kind FROM edges '
                f' WHERE src_id=? AND kind IN ({placeholders})',
                (nid, *edge_kinds)
            ):
                tid = r['dst_id']
                if tid not in visited:
                    visited[tid] = (d, r['kind'], 'out')
                    next_frontier.append(tid)
            # Incoming
            for r in conn.execute(
                f'SELECT src_id, kind FROM edges '
                f' WHERE dst_id=? AND kind IN ({placeholders})',
                (nid, *edge_kinds)
            ):
                tid = r['src_id']
                if tid not in visited:
                    visited[tid] = (d, r['kind'], 'in')
                    next_frontier.append(tid)
        frontier = next_frontier

    # Hydrate
    ids = [i for i in visited if i != sym['id']]
    if not ids:
        return {'symbol': sym['qualified_name'], 'neighbors': []}
    placeholders2 = ','.join('?' * len(ids))
    rows = conn.execute(
        f'SELECT id, qualified_name, kind, file_path, line_number, degree, betweenness '
        f'  FROM symbols WHERE id IN ({placeholders2})',
        ids
    ).fetchall()
    neighbors = []
    for r in rows:
        d, via_kind, direction = visited[r['id']]
        neighbors.append({
            **dict(r),
            'distance': d,
            'via_kind': via_kind,
            'direction': direction,
        })
    neighbors.sort(key=lambda n: (n['distance'], -n['degree']))
    return {
        'symbol': sym['qualified_name'],
        'depth': depth,
        'neighbors': neighbors,
    }


def tool_impact(conn, symbol, max_depth: int = 3) -> dict:
    """Blast-radius analysis. Walks transitive callers (upstream — who's
    affected if `symbol` changes behavior) and transitive callees
    (downstream — what `symbol` itself relies on), separately. Returns
    a risk summary keyed off betweenness centrality.

    Use this before editing a symbol to spot the unexpected ripples.
    A high-betweenness affected node = a structural bridge: changing
    `symbol` will reverberate widely through it."""
    sym = resolve_symbol(conn, symbol)
    if not sym:
        return {'error': f'symbol not found: {symbol!r}'}
    max_depth = max(1, min(5, int(max_depth)))
    sid = sym['id']

    # Detect whether the edges table has the Phase-1 confidence columns.
    # Older codegraph.db builds predate them; gracefully fall back to
    # treating every edge as full-confidence in that case.
    has_confidence = bool(conn.execute(
        "SELECT 1 FROM pragma_table_info('edges') WHERE name='confidence_score'"
    ).fetchone())

    def walk(seed_id, direction):
        """direction='upstream' walks src_id<-dst_id (callers).
        direction='downstream' walks src_id->dst_id (callees).
        Returns {symbol_id: (distance, min_confidence_along_path)}.
        Min confidence along the path is the bottleneck — one weak
        link makes the whole reach less trustworthy."""
        seen = {seed_id: (0, 1.0)}
        frontier = [seed_id]
        for d in range(1, max_depth + 1):
            if not frontier:
                break
            next_frontier = []
            for nid in frontier:
                parent_conf = seen[nid][1]
                if has_confidence:
                    if direction == 'upstream':
                        rows = conn.execute(
                            'SELECT src_id, confidence_score FROM edges '
                            ' WHERE dst_id=? AND kind="calls"',
                            (nid,)
                        )
                    else:
                        rows = conn.execute(
                            'SELECT dst_id, confidence_score FROM edges '
                            ' WHERE src_id=? AND kind="calls"',
                            (nid,)
                        )
                else:
                    col = 'src_id' if direction == 'upstream' else 'dst_id'
                    other_col = 'dst_id' if direction == 'upstream' else 'src_id'
                    rows = [(r[0], 1.0) for r in conn.execute(
                        f'SELECT {col} FROM edges WHERE {other_col}=? AND kind="calls"',
                        (nid,)
                    )]
                for r in rows:
                    other, edge_conf = r[0], r[1]
                    path_conf = min(parent_conf, float(edge_conf or 1.0))
                    if other not in seen:
                        seen[other] = (d, path_conf)
                        next_frontier.append(other)
            frontier = next_frontier
        seen.pop(seed_id, None)
        return seen

    upstream = walk(sid, 'upstream')
    downstream = walk(sid, 'downstream')

    def hydrate(reach: dict) -> list[dict]:
        if not reach:
            return []
        ids = list(reach.keys())
        ph = ','.join('?' * len(ids))
        rows = conn.execute(
            f'SELECT id, qualified_name, kind, file_path, line_number, '
            f'       degree, betweenness FROM symbols WHERE id IN ({ph})',
            ids
        ).fetchall()
        out = []
        for r in rows:
            distance, path_conf = reach[r['id']]
            out.append({
                **dict(r),
                'distance': distance,
                'path_confidence': round(path_conf, 3),
            })
        out.sort(key=lambda x: (-x['betweenness'] or 0, x['distance']))
        return out

    up_list = hydrate(upstream)
    dn_list = hydrate(downstream)
    affected = up_list + dn_list

    # Risk score weights each affected node's betweenness by its
    # path confidence — a high-betweenness symbol reached only via
    # low-confidence inferred edges shouldn't drive risk as hard as
    # one reached via deterministic AST edges.
    risk_score = sum(
        (s['betweenness'] or 0) * (s['path_confidence'] or 0)
        for s in affected
    )
    high_risk = [
        s for s in affected
        if (s['betweenness'] or 0) * (s['path_confidence'] or 0)
            >= HIGH_RISK_BETWEENNESS
    ]

    return {
        'symbol': sym['qualified_name'],
        'max_depth': max_depth,
        'self_betweenness': sym['betweenness'],
        'upstream_count': len(up_list),
        'downstream_count': len(dn_list),
        'risk_score': round(risk_score, 4),
        'high_risk_count': len(high_risk),
        'high_risk': high_risk[:20],
        'upstream': up_list[:50],
        'downstream': dn_list[:50],
    }


def tool_get_stats(conn) -> dict:
    """Quick health/freshness summary for the codegraph."""
    meta = dict(conn.execute('SELECT key, value FROM metadata').fetchall())
    counts = {
        'symbols': conn.execute('SELECT COUNT(*) FROM symbols').fetchone()[0],
        'edges_total': conn.execute('SELECT COUNT(*) FROM edges').fetchone()[0],
    }
    for kind in ('calls', 'inherits', 'signal-slot'):
        counts[f'edges_{kind.replace("-", "_")}'] = conn.execute(
            'SELECT COUNT(*) FROM edges WHERE kind=?', (kind,)
        ).fetchone()[0]
    return {'counts': counts, 'metadata': meta}


def tool_get_rationale(conn, symbol) -> dict:
    """For a given code symbol (or concept), return all CONCEPT nodes
    related to it via documented_in / rationale_for / motivates /
    implements_pattern / obsolesces edges. Use this to answer "why
    does this symbol exist" / "what design decisions shaped it"
    questions before editing.

    Concepts are extracted from AetherSDR docs by codegraph-extract-
    docs.py; their relations carry confidence='INFERRED' and a 0-1
    confidence_score from the LLM."""
    sym = resolve_symbol(conn, symbol)
    if not sym:
        return {'error': f'symbol not found: {symbol!r}'}
    sid = sym['id']
    # Concepts may be on either side of the edge depending on the
    # relation (e.g. rationale_for points concept→symbol, while
    # implements_pattern points symbol→concept). Query both.
    concept_relations = (
        'documented_in', 'rationale_for', 'motivates',
        'implements_pattern', 'obsolesces',
    )
    placeholders = ','.join('?' * len(concept_relations))
    out_concepts: list[dict] = []
    seen: set[int] = set()
    # Concept → this symbol
    for r in conn.execute(
        f'SELECT s.id, s.qualified_name, s.name, s.signature AS description, '
        f'       s.parent_scope AS concept_kind, e.kind AS relation, '
        f'       e.confidence_score, e.confidence '
        f'  FROM edges e JOIN symbols s ON e.src_id=s.id '
        f' WHERE e.dst_id=? AND s.kind="concept" '
        f'   AND e.kind IN ({placeholders}) '
        f' ORDER BY e.confidence_score DESC',
        (sid, *concept_relations)
    ):
        if r['id'] in seen:
            continue
        seen.add(r['id'])
        d = dict(r)
        d['direction'] = 'incoming'  # concept → this symbol
        out_concepts.append(d)
    # This symbol → concept (e.g. when this symbol IS a concept linking
    # to another, or rare cases where a code symbol is the source of
    # an implements_pattern edge).
    for r in conn.execute(
        f'SELECT s.id, s.qualified_name, s.name, s.signature AS description, '
        f'       s.parent_scope AS concept_kind, e.kind AS relation, '
        f'       e.confidence_score, e.confidence '
        f'  FROM edges e JOIN symbols s ON e.dst_id=s.id '
        f' WHERE e.src_id=? AND s.kind="concept" '
        f'   AND e.kind IN ({placeholders}) '
        f' ORDER BY e.confidence_score DESC',
        (sid, *concept_relations)
    ):
        if r['id'] in seen:
            continue
        seen.add(r['id'])
        d = dict(r)
        d['direction'] = 'outgoing'  # this symbol → concept
        out_concepts.append(d)
    return {
        'symbol': sym['qualified_name'],
        'kind': sym['kind'],
        'concepts_count': len(out_concepts),
        'concepts': out_concepts,
    }


def tool_staleness(conn) -> dict:
    """Compare the codegraph's recorded src_head_sha against AetherSDR's
    live HEAD. Lets agents decide whether to trust the index or
    request a re-extraction before using impact / get_neighbors."""
    import subprocess
    meta = dict(conn.execute('SELECT key, value FROM metadata').fetchall())
    recorded = (meta.get('src_head_sha') or '').strip()
    src_path = meta.get('src_root', '/Users/aetherclaude/workspace/AetherSDR')
    # The src_root in metadata may be the in-container path (/src);
    # remap to the host path the dashboard / agent sees.
    if src_path == '/src' or src_path == '/src/src':
        src_path = '/Users/aetherclaude/workspace/AetherSDR'
    elif src_path.endswith('/src'):
        src_path = src_path[:-4]
    current = ''
    commits_behind = 0
    reason = ''
    if not recorded:
        reason = 'no src_head_sha in metadata (re-run extractor)'
    else:
        try:
            out = subprocess.run(
                ['git', '-C', src_path, 'rev-parse', 'HEAD'],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                current = out.stdout.strip()
        except Exception as e:
            reason = f'git rev-parse failed: {e}'
    if recorded and current and recorded != current:
        try:
            out = subprocess.run(
                ['git', '-C', src_path, 'rev-list',
                 f'{recorded}..{current}', '--count'],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                commits_behind = int(out.stdout.strip() or '0')
            else:
                commits_behind = -1
                reason = 'recorded SHA unreachable from HEAD'
        except Exception as e:
            reason = f'git rev-list failed: {e}'
    is_stale = (commits_behind != 0 and recorded and current)
    return {
        'is_stale': bool(is_stale),
        'commits_behind': commits_behind,
        'src_head_sha': recorded,
        'current_head_sha': current,
        'extracted_at': meta.get('extracted_at', ''),
        'reason': reason,
    }


# --------------------------------------------------------------------------
# Tool registry — JSONSchema for each tool's input
# --------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        'name': 'search_symbols',
        'description': (
            'Search the AetherSDR codegraph for symbols by substring of '
            'name or qualified_name. Returns the highest-degree matches. '
            'Use this to find anchor symbols before calling get_symbol, '
            'get_neighbors, or impact.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'query': {'type': 'string', 'description': 'Substring to match against name and qualified_name'},
                'limit': {'type': 'integer', 'default': 20, 'minimum': 1, 'maximum': 100},
            },
            'required': ['query'],
        },
    },
    {
        'name': 'get_symbol',
        'description': (
            'Fetch a single symbol\'s record by integer id, exact '
            'qualified_name (e.g. "AetherSDR::MainWindow::buildUI"), '
            'bare name, or qualified_name suffix. Returns the symbol '
            'plus caller/callee counts and inheritance chain.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'symbol': {'type': 'string', 'description': 'Symbol identifier (id, name, or qualified_name)'},
            },
            'required': ['symbol'],
        },
    },
    {
        'name': 'get_neighbors',
        'description': (
            'k-step BFS from the given symbol, returning all reachable '
            'neighbors with distance and the edge kind that connects '
            'them. Use this to map out a symbol\'s local neighborhood '
            'before making edits.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'symbol': {'type': 'string'},
                'depth': {'type': 'integer', 'default': 1, 'minimum': 1, 'maximum': 5},
                'edge_kinds': {
                    'type': 'array',
                    'items': {'type': 'string', 'enum': ['calls', 'inherits', 'signal-slot']},
                    'default': ['calls', 'inherits', 'signal-slot'],
                },
            },
            'required': ['symbol'],
        },
    },
    {
        'name': 'impact',
        'description': (
            'Blast-radius analysis. Walks transitive callers (upstream) '
            'and callees (downstream) up to max_depth, weights each '
            'affected symbol by its betweenness centrality, and returns '
            'a risk_score + high_risk subset. Call this BEFORE editing '
            'any non-trivial AetherSDR symbol to surface unexpected '
            'ripple effects through structural bridges (e.g. AppSettings'
            '::instance, MainWindow). The high_risk list is the things '
            'a reviewer should look at carefully.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'symbol': {'type': 'string'},
                'max_depth': {'type': 'integer', 'default': 3, 'minimum': 1, 'maximum': 5},
            },
            'required': ['symbol'],
        },
    },
    {
        'name': 'get_stats',
        'description': 'Symbol/edge counts and codegraph metadata (last extraction time, extractor version, etc.).',
        'inputSchema': {'type': 'object', 'properties': {}},
    },
    {
        'name': 'get_rationale',
        'description': (
            'Returns the architectural concepts (subsystems, patterns, '
            'principles, protocols, features) connected to a code symbol '
            'via documented_in / rationale_for / motivates / '
            'implements_pattern / obsolesces edges. Concepts are '
            'extracted from AetherSDR docs by codegraph-extract-docs.py. '
            'Use this to answer "why does this symbol exist" / "what '
            'design decisions shaped it" before editing a non-trivial '
            'symbol — same pre-edit safety check as impact() but for '
            'design rationale instead of structural blast radius.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'symbol': {'type': 'string'},
            },
            'required': ['symbol'],
        },
    },
    {
        'name': 'staleness',
        'description': (
            'Returns whether the codegraph is behind AetherSDR HEAD. '
            'commits_behind > 0 means symbols/edges/centrality may not '
            'reflect the current source. Call this before relying on '
            'impact() output for high-stakes edits.'
        ),
        'inputSchema': {'type': 'object', 'properties': {}},
    },
]


# --------------------------------------------------------------------------
# JSON-RPC stdio loop (MCP transport)
# --------------------------------------------------------------------------

def call_tool(conn, name: str, arguments: dict) -> dict:
    """Dispatch a tool call. Returns the JSON result the MCP client
    will see. Errors are returned as `{error: "..."}` rather than
    raised, so the client gets a structured response."""
    try:
        if name == 'search_symbols':
            return tool_search_symbols(conn, **arguments)
        if name == 'get_symbol':
            return tool_get_symbol(conn, arguments['symbol'])
        if name == 'get_neighbors':
            return tool_get_neighbors(conn, **arguments)
        if name == 'impact':
            return tool_impact(conn, **arguments)
        if name == 'get_stats':
            return tool_get_stats(conn)
        if name == 'staleness':
            return tool_staleness(conn)
        if name == 'get_rationale':
            return tool_get_rationale(conn, arguments['symbol'])
        return {'error': f'unknown tool: {name}'}
    except sqlite3.Error as e:
        return {'error': f'sqlite error: {e}'}
    except (KeyError, TypeError) as e:
        return {'error': f'bad arguments: {e}'}


def write_response(payload: dict) -> None:
    """Write a single JSON-RPC response to stdout, framed by newline.
    MCP stdio uses LSP-style framing in some implementations but the
    canonical MCP spec uses newline-delimited JSON for stdio."""
    sys.stdout.write(json.dumps(payload) + '\n')
    sys.stdout.flush()


def handle_request(conn, msg: dict) -> dict | None:
    """Route an incoming JSON-RPC request to the appropriate MCP method.
    Returns the response dict, or None for notifications (which MCP
    requires no response for)."""
    method = msg.get('method')
    msg_id = msg.get('id')
    is_notification = (msg_id is None)

    if method == 'initialize':
        result = {
            'protocolVersion': PROTOCOL_VERSION,
            'capabilities': {'tools': {}},
            'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
        }
    elif method == 'notifications/initialized':
        # Client signals it's ready; no response.
        return None
    elif method == 'tools/list':
        result = {'tools': TOOL_SCHEMAS}
    elif method == 'tools/call':
        params = msg.get('params', {})
        tool_name = params.get('name', '')
        args = params.get('arguments', {}) or {}
        out = call_tool(conn, tool_name, args)
        # MCP tool results are content[] arrays; we serialize the dict
        # as JSON text so the client sees a structured response.
        result = {
            'content': [
                {'type': 'text', 'text': json.dumps(out, indent=2, default=str)}
            ],
            'isError': bool(out.get('error')),
        }
    elif method == 'ping':
        result = {}
    elif method in ('shutdown', 'exit'):
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': None}
    else:
        if is_notification:
            return None
        return {
            'jsonrpc': '2.0',
            'id': msg_id,
            'error': {'code': -32601, 'message': f'method not found: {method}'},
        }

    if is_notification:
        return None
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def serve_stdio(db_path: str) -> None:
    """Read JSON-RPC requests from stdin (one per line), dispatch, write
    responses to stdout. Stays in this loop until stdin EOF or a fatal
    error. Connection to the codegraph db is opened once and reused."""
    if not os.path.exists(db_path):
        # Surface the missing-db case via a startup log on stderr so
        # `claude mcp add` shows the operator a useful diagnostic.
        print(f'[codegraph-mcp] db not found: {db_path}', file=sys.stderr)
        # Don't exit — Claude Code will still start the server, and
        # tool calls return a structured error per call.
    conn = open_db(db_path)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            write_response({
                'jsonrpc': '2.0',
                'id': None,
                'error': {'code': -32700, 'message': f'parse error: {e}'},
            })
            continue
        try:
            response = handle_request(conn, msg)
            if response is not None:
                write_response(response)
        except Exception as e:
            # Surface as JSON-RPC error rather than crashing the server
            write_response({
                'jsonrpc': '2.0',
                'id': msg.get('id'),
                'error': {'code': -32000, 'message': str(e)},
            })

    conn.close()


# --------------------------------------------------------------------------
# CLI: stdio server + a debug "call" mode for local testing
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split('\n')[0])
    ap.add_argument('--db', default=DEFAULT_DB,
                    help=f'codegraph SQLite path (default: {DEFAULT_DB})')
    sub = ap.add_subparsers(dest='cmd')

    # `serve` (default) — stdio MCP server
    sub.add_parser('serve', help='Run as stdio MCP server (default)')

    # `call` — invoke a single tool from the command line for testing
    call = sub.add_parser('call', help='Invoke one tool and print the result')
    call.add_argument('tool')
    call.add_argument('args', nargs='?', default='{}',
                      help='JSON-encoded arguments object, e.g. \'{"query":"Audio"}\'')

    args = ap.parse_args()

    if args.cmd == 'call':
        conn = open_db(args.db)
        try:
            arguments = json.loads(args.args)
        except json.JSONDecodeError as e:
            print(f'bad --args JSON: {e}', file=sys.stderr)
            sys.exit(2)
        out = call_tool(conn, args.tool, arguments)
        print(json.dumps(out, indent=2, default=str))
        return

    serve_stdio(args.db)


if __name__ == '__main__':
    main()
