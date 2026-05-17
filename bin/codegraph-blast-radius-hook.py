#!/usr/bin/env python3
"""
codegraph-blast-radius-hook — Claude Code PreToolUse hook.

When the orchestrator's Claude is about to Edit / Write / MultiEdit a
file under AetherSDR's src/, this hook computes the blast radius for
the symbols defined in that file and injects a warning into Claude's
next-turn context if the structural risk is non-trivial.

Goal: catch "I'm about to change AppSettings::instance and it has 533
transitive callers" BEFORE Claude commits to the edit, not after the
PR ships and the build breaks. Same mechanism GitNexus uses to enrich
edits with graph context.

Hook spec (Claude Code):
  - stdin: JSON with `tool_name`, `tool_input`, etc.
  - exit 0 + JSON to stdout to control behaviour
  - We emit `hookSpecificOutput.additionalContext` for non-blocking
    warnings; never block (orchestrator runs headless).

This is informational, never blocks. Output is a single short
paragraph + a list of the 5 highest-betweenness affected symbols.

Wire in via ~/.claude/settings.json PreToolUse hooks array. The
DefenseClaw observability hook stays in place; multiple PreToolUse
hooks fire in series.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time

CODEGRAPH_DB = os.environ.get(
    'CODEGRAPH_DB',
    '/Users/Shared/aetherclaude/data/codegraph.db',
)
# events.db is the dashboard's central event store. We write a
# 'codegraph:blast' row keyed by AETHER_TRACE_ID so the agent-walk
# view can correlate this hook run with its corresponding TOOL event.
EVENTS_DB = os.environ.get(
    'EVENTS_DB',
    '/Users/aetherclaude/data/events.db',
)
TRACE_ID = os.environ.get('AETHER_TRACE_ID', '')
# Minimum risk_score to bother emitting the warning. Below this the
# edit is on a leaf node nobody calls — noise.
MIN_RISK_SCORE = 0.005
# Betweenness threshold for flagging an affected symbol as "high risk"
HIGH_RISK_BETWEENNESS = 0.005
# How many transitive hops to walk in each direction. Matches the MCP
# server's default; deep enough to catch second-order ripples,
# shallow enough to stay fast.
MAX_DEPTH = 3
# Max files we'll scan in a single Edit. MultiEdit with hundreds of
# touches → skip rather than spend 30 s computing blast radius.
MAX_FILES = 8


def log_to_events_db(file_path: str, risk_score: float, high_risk_count: int,
                     symbols_count: int, callers_count: int,
                     top_high_risk: list[dict]) -> None:
    """Write a codegraph:blast row to events.db for agent-walk
    correlation. Best-effort — failures here must never break the
    hook."""
    if not os.path.exists(EVENTS_DB):
        return
    summary = {
        'file': file_path,
        'risk_score': round(risk_score, 4),
        'high_risk_count': high_risk_count,
        'symbols_count': symbols_count,
        'callers_count': callers_count,
        'top': [
            {'name': s['qualified_name'], 'bw': round(s['betweenness'] or 0, 4),
             'd': s['distance']}
            for s in top_high_risk[:5]
        ],
    }
    try:
        conn = sqlite3.connect(EVENTS_DB, timeout=2.0)
        conn.execute(
            'INSERT INTO events (timestamp, type, uid, binary_name, args, '
            '                    policy, is_agent, source, trace_id) '
            ' VALUES (?,?,?,?,?,?,?,?,?)',
            (
                time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'TOOL',
                965,
                'codegraph:blast',
                json.dumps(summary),
                '',
                1,
                'codegraph',
                TRACE_ID or None,
            )
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def emit_response(additional_context: str | None = None) -> None:
    """Write the hook response JSON to stdout and exit 0. If
    additional_context is None, the hook says nothing (no-op for
    non-AetherSDR files or low-risk edits)."""
    out = {}
    if additional_context:
        out = {
            'continue': True,
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'additionalContext': additional_context,
            },
        }
    sys.stdout.write(json.dumps(out))
    sys.exit(0)


def file_paths_from_input(tool_name: str, tool_input: dict) -> list[str]:
    """Extract every file path the tool is about to touch."""
    if tool_name in ('Edit', 'Write'):
        fp = tool_input.get('file_path')
        return [fp] if fp else []
    if tool_name == 'MultiEdit':
        fp = tool_input.get('file_path')
        return [fp] if fp else []
    if tool_name == 'NotebookEdit':
        fp = tool_input.get('notebook_path')
        return [fp] if fp else []
    return []


def is_aethersdr_path(p: str) -> bool:
    """True if the path looks like it lives in AetherSDR's src/.
    Accepts both absolute paths and basenames — the orchestrator runs
    in /tmp/aetherclaude/issue-N/ with the source tree there."""
    if not p:
        return False
    return ('AetherSDR/src/' in p) or ('/src/' in p) or p.endswith(('.cpp', '.h', '.cc', '.hpp'))


def normalize_relpath(abs_path: str) -> str:
    """Convert an absolute path under any AetherSDR checkout to the
    `src/foo/bar.cpp` form the codegraph db stores. Handles the
    common cases (working copy in /tmp, in ~/workspace, in $HOME)
    without hardcoding any one of them."""
    # Look for the 'src/' anchor — codegraph file_path always starts
    # with 'src/'. Everything before is the checkout root.
    for marker in ('/src/',):
        idx = abs_path.rfind(marker)
        if idx >= 0:
            return 'src' + abs_path[idx + len('/src'):]
    # Already relative or basename only — return as-is, the LIKE
    # match below will pick it up.
    return abs_path


def find_symbols_in_file(conn, rel_path: str) -> list[dict]:
    """Find all symbols defined in the given file plus its partner
    header/cpp. C++ symbols frequently live under the .h (class
    declaration) even when the change is in the .cpp (method body) —
    editing AppSettings.cpp ripples through every caller of every
    AppSettings method, so we surface those too."""
    seen_ids: set[int] = set()
    out: list[dict] = []

    def collect(rows):
        for r in rows:
            d = dict(r)
            if d['id'] in seen_ids:
                continue
            seen_ids.add(d['id'])
            out.append(d)

    # Exact match for the edited path
    rows = conn.execute(
        'SELECT id, qualified_name, name, kind, betweenness, degree '
        '  FROM symbols WHERE file_path = ?',
        (rel_path,)
    ).fetchall()
    collect(rows)

    # Partner files — same basename minus extension, common C++ pair
    # extensions. Adds the .h symbols when we edit a .cpp, and vice
    # versa.
    basename = rel_path.rsplit('/', 1)[-1]
    stem = basename.rsplit('.', 1)[0]
    if stem and stem != basename:
        for ext in ('h', 'hpp', 'cpp', 'cc', 'cxx'):
            partner = f'{stem}.{ext}'
            if partner == basename:
                continue
            rows = conn.execute(
                'SELECT id, qualified_name, name, kind, betweenness, degree '
                '  FROM symbols WHERE file_path LIKE ?',
                (f'%/{partner}',)
            ).fetchall()
            collect(rows)

    if out:
        return out

    # Last-ditch suffix match (handles odd checkout roots, basename-only
    # paths from MultiEdit, etc.).
    rows = conn.execute(
        'SELECT id, qualified_name, name, kind, betweenness, degree '
        '  FROM symbols WHERE file_path LIKE ?',
        (f'%/{basename}',)
    ).fetchall()
    collect(rows)
    return out


def transitive_callers(conn, seed_ids: list[int], max_depth: int) -> dict[int, int]:
    """Return {symbol_id: distance} of every symbol that transitively
    reaches at least one seed via `calls` edges, up to max_depth hops."""
    seen = {sid: 0 for sid in seed_ids}
    frontier = list(seed_ids)
    for d in range(1, max_depth + 1):
        if not frontier:
            break
        ph = ','.join('?' * len(frontier))
        rows = conn.execute(
            f'SELECT DISTINCT src_id FROM edges '
            f' WHERE dst_id IN ({ph}) AND kind="calls"',
            frontier
        ).fetchall()
        next_frontier = []
        for r in rows:
            sid = r[0]
            if sid not in seen:
                seen[sid] = d
                next_frontier.append(sid)
        frontier = next_frontier
    for sid in seed_ids:
        seen.pop(sid, None)
    return seen


def build_warning_from_data(symbols: list[dict], affected: list[dict],
                            callers: dict[int, int], risk_score: float,
                            high_risk: list[dict]) -> str | None:
    """Format the human-readable blast-radius summary that Claude
    will see as additional context. Returns None if the risk is
    too low to bother mentioning."""
    if risk_score < MIN_RISK_SCORE:
        return None

    seed_names = ', '.join(
        f'{s["qualified_name"].split("::")[-1]} (bw={s["betweenness"] or 0:.4f})'
        for s in symbols[:3]
    )
    lines = [
        '## Codegraph blast-radius check',
        '',
        f'This edit touches **{len(symbols)} symbol(s)**: {seed_names}'
        + ('...' if len(symbols) > 3 else ''),
        '',
        f'**Transitive callers** ({MAX_DEPTH} hops): '
        f'{len(callers)} symbols  ·  '
        f'**risk_score**: {risk_score:.3f}  ·  '
        f'**high-risk affected**: {len(high_risk)}',
    ]
    if high_risk:
        lines.append('')
        lines.append('Top high-betweenness callers (structural bridges — '
                     'changing the seed symbol will ripple through these):')
        lines.append('')
        for s in high_risk[:5]:
            qn = s['qualified_name']
            bw = s['betweenness']
            d = s['distance']
            fp = s['file_path']
            lines.append(f'- `{qn}` (bw={bw:.4f}, depth={d}) — {fp}')
        if len(high_risk) > 5:
            lines.append(f'- _... and {len(high_risk) - 5} more high-risk symbols_')
    lines.append('')
    lines.append('_Consider checking these dependents before proceeding. '
                 'Run codegraph MCP `impact` on the seed symbol for the full list._')
    return '\n'.join(lines)


def main():
    try:
        payload = json.loads(sys.stdin.read() or '{}')
    except json.JSONDecodeError:
        # Malformed payload — silently no-op. Don't break the run.
        emit_response(None)
        return

    tool_name = payload.get('tool_name', '')
    if tool_name not in ('Edit', 'Write', 'MultiEdit', 'NotebookEdit'):
        emit_response(None)
        return

    tool_input = payload.get('tool_input', {}) or {}
    files = file_paths_from_input(tool_name, tool_input)
    files = [f for f in files if is_aethersdr_path(f)][:MAX_FILES]
    if not files:
        emit_response(None)
        return

    if not os.path.exists(CODEGRAPH_DB):
        emit_response(None)
        return

    try:
        conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        emit_response(None)
        return

    try:
        all_symbols: list[dict] = []
        for f in files:
            rel = normalize_relpath(f)
            all_symbols.extend(find_symbols_in_file(conn, rel))
        if not all_symbols:
            emit_response(None)
            return
        seed_ids = [s['id'] for s in all_symbols]
        callers = transitive_callers(conn, seed_ids, MAX_DEPTH)
        # Hydrate the affected set once for both the warning text
        # and the events.db row.
        affected: list[dict] = []
        if callers:
            ids = list(callers.keys())
            ph = ','.join('?' * len(ids))
            for r in conn.execute(
                f'SELECT id, qualified_name, betweenness, file_path '
                f'  FROM symbols WHERE id IN ({ph})',
                ids
            ):
                affected.append({**dict(r), 'distance': callers[r['id']]})
        risk_score = sum((s['betweenness'] or 0) for s in affected)
        high_risk = sorted(
            [s for s in affected if (s['betweenness'] or 0) >= HIGH_RISK_BETWEENNESS],
            key=lambda s: -(s['betweenness'] or 0),
        )
        # ALWAYS log to events.db so Agent Walk can distinguish
        # "hook fired and scanned" (green low-risk overlay) from
        # "hook didn't fire at all" (no overlay). Previously we only
        # logged when risk_score >= 0.005, which made low-risk edits
        # look identical to non-scanned edits in the UI. Leaf-class
        # edits (MainWindow.cpp, where 117/118 callers are self-calls
        # inside the class itself) routinely fall below threshold;
        # the user reading Agent Walk reads that as "the hook is
        # broken" rather than "the hook scanned and found low risk".
        log_to_events_db(
            file_path=files[0],
            risk_score=risk_score,
            high_risk_count=len(high_risk),
            symbols_count=len(all_symbols),
            callers_count=len(callers),
            top_high_risk=high_risk,
        )
        # Only emit the warning back to Claude when risk is non-trivial
        # — Claude doesn't need a "scanned, no risk" footnote on every
        # leaf edit. Threshold only gates the conversational injection,
        # not the events.db audit row.
        warning = build_warning_from_data(all_symbols, affected, callers,
                                          risk_score, high_risk) if risk_score >= MIN_RISK_SCORE else None
        emit_response(warning)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
