#!/usr/bin/env python3
"""Cost-band footer + private audit logger for aethersdr-agent[bot] posts.

Every comment, review, and PR description the bot posts gets a coarse
public cost band appended to the body, and a precise audit row written
to sqlite. The band hides the precise cost from anyone watching the
bot's public output (so an attacker can't climb a gradient to find
expensive prompt shapes), while still surfacing spikes visibly.

Invoked from bash (run-agent.sh) and node (create-pr.js,
github-mcp-server.js). Two subcommands:

  wrap          read usage since marker, append footer, log audit row,
                print body+footer to stdout
  backfill-url  set comment_url on the most recent audit row matching
                --target (called after the POST returns the URL)
"""
import argparse
import glob
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# PRICING — UPDATE-ME when Anthropic published prices change.
# Source: https://www.anthropic.com/pricing (values as of 2026-01).
# All rates are USD per 1,000,000 tokens.
#   cache_read  ≈ 0.10x base input  (cached prompt-read discount)
#   cache_create ≈ 1.25x base input (5-minute prompt-write surcharge)
# ---------------------------------------------------------------------------
PRICING = {
    'claude-opus-4-7':   {'input': 15.0, 'cache_read': 1.50, 'cache_create': 18.75, 'output': 75.0},
    'claude-sonnet-4-6': {'input':  3.0, 'cache_read': 0.30, 'cache_create':  3.75, 'output': 15.0},
    'claude-haiku-4-5':  {'input':  1.0, 'cache_read': 0.10, 'cache_create':  1.25, 'output':  5.0},
}
FALLBACK_MODEL = 'claude-sonnet-4-6'

# Bands [lo, hi); the last band has hi=inf.
BANDS = [
    (0.0,           0.05,           '< $0.05'),
    (0.05,          0.20,           '$0.05–$0.20'),
    (0.20,          1.00,           '$0.20–$1.00'),
    (1.00,          5.00,           '$1.00–$5.00'),
    (5.00, float('inf'),            '> $5.00'),
]

SESSION_GLOB = os.path.expanduser('~/.claude/projects/**/*.jsonl')
DB_PATH      = os.environ.get('ACTIONS_DB',       '/Users/aetherclaude/data/issue-actions.db')
OFFSET_FILE  = os.environ.get('BOT_COST_OFFSETS', '/Users/aetherclaude/data/.bot-cost-offsets.json')


def cost_for(model, totals):
    p = PRICING.get(model) or PRICING[FALLBACK_MODEL]
    return (
        totals['input_tokens']                * p['input']        / 1_000_000
      + totals['cache_read_input_tokens']     * p['cache_read']   / 1_000_000
      + totals['cache_creation_input_tokens'] * p['cache_create'] / 1_000_000
      + totals['output_tokens']               * p['output']       / 1_000_000
    )


def band_for(usd):
    for lo, hi, label in BANDS:
        if lo <= usd < hi:
            return label
    return BANDS[-1][2]


def format_footer(model, band):
    # "<$0.05" and ">$5.00" already imply approximation; the middle
    # bands get a "~" prefix to signal "rough" cost.
    cost_str = band if (band.startswith('<') or band.startswith('>')) else '~' + band
    return (
        '\n\n---\n'
        '<sub>\U0001f916 aethersdr-agent · cost: '
        + cost_str + ' · model: ' + model + '</sub>'
    )


def read_usage_since_marker():
    """Sum usage records appearing after each session JSONL's last-read
    byte offset. Returns (model_seen_or_fallback, totals). Advances the
    offsets file even on partial failure (next call won't double-count
    bytes we already managed to read)."""
    try:
        with open(OFFSET_FILE) as fh:
            offsets = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        offsets = None

    totals = {
        'input_tokens': 0,
        'output_tokens': 0,
        'cache_read_input_tokens': 0,
        'cache_creation_input_tokens': 0,
    }
    model_seen = None
    new_offsets = dict(offsets) if offsets is not None else {}

    paths = glob.glob(SESSION_GLOB, recursive=True)

    # First-ever run: don't sum the entire history. Seed offsets at EOF
    # and report zero. The very first post will under-report; everything
    # after is accurate.
    if offsets is None:
        for path in paths:
            try:
                new_offsets[path] = os.path.getsize(path)
            except OSError:
                pass
        _save_offsets(new_offsets)
        return FALLBACK_MODEL, totals

    for path in paths:
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        start = offsets.get(path, 0)
        # If a file shrank (truncation or rotation), start over.
        if start > size:
            start = 0
        if start >= size:
            new_offsets[path] = size
            continue
        try:
            with open(path, 'rb') as fh:
                fh.seek(start)
                chunk = fh.read()
            new_offsets[path] = start + len(chunk)
        except OSError:
            continue
        for raw in chunk.splitlines():
            if b'"usage"' not in raw:
                continue
            try:
                rec = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            msg = rec.get('message') or {}
            u = msg.get('usage') or {}
            if not u:
                continue
            for k in totals:
                v = u.get(k, 0)
                if isinstance(v, (int, float)):
                    totals[k] += int(v)
            m = msg.get('model')
            if m:
                model_seen = m

    _save_offsets(new_offsets)
    return (model_seen or FALLBACK_MODEL), totals


def _save_offsets(offsets):
    tmp = OFFSET_FILE + '.tmp'
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(tmp, 'w') as fh:
        json.dump(offsets, fh)
    os.replace(tmp, OFFSET_FILE)


def _ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bot_cost_audit (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc               TEXT    NOT NULL,
            kind                        TEXT    NOT NULL,
            source_target               TEXT    NOT NULL,
            comment_url                 TEXT,
            model                       TEXT    NOT NULL,
            input_tokens                INTEGER NOT NULL DEFAULT 0,
            output_tokens               INTEGER NOT NULL DEFAULT 0,
            cache_read_input_tokens     INTEGER NOT NULL DEFAULT 0,
            cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0,
            usd_cost                    REAL    NOT NULL,
            public_band                 TEXT    NOT NULL,
            run_id                      TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bca_target ON bot_cost_audit(source_target)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bca_ts     ON bot_cost_audit(timestamp_utc)")
    conn.commit()


def log_audit(model, totals, usd, band, kind, target, run_id):
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        _ensure_schema(conn)
        conn.execute("""
            INSERT INTO bot_cost_audit (
                timestamp_utc, kind, source_target, model,
                input_tokens, output_tokens,
                cache_read_input_tokens, cache_creation_input_tokens,
                usd_cost, public_band, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, kind, target, model,
              totals['input_tokens'], totals['output_tokens'],
              totals['cache_read_input_tokens'],
              totals['cache_creation_input_tokens'],
              usd, band, run_id))
        conn.commit()
    finally:
        conn.close()


# --- target derivation -------------------------------------------------------

_TARGET_RE_ENDPOINT = re.compile(r'/(issues|pulls)/(\d+)(?:/|$)')
_TARGET_RE_DISCUSSION = re.compile(r'discussion[_-]?(?:id|number)?[:=](\S+)', re.I)

def derive_target(target_arg, endpoint, kind):
    if target_arg:
        return target_arg
    if endpoint:
        m = _TARGET_RE_ENDPOINT.search(endpoint)
        if m:
            t = 'pr' if m.group(1) == 'pulls' else 'issue'
            return '{}:{}'.format(t, m.group(2))
    if kind == 'pr_description':
        return 'pr:new'
    if kind == 'discussion_comment':
        return 'discussion:?'
    return 'unknown:?'


# --- subcommand handlers -----------------------------------------------------

def cmd_wrap(args):
    if args.body_file:
        with open(args.body_file) as fh:
            body = fh.read()
    elif args.body == '-':
        body = sys.stdin.read()
    else:
        body = args.body or ''

    target = derive_target(args.target, args.endpoint, args.kind)
    model, totals = read_usage_since_marker()
    usd = cost_for(model, totals)
    band = band_for(usd)
    try:
        log_audit(model, totals, usd, band, args.kind, target,
                  args.run_id or os.environ.get('RUN_ID', ''))
    except sqlite3.Error as e:
        # Never block a post on audit-log failure; surface to stderr.
        sys.stderr.write('bot-cost: audit log failed: {}\n'.format(e))

    sys.stdout.write(body + format_footer(model, band))


def cmd_backfill_url(args):
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        _ensure_schema(conn)
        conn.execute("""
            UPDATE bot_cost_audit
            SET comment_url = ?
            WHERE id = (
                SELECT id FROM bot_cost_audit
                WHERE source_target = ?
                  AND (comment_url IS NULL OR comment_url = '')
                ORDER BY id DESC LIMIT 1
            )
        """, (args.url, args.target))
        conn.commit()
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest='cmd', required=True)

    w = sub.add_parser('wrap', help='append cost footer + log audit row')
    w.add_argument('--kind', required=True,
                   choices=['issue_comment', 'pr_review', 'pr_description',
                            'discussion_comment'])
    w.add_argument('--target', default=None,
                   help='explicit "issue:N" / "pr:N" / "discussion:N"; '
                        'if omitted, derived from --endpoint')
    w.add_argument('--endpoint', default=None,
                   help='API path, e.g. /repos/o/r/issues/123/comments')
    w.add_argument('--run-id', default=None)
    grp = w.add_mutually_exclusive_group(required=True)
    grp.add_argument('--body', help='inline body text, or "-" for stdin')
    grp.add_argument('--body-file', help='path to file containing body')
    w.set_defaults(func=cmd_wrap)

    b = sub.add_parser('backfill-url',
                       help='set comment_url on the most recent audit row '
                            'for --target')
    b.add_argument('--target', required=True)
    b.add_argument('--url',    required=True)
    b.set_defaults(func=cmd_backfill_url)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
