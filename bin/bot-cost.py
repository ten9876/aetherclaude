#!/usr/bin/env python3
"""Cost footer + audit logger for aethersdr-agent[bot] posts.

Every comment, review, and PR description the bot posts gets a precise
USD cost appended to the body, and a matching audit row written to
sqlite. The original implementation used coarse cost bands to hide
exact costs from public observers; operator preference is now precise
amounts — visibility of per-post cost outweighs the gradient-attack
concern (the orchestrator is single-tenant, posts are infrequent,
and the audit row already stored the precise figure anyway).

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
# Source: https://www.anthropic.com/pricing (values as of 2026-05).
# All rates are USD per 1,000,000 tokens.
#   cache_read   ≈ 0.10x base input  (cached prompt-read discount)
#   cache_create = 2.00x base input  (1-HOUR ephemeral cache surcharge)
#
# Cache_create uses the 1-hour rate, not the 5-minute rate (1.25x), because
# Claude Code defaults to ephemeral_1h_input_tokens — confirmed by
# inspecting session JSONLs (`cache_creation.ephemeral_1h_input_tokens`
# is populated; 5m field stays at 0). Earlier table used 5-min rates and
# was under-attributing cache writes by 37%.
# ---------------------------------------------------------------------------
PRICING = {
    'claude-fable-5':    {'input': 10.0, 'cache_read': 1.00, 'cache_create': 20.00, 'output': 50.0},
    'claude-opus-4-8':   {'input':  5.0, 'cache_read': 0.50, 'cache_create': 10.00, 'output': 25.0},
    'claude-opus-4-7':   {'input':  5.0, 'cache_read': 0.50, 'cache_create': 10.00, 'output': 25.0},
    'claude-sonnet-4-6': {'input':  3.0, 'cache_read': 0.30, 'cache_create':  6.00, 'output': 15.0},
    'claude-haiku-4-5':  {'input':  1.0, 'cache_read': 0.10, 'cache_create':  2.00, 'output':  5.0},
}
FALLBACK_MODEL = 'claude-sonnet-4-6'

# ── Framework-tag sanitizer ─────────────────────────────────────────────────
# Strip framework-internal XML-style tags from bot post bodies. These
# tags don't appear in the bot's natural markdown output (verified across
# 30 days of post-backfill scan); any instance in an outbound body means
# either training-set residue, an upstream context that carried a prompt-
# injection seed, or a model jailbreak. Never let them out — a downstream
# LLM that reads PR comments via `gh pr view` could be derailed by them.
#
# Defense-in-depth: no confirmed live incident as of the initial deploy;
# this closes the surface proactively before one materializes.
FRAMEWORK_TAG_PATTERNS = [
    # (regex, kind-for-telemetry). Order matters only for telemetry
    # labeling — a tag that matches an earlier specific pattern gets
    # that label rather than the namespace catch-all.
    (re.compile(r'<system-reminder\b[^>]*>.*?</system-reminder>',
                re.IGNORECASE | re.DOTALL),                  'system-reminder-paired'),
    (re.compile(r'<system-reminder\b[^>]*/>', re.IGNORECASE), 'system-reminder-self-closing'),
    (re.compile(r'<system\b[^>]*>.*?</system>',
                re.IGNORECASE | re.DOTALL),                  'system-paired'),
    (re.compile(r'<command-name\b[^>]*>.*?</command-name>',
                re.IGNORECASE | re.DOTALL),                  'command-name'),
    (re.compile(r'<task-notification\b[^>]*>.*?</task-notification>',
                re.IGNORECASE | re.DOTALL),                  'task-notification'),
    # Namespace catch-alls: any well-formed paired tag whose name is in
    # the system-* / user-prompt-* / task-* / hook-* namespace. The \1
    # backreference ensures open/close match (won't false-positive on
    # legitimate prose that mentions "<system-something>" without a
    # matching close).
    (re.compile(r'<(system-[a-z][a-z0-9-]*)\b[^>]*>.*?</\1>',
                re.IGNORECASE | re.DOTALL),                  'system-namespace'),
    (re.compile(r'<(user-prompt-[a-z][a-z0-9-]*)\b[^>]*>.*?</\1>',
                re.IGNORECASE | re.DOTALL),                  'user-prompt-namespace'),
    (re.compile(r'<(task-[a-z][a-z0-9-]*)\b[^>]*>.*?</\1>',
                re.IGNORECASE | re.DOTALL),                  'task-namespace'),
    (re.compile(r'<(hook-[a-z][a-z0-9-]*)\b[^>]*>.*?</\1>',
                re.IGNORECASE | re.DOTALL),                  'hook-namespace'),
]

# If the body shrinks below this many chars after scrubbing, the
# original was overwhelmingly framework tags — almost certainly a
# successful prompt-injection of the agent. Don't post silently; emit
# a clear "blocked" marker so the operator notices and can investigate
# the corresponding agent run.
MIN_BODY_AFTER_SCRUB = 50


def scrub_framework_tags(body):
    """Strip framework-internal tags from body. Returns
    (cleaned_body, [strip_events]). Each event = {kind, len, excerpt}.

    Stripping is unconditional — code-fenced examples that legitimately
    quote a tag will also be stripped. Acceptable trade-off for v1:
    the bot's natural output doesn't write prose about prompt-injection
    tag syntax, so false positives are unlikely. If that changes,
    refine to skip inside ``` fences."""
    strip_events = []
    cleaned = body
    for pattern, kind in FRAMEWORK_TAG_PATTERNS:
        def _record(m, _kind=kind):
            text = m.group(0)
            strip_events.append({
                'kind': _kind,
                'len': len(text),
                'excerpt': text[:120].replace('\n', ' '),
            })
            return ''
        cleaned = pattern.sub(_record, cleaned)
    # Strips often leave triple+ newlines; normalize and trim trailing.
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned).rstrip()
    return cleaned, strip_events


SESSION_GLOB = os.path.expanduser('~/.claude/projects/**/*.jsonl')
SESSION_ROOT = os.path.expanduser('~/.claude/projects')
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


def format_cost(usd):
    """Always 4-decimal USD so cheap calls (<1¢) show non-zero digits.
    Examples: $0.0001, $0.0123, $1.2345, $12.3456."""
    return '${:.4f}'.format(usd)


def format_footer(model, usd):
    return (
        '\n\n---\n'
        '<sub>\U0001f916 aethersdr-agent · cost: '
        + format_cost(usd) + ' · model: ' + model + '</sub>'
    )


def _sum_usage_records(paths, totals, model_seen):
    """Read every line in each path, accumulate usage tokens into totals,
    and return the most-recent model string seen. Shared by the
    per-session and legacy offset readers."""
    for path in paths:
        try:
            with open(path, 'rb') as fh:
                chunk = fh.read()
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
    return model_seen


def read_usage_for_session(session_id):
    """Per-run scoped reader. Sums usage from:
      - the main session JSONL: ~/.claude/projects/*/<session_id>.jsonl
      - its sub-agent JSONLs:   ~/.claude/projects/*/<session_id>/subagents/agent-*.jsonl
    Reads the FULL file each time (no offset tracking): the session JSONL
    is created fresh per `run_claude` invocation and belongs entirely to
    this run, so the whole file is the right delta to attribute. Sibling
    sessions running concurrently are ignored — that's the whole point."""
    totals = {
        'input_tokens': 0,
        'output_tokens': 0,
        'cache_read_input_tokens': 0,
        'cache_creation_input_tokens': 0,
    }
    main_paths = glob.glob(os.path.join(SESSION_ROOT, '*', session_id + '.jsonl'))
    sub_paths  = glob.glob(os.path.join(SESSION_ROOT, '*', session_id,
                                        'subagents', 'agent-*.jsonl'))
    model_seen = _sum_usage_records(main_paths + sub_paths, totals, None)
    return (model_seen or FALLBACK_MODEL), totals


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
    # Sanitizer telemetry: every framework-tag strip recorded here. A
    # row appears only when at least one tag was stripped — quiet on
    # the common case of clean output. `aborted=1` indicates the post
    # body shrank below MIN_BODY_AFTER_SCRUB and was replaced with a
    # blocked-marker before sending.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bot_post_sanitize (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT    NOT NULL,
            target        TEXT    NOT NULL,
            kind          TEXT    NOT NULL,
            strip_count   INTEGER NOT NULL,
            original_len  INTEGER NOT NULL,
            final_len     INTEGER NOT NULL,
            kinds         TEXT    NOT NULL,
            excerpts      TEXT    NOT NULL,
            aborted       INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bps_ts     ON bot_post_sanitize(timestamp_utc)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bps_target ON bot_post_sanitize(target)")
    conn.commit()


def log_sanitize_audit(target, kind, strip_events, original_len, final_len, aborted):
    """Record a sanitize event. Called only when strip_events is non-empty.
    Best-effort — failures here must never block the post."""
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        _ensure_schema(conn)
        conn.execute("""
            INSERT INTO bot_post_sanitize (
                timestamp_utc, target, kind, strip_count,
                original_len, final_len, kinds, excerpts, aborted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, target, kind, len(strip_events),
              original_len, final_len,
              ','.join(e['kind'] for e in strip_events),
              '\n---\n'.join(e['excerpt'] for e in strip_events),
              1 if aborted else 0))
        conn.commit()
    finally:
        conn.close()


def log_audit(model, totals, usd, kind, target, run_id):
    # The schema still has a `public_band` column (legacy from when this
    # script published coarse bands publicly). We populate it with the
    # precise cost string for backward-compat with anything reading the
    # column; it's no longer a "band" but isn't worth a migration.
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
              usd, format_cost(usd), run_id))
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

_ABORT_MARKER = (
    '⚠️ **Automated post blocked by output sanitizer.**\n\n'
    'The bot\'s draft response was {stripped} of {orig} bytes ({pct}%) '
    'framework-internal tags after sanitization — high confidence this '
    'was either a prompt-injection seed in the upstream context, '
    'training-set residue, or a model jailbreak.\n\n'
    'See the `bot_post_sanitize` table in `issue-actions.db` for the '
    'matched content; review the corresponding agent run before '
    'unblocking the path.\n\n'
    '— aethersdr-agent output sanitizer'
)


def cmd_wrap(args):
    if args.body_file:
        with open(args.body_file) as fh:
            body = fh.read()
    elif args.body == '-':
        body = sys.stdin.read()
    else:
        body = args.body or ''

    # Caller can pass --session-id explicitly, or set CLAUDE_SESSION_ID /
    # LAST_CLAUDE_SESSION_ID in env. Env precedence: the orchestrator's
    # run_claude exports LAST_CLAUDE_SESSION_ID before invoking helpers
    # that may post comments.
    session_id = (args.session_id
                  or os.environ.get('CLAUDE_SESSION_ID')
                  or os.environ.get('LAST_CLAUDE_SESSION_ID')
                  or '').strip()

    target = derive_target(args.target, args.endpoint, args.kind)

    # ── Output sanitizer (defense-in-depth) ────────────────────────────────
    # Runs BEFORE cost-footer so a successful injection of the footer
    # itself can't pass through. If the body shrinks under threshold,
    # replace with a clear blocked marker rather than silently dropping
    # the post — operator-visible failure beats silent data loss.
    original_len = len(body)
    body, strip_events = scrub_framework_tags(body)
    final_len = len(body)
    aborted = False
    if strip_events:
        aborted = final_len < MIN_BODY_AFTER_SCRUB
        if aborted:
            stripped = original_len - final_len
            pct = round(stripped * 100 / max(original_len, 1))
            body = _ABORT_MARKER.format(stripped=stripped, orig=original_len, pct=pct)
            final_len = len(body)
        try:
            log_sanitize_audit(target, args.kind, strip_events,
                               original_len, final_len, aborted)
        except sqlite3.Error as e:
            sys.stderr.write('bot-cost: sanitize audit log failed: {}\n'.format(e))
        # Also surface to stderr so the orchestrator log captures it
        # immediately (sqlite is silent). Stripped-but-not-aborted is
        # interesting; aborted is alarming.
        sys.stderr.write(
            'bot-cost: scrubbed {} framework tag(s) from {} post (target={}, '
            'kinds={}, aborted={})\n'.format(
                len(strip_events), args.kind, target,
                ','.join(e['kind'] for e in strip_events), aborted))

    if session_id:
        model, totals = read_usage_for_session(session_id)
    else:
        model, totals = read_usage_since_marker()
    usd = cost_for(model, totals)
    try:
        log_audit(model, totals, usd, args.kind, target,
                  args.run_id or os.environ.get('RUN_ID', ''))
    except sqlite3.Error as e:
        # Never block a post on audit-log failure; surface to stderr.
        sys.stderr.write('bot-cost: audit log failed: {}\n'.format(e))

    # Skip the footer entirely when there's no measurable usage delta
    # (first-ever invocation seeds offsets at EOF and returns zero; some
    # webhook-only short-circuit paths also produce no LLM calls). A
    # "$0.0000" footer on those is misleading — operator reads it as
    # "the model is free" or "the cost-tracker is broken". The audit
    # row is still written above so we have a record that the post
    # happened with zero attributed cost — useful diagnostic.
    if usd <= 0:
        sys.stdout.write(body)
    else:
        sys.stdout.write(body + format_footer(model, usd))


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
    w.add_argument('--session-id', default=None,
                   help='UUID of the claude session to attribute tokens '
                        'to. Reads usage ONLY from this session\'s JSONL '
                        'and its sub-agents, ignoring all other concurrent '
                        'sessions. Falls back to env CLAUDE_SESSION_ID / '
                        'LAST_CLAUDE_SESSION_ID, then to the legacy '
                        'offset-marker reader if neither is set.')
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
