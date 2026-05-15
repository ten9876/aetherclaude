#!/usr/bin/env python3
"""
codegraph-watcher — auto-trigger reindex when AetherSDR HEAD moves.

Fires every 60 s via launchd. Compares the codegraph's recorded
src_head_sha to AetherSDR's live HEAD; if they differ AND we haven't
already kicked the refresh for this SHA, runs
`launchctl kickstart system/com.aetherclaude.codegraph-refresh`.

State lives in /Users/Shared/aetherclaude/data/.watcher-state so the
watcher doesn't repeatedly re-kick the same SHA while extraction is
still running (or if the refresh job is unhealthy and never publishes).
The state file records the last SHA we triggered for and a timestamp;
we only re-trigger on a NEW SHA, never on the same one twice.

Designed to be a one-shot: launchd runs it on a 60 s StartInterval
and lets it exit. KeepAlive would loop forever inside a single
process; one-shot keeps the watcher behaviour transparent to
`launchctl list` (you can see when it last ran and what it did).
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time

CODEGRAPH_DB = '/Users/Shared/aetherclaude/data/codegraph.db'
SRC_PATH = '/Users/aetherclaude/workspace/AetherSDR'
STATE_FILE = '/Users/Shared/aetherclaude/data/.watcher-state'
REFRESH_LABEL = 'system/com.aetherclaude.codegraph-refresh'
# Don't re-kick if the refresh job was triggered in the last MIN_INTERVAL
# seconds, even if the SHA has moved again. Extraction takes ~3 min;
# stacking triggers wastes resources.
MIN_INTERVAL = 180


def log(msg: str) -> None:
    """One-line stderr log per run. launchd captures stderr to the
    standard codegraph-refresh log file via StandardErrorPath so the
    watcher's actions show up alongside the extractor's."""
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    print(f'[codegraph-watcher {ts}] {msg}', file=sys.stderr)


def read_state() -> tuple[str, float]:
    """Returns (last_triggered_sha, last_triggered_unix). Missing
    file → ('', 0). Used to suppress repeat-kicks for the same SHA
    and to enforce MIN_INTERVAL backoff."""
    try:
        with open(STATE_FILE) as f:
            line = f.readline().strip()
        if not line:
            return ('', 0.0)
        parts = line.split(None, 1)
        sha = parts[0]
        ts = float(parts[1]) if len(parts) > 1 else 0.0
        return (sha, ts)
    except FileNotFoundError:
        return ('', 0.0)
    except (OSError, ValueError):
        return ('', 0.0)


def write_state(sha: str) -> None:
    try:
        with open(STATE_FILE, 'w') as f:
            f.write(f'{sha} {time.time():.0f}\n')
    except OSError as e:
        log(f'failed to write state: {e}')


def current_head() -> str:
    # Watcher runs as jeremy, repo is owned by aetherclaude — git's
    # dubious-ownership check rejects the read unless we declare the
    # path safe inline. Cleaner than a global git config tweak.
    try:
        out = subprocess.run(
            ['git', '-c', f'safe.directory={SRC_PATH}',
             '-C', SRC_PATH, 'rev-parse', 'HEAD'],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
        log(f'git rev-parse stderr: {out.stderr.strip()[:200]}')
    except Exception as e:
        log(f'git rev-parse failed: {e}')
    return ''


def recorded_head() -> str:
    """Read the src_head_sha from the codegraph metadata. May be empty
    on the first run before extraction has captured it."""
    if not os.path.exists(CODEGRAPH_DB):
        return ''
    try:
        conn = sqlite3.connect(f'file:{CODEGRAPH_DB}?mode=ro', uri=True)
        row = conn.execute(
            'SELECT value FROM metadata WHERE key=?', ('src_head_sha',)
        ).fetchone()
        conn.close()
        return (row[0] or '').strip() if row else ''
    except sqlite3.Error:
        return ''


def kick_refresh() -> int:
    """Trigger the codegraph-refresh launchd job. Uses kickstart
    (not -k) so we don't kill a running extraction. launchd no-ops
    if the job is already in flight."""
    try:
        out = subprocess.run(
            ['launchctl', 'kickstart', REFRESH_LABEL],
            capture_output=True, text=True, timeout=10,
        )
        return out.returncode
    except Exception as e:
        log(f'launchctl kickstart failed: {e}')
        return 1


def main() -> int:
    cur = current_head()
    if not cur:
        log('no live HEAD (git unreachable); skipping')
        return 0
    rec = recorded_head()
    if rec == cur:
        # In sync — silent exit (no log spam).
        return 0
    last_sha, last_ts = read_state()
    # If we already triggered for this SHA, don't re-trigger.
    if last_sha == cur:
        return 0
    # Backoff so a flurry of pushes doesn't queue extractions
    # back-to-back. Extraction takes ~3 min; one trigger per 3-min
    # window is enough.
    age = time.time() - last_ts
    if age < MIN_INTERVAL:
        log(f'AetherSDR HEAD moved ({rec[:8]} -> {cur[:8]}) but last '
            f'trigger was {age:.0f}s ago; backing off')
        return 0
    log(f'AetherSDR HEAD moved {rec[:8] or "(unknown)"} -> {cur[:8]}; '
        f'kicking codegraph-refresh')
    rc = kick_refresh()
    if rc == 0:
        write_state(cur)
    else:
        log(f'launchctl kickstart returned {rc}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
