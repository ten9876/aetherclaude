#!/usr/bin/env python3
"""Merge the canonical tool deny list into the agent's Claude settings.

Ring 5 of the dashboard's Defense Posture counts
permissions.deny in /Users/aetherclaude/.claude/settings.json. That file
carried a permissions block with only additionalDirectories, so the ring
read "tool deny list not loaded" — accurately, as far as that file went.
The denials were real but lived only in run-agent.sh's --disallowedTools
flag, which covers the orchestrator and nothing else.

This script lands config/claude/deny-tools.json into the settings file so
the same set applies to every claude invocation on the account.

Deliberately a merge, not a write: settings.json also holds model,
effortLevel, hooks, env, theme, tui and enabledPlugins, all of which are
managed by hand and must survive. Only permissions.deny is touched.

Idempotent — re-running with the list already in place is a no-op and
exits 0 without rewriting the file, so deploy can call it every time.

Usage: sync-claude-settings.py [--settings PATH] [--deny-list PATH] [--dry-run]
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

DEFAULT_SETTINGS = '/Users/aetherclaude/.claude/settings.json'
DEFAULT_DENY_LIST = '/Users/Shared/aetherclaude/config/claude/deny-tools.json'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--settings', default=DEFAULT_SETTINGS)
    ap.add_argument('--deny-list', default=DEFAULT_DENY_LIST)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    with open(args.deny_list) as f:
        desired = json.load(f)['deny']

    try:
        with open(args.settings) as f:
            settings = json.load(f)
    except FileNotFoundError:
        print(f'settings not found: {args.settings}', file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        # Never overwrite a file we could not parse — that would discard
        # hand-managed keys we cannot see.
        print(f'settings is not valid JSON, refusing to touch it: {e}',
              file=sys.stderr)
        return 1

    current = settings.get('permissions', {}).get('deny', [])
    if current == desired:
        print(f'deny list already current ({len(desired)} entries)')
        return 0

    if args.dry_run:
        print(f'would set permissions.deny: {len(current)} -> {len(desired)} entries')
        return 0

    settings.setdefault('permissions', {})['deny'] = desired

    # Preserve owner and mode: the file is aetherclaude:staff 0600 and the
    # agent must keep being able to read it after a root-run deploy.
    st = os.stat(args.settings)
    d = os.path.dirname(args.settings)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.settings-', suffix='.json')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(settings, f, indent=2)
            f.write('\n')
        shutil.copystat(args.settings, tmp)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, args.settings)  # atomic
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    print(f'permissions.deny: {len(current)} -> {len(desired)} entries')
    return 0


if __name__ == '__main__':
    sys.exit(main())
