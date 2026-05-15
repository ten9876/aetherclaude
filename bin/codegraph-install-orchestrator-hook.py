#!/usr/bin/env python3
"""
Install the codegraph blast-radius PreToolUse hook + MCP server into
the orchestrator's Claude config. Idempotent; safe to re-run.

Touches two files (with timestamped backups in /tmp):
  /Users/aetherclaude/.claude/settings.json
    + Adds a PreToolUse hook for Edit|Write|MultiEdit|NotebookEdit
      that runs codegraph-blast-radius-hook.py before any code edit.
      The existing DefenseClaw observability hook stays in place.

  /Users/aetherclaude/.claude/mcp-servers.json
    + Adds a "codegraph" MCP server entry so Claude can also call
      the impact/get_neighbors/search_symbols tools directly.

Run as root (or via `sudo -u aetherclaude`) so the writes land with
correct ownership. The hook + server scripts must already exist at
/Users/Shared/aetherclaude/bin/.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time

SETTINGS_PATH = '/Users/aetherclaude/.claude/settings.json'
MCP_PATH = '/Users/aetherclaude/.claude/mcp-servers.json'
HOOK_CMD = '/Users/Shared/aetherclaude/bin/codegraph-blast-radius-hook.py'
MCP_CMD = '/Users/Shared/aetherclaude/bin/codegraph-mcp.py'

PRE_TOOL_HOOK_ENTRY = {
    'matcher': 'Edit|Write|MultiEdit|NotebookEdit',
    'hooks': [
        {
            'type': 'command',
            'command': HOOK_CMD,
            'timeout': 15000,
        }
    ],
}

MCP_SERVER_ENTRY = {
    'command': MCP_CMD,
    # codegraph-mcp.py uses /usr/bin/env python3 in shebang; no args needed.
}


def backup(path: str) -> str:
    """Snapshot a config file before mutating it. The orchestrator
    relies on these JSONs; a botched merge would brick the next run."""
    ts = time.strftime('%Y%m%dT%H%M%S')
    bak = f'/tmp/{os.path.basename(path)}.bak-{ts}'
    shutil.copy2(path, bak)
    return bak


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def save_json(path: str, data: dict) -> None:
    """Write JSON atomically (tmp + rename) so a crash mid-write
    doesn't leave a half-formed config that breaks the orchestrator."""
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    os.replace(tmp, path)


def add_pretool_hook(settings: dict) -> bool:
    """Returns True if a change was made, False if the hook was
    already installed."""
    hooks = settings.setdefault('hooks', {})
    pre = hooks.setdefault('PreToolUse', [])
    # Already installed?
    for entry in pre:
        for h in entry.get('hooks', []):
            if h.get('command') == HOOK_CMD:
                return False
    pre.append(PRE_TOOL_HOOK_ENTRY)
    return True


def add_mcp_server(mcp: dict) -> bool:
    servers = mcp.setdefault('mcpServers', {})
    if servers.get('codegraph', {}).get('command') == MCP_CMD:
        return False
    servers['codegraph'] = MCP_SERVER_ENTRY
    return True


def install_settings() -> None:
    if not os.path.exists(SETTINGS_PATH):
        print(f'ERROR: {SETTINGS_PATH} does not exist', file=sys.stderr)
        sys.exit(2)
    bak = backup(SETTINGS_PATH)
    settings = load_json(SETTINGS_PATH)
    changed = add_pretool_hook(settings)
    if not changed:
        print(f'[settings] blast-radius hook already installed (no-op)')
        os.remove(bak)
        return
    save_json(SETTINGS_PATH, settings)
    print(f'[settings] added PreToolUse hook → {HOOK_CMD}')
    print(f'[settings] backup: {bak}')


def install_mcp() -> None:
    if not os.path.exists(MCP_PATH):
        # Create a minimal one if missing, but warn — the orchestrator
        # likely expects this file to exist with at least the github MCP.
        print(f'WARNING: {MCP_PATH} did not exist; creating fresh',
              file=sys.stderr)
        save_json(MCP_PATH, {'mcpServers': {}})
    bak = backup(MCP_PATH)
    mcp = load_json(MCP_PATH)
    changed = add_mcp_server(mcp)
    if not changed:
        print(f'[mcp] codegraph server already registered (no-op)')
        os.remove(bak)
        return
    save_json(MCP_PATH, mcp)
    print(f'[mcp] added codegraph MCP server → {MCP_CMD}')
    print(f'[mcp] backup: {bak}')


def main():
    # Sanity check the target scripts exist before mutating config.
    for p in (HOOK_CMD, MCP_CMD):
        if not os.path.exists(p):
            print(f'ERROR: {p} not found — run `git pull` in '
                  '/Users/Shared/aetherclaude first', file=sys.stderr)
            sys.exit(2)
    install_settings()
    install_mcp()
    print('Done. Next orchestrator run will use the blast-radius hook.')


if __name__ == '__main__':
    main()
