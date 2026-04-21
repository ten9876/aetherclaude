#!/usr/bin/env python3
"""
One-time migration: seed issue_actions DB from last-poll.json
"""
import json, sqlite3, time, os, sys

STATE_FILE = '/Users/aetherclaude/state/last-poll.json'
DB = '/Users/aetherclaude/data/issue-actions.db'
RUN_ID = 'migration-' + time.strftime('%Y-%m-%dT%H:%M:%S')

os.makedirs(os.path.dirname(DB), exist_ok=True)

state = json.load(open(STATE_FILE))
conn = sqlite3.connect(DB)

# Ensure table exists
conn.executescript("""
CREATE TABLE IF NOT EXISTS issue_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_number INTEGER NOT NULL,
    action       TEXT NOT NULL,
    state        TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    detail       TEXT,
    run_id       TEXT,
    created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
);
CREATE INDEX IF NOT EXISTS idx_ia_issue   ON issue_actions(issue_number);
CREATE INDEX IF NOT EXISTS idx_ia_action  ON issue_actions(action);
CREATE INDEX IF NOT EXISTS idx_ia_state   ON issue_actions(state);
CREATE INDEX IF NOT EXISTS idx_ia_created ON issue_actions(created_at);
""")

inserted = 0
issues_seen = set()

action_map = {
    'done':    ('pr_created',  'done',     'success'),
    'failed':  ('implement',   'failed',   'failure'),
    'declined':('declined',    'declined', 'success'),
    'waiting': ('triage',      'waiting',  'success'),
    'implement':('triage',     'implement','success'),
    'triage':  ('triage',      'triage',   'started'),
}

for key, value in state.items():
    if key.startswith('issue_') and key.endswith('_state') and value in action_map:
        parts = key.split('_')
        if len(parts) < 3:
            continue
        try:
            number = int(parts[1])
        except ValueError:
            continue
        issues_seen.add(number)
        last_action = state.get(f'issue_{number}_last_action', RUN_ID)
        action, state_col, outcome = action_map[value]
        # Skip if already migrated
        existing = conn.execute(
            'SELECT id FROM issue_actions WHERE issue_number=? AND run_id LIKE "migration-%"',
            (number,)
        ).fetchone()
        if not existing:
            conn.execute(
                'INSERT INTO issue_actions (issue_number,action,state,outcome,detail,run_id,created_at) VALUES (?,?,?,?,?,?,?)',
                (number, action, state_col, outcome, 'Migrated from last-poll.json', RUN_ID, last_action)
            )
            inserted += 1
            print(f"  #{number}: {value} -> state={state_col}, action={action}")

# Migrate dup_checked entries
for key, value in state.items():
    if key.startswith('dup_checked_') and value not in ('', 'skip', None):
        try:
            number = int(key.replace('dup_checked_', ''))
        except ValueError:
            continue
        existing = conn.execute(
            'SELECT id FROM issue_actions WHERE issue_number=? AND action="dup_check"',
            (number,)
        ).fetchone()
        if not existing:
            conn.execute(
                'INSERT INTO issue_actions (issue_number,action,state,outcome,detail,run_id,created_at) VALUES (?,?,?,?,?,?,?)',
                (number, 'dup_check', 'N/A', 'success', f'Migrated: checked at {value}', RUN_ID, value)
            )
            inserted += 1
            print(f"  #{number}: dup_check at {value}")

conn.commit()

# Show summary
total = conn.execute('SELECT COUNT(*) FROM issue_actions').fetchone()[0]
conn.close()

print(f"\nMigration complete:")
print(f"  {inserted} records inserted")
print(f"  {len(issues_seen)} issues migrated")
print(f"  {total} total records in DB")
