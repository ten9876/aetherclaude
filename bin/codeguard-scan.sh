#!/opt/homebrew/bin/bash
# Shared Cisco DefenseClaw CodeGuard scanner.
#
# Scans the files changed vs `main` in <scan_root> with CodeGuard, records the
# findings to the events DB (tagged by SOURCE/REF) + codeguard-latest.json (for
# the dashboard), and prints the aggregated findings as JSON to stdout:
#     {"findings":[ {id,severity,title,description,location,remediation,file}, ... ]}
#
# ADVISORY: always exits 0 — the caller decides whether to block. Both the
# Validation Gate (validate-diff.sh, SOURCE=agent) and PR review
# (run-agent.sh review_single_pr, SOURCE=pr) call this so there is exactly one
# CodeGuard implementation.
#
# Usage: codeguard-scan.sh <scan_root> <source> <ref>
#   scan_root — a checkout; files changed vs main are the scan set
#   source    — "agent" | "pr" (tags the finding rows)
#   ref       — issue/PR number for attribution (may be empty)
set -uo pipefail

SCAN_ROOT="${1:-.}"
SOURCE="${2:-agent}"
REF="${3:-}"

EVENTS_DB="/Users/aetherclaude/data/events.db"
LATEST_JSON="/Users/aetherclaude/logs/codeguard-latest.json"
# `defenseclaw-gateway scan code` is a standalone CLI that opens its own audit
# store; with the supervised daemon holding ~/.defenseclaw/audit.db in WAL mode
# it fails SQLITE_CANTOPEN, so each scan gets an isolated HOME.
CODEGUARD="/Users/aetherclaude/.local/bin/defenseclaw-gateway"

emit_empty() { echo '{"findings":[]}'; exit 0; }

[ -x "$CODEGUARD" ] || emit_empty
[ -d "$SCAN_ROOT" ] || emit_empty

CHANGED=$(git -C "$SCAN_ROOT" diff --name-only main 2>/dev/null || true)
[ -n "$CHANGED" ] || emit_empty

CGHOME=$(mktemp -d -t codeguard-scan.XXXXXX)
mkdir -p "$CGHOME/.defenseclaw"
ACC=$(mktemp -t codeguard-acc.XXXXXX)
echo '[]' > "$ACC"
trap 'rm -rf "$CGHOME" "$ACC"' EXIT

for file in $CHANGED; do
    [ -f "$SCAN_ROOT/$file" ] || continue
    case "$file" in
        *.cpp|*.h|*.c|*.py|*.js|*.ts|*.go|*.java|*.rb|*.php|*.sh|*.yaml|*.yml|*.json|*.xml|*.rs) ;;
        *) continue ;;
    esac

    RES=$(env HOME="$CGHOME" "$CODEGUARD" scan code "$SCAN_ROOT/$file" --json 2>/dev/null || echo '{"findings":[]}')

    # Record findings (tagged) + accumulate them for the caller.
    echo "$RES" | SCAN_FILE="$file" CG_SOURCE="$SOURCE" CG_REF="$REF" \
        EVENTS_DB="$EVENTS_DB" LATEST_JSON="$LATEST_JSON" ACC="$ACC" python3 -c '
import sys, json, sqlite3, os
try:
    d = json.loads(sys.stdin.read() or "{}")
except Exception:
    d = {}
findings = d.get("findings", []) or []
if not findings:
    sys.exit(0)
scan_file = os.environ.get("SCAN_FILE", "")
source = os.environ.get("CG_SOURCE", "agent")
ref = os.environ.get("CG_REF", "")
for f in findings:
    f["file"] = scan_file

# accumulate for stdout aggregation
acc_path = os.environ["ACC"]
try:
    with open(acc_path) as fh:
        acc = json.load(fh)
except Exception:
    acc = []
acc.extend(findings)
with open(acc_path, "w") as fh:
    json.dump(acc, fh)

# codeguard-latest.json (dashboard back-compat) tracks the agent validation-
# gate scan only; PR scans go to the tagged table, not here.
if source == "agent":
    try:
        lj = os.environ["LATEST_JSON"]
        try:
            with open(lj) as fh:
                existing = json.load(fh)
        except Exception:
            existing = []
        existing.extend(findings)
        with open(lj, "w") as fh:
            json.dump(existing, fh)
    except Exception:
        pass

# SQLite (with source/ref columns; migrate older DBs in place)
try:
    db = sqlite3.connect(os.environ["EVENTS_DB"], timeout=10)
    db.execute("""CREATE TABLE IF NOT EXISTS codeguard_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT, rule_id TEXT, severity TEXT,
        title TEXT, description TEXT, location TEXT, remediation TEXT,
        source TEXT DEFAULT "agent", ref TEXT)""")
    cols = {r[1] for r in db.execute("PRAGMA table_info(codeguard_findings)")}
    if "source" not in cols:
        db.execute("ALTER TABLE codeguard_findings ADD COLUMN source TEXT DEFAULT \"agent\"")
    if "ref" not in cols:
        db.execute("ALTER TABLE codeguard_findings ADD COLUMN ref TEXT")
    for f in findings:
        db.execute(
            "INSERT INTO codeguard_findings (file_path, rule_id, severity, title, description, location, remediation, source, ref) VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_file, f.get("id",""), f.get("severity",""), f.get("title",""),
             f.get("description",""), f.get("location",""), f.get("remediation",""),
             source, ref))
    db.commit(); db.close()
except Exception:
    pass
'
done

# Emit the aggregated findings for the caller (block decision / comment / feed).
ACC="$ACC" python3 -c '
import json, os
try:
    with open(os.environ["ACC"]) as fh:
        acc = json.load(fh)
except Exception:
    acc = []
print(json.dumps({"findings": acc}))
' 2>/dev/null || echo '{"findings":[]}'
exit 0
