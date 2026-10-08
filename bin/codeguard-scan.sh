#!/opt/homebrew/bin/bash
# Shared Cisco DefenseClaw CodeGuard scanner.
#
# Scans the files changed vs `main` in <scan_root> with CodeGuard, records the
# findings to the events DB (tagged by SOURCE/REF) + codeguard-latest.json (for
# the dashboard), and prints the aggregated findings as JSON to stdout:
#     {"findings":[ {id,severity,title,description,location,remediation,file}, ... ],
#      "errors":[ {file,error}, ... ]}
# A file the scanner could not scan (non-zero exit, or output that is not a
# findings object) is listed under "errors", never counted as clean.
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
# `defenseclaw-gateway scan code` runs against the real ~/.defenseclaw: since
# 0.8.5 it requires the v8 config there and refuses an empty isolated HOME.
CODEGUARD="/Users/aetherclaude/.local/bin/defenseclaw-gateway"

emit_empty() { echo '{"findings":[],"errors":[]}'; exit 0; }

[ -x "$CODEGUARD" ] || { jq -cn --arg e "scanner not installed: $CODEGUARD" '{findings:[], errors:[{file:"", error:$e}]}'; exit 0; }
[ -d "$SCAN_ROOT" ] || emit_empty

CHANGED=$(git -C "$SCAN_ROOT" diff --name-only main 2>/dev/null || true)
[ -n "$CHANGED" ] || emit_empty

ACC=$(mktemp -t codeguard-acc.XXXXXX)
ERRS=$(mktemp -t codeguard-errs.XXXXXX)
CG_ERR=$(mktemp -t codeguard-stderr.XXXXXX)
echo '[]' > "$ACC"
trap 'rm -f "$ACC" "$ERRS" "$CG_ERR"' EXIT

for file in $CHANGED; do
    [ -f "$SCAN_ROOT/$file" ] || continue
    case "$file" in
        *.cpp|*.h|*.c|*.py|*.js|*.ts|*.go|*.java|*.rb|*.php|*.sh|*.yaml|*.yml|*.json|*.xml|*.rs) ;;
        *) continue ;;
    esac

    RES=$("$CODEGUARD" scan code "$SCAN_ROOT/$file" --json 2>"$CG_ERR")
    rc=$?
    if [ "$rc" -ne 0 ] || ! printf '%s' "$RES" | jq -e 'type == "object" and has("findings")' >/dev/null 2>&1; then
        msg=$( { head -c 300 "$CG_ERR"; printf '%s' "$RES" | head -c 300; } | tr '\n' ' ')
        jq -cn --arg f "$file" --arg e "exit ${rc}: ${msg}" '{file:$f, error:$e}' >> "$ERRS"
        continue
    fi

    # Record findings (tagged) + accumulate them for the caller.
    echo "$RES" | SCAN_ROOT="$SCAN_ROOT" SCAN_FILE="$file" CG_SOURCE="$SOURCE" CG_REF="$REF" \
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

# Since 0.8.5 the scan JSON redacts description/location/remediation. Rebuild
# the first two from the scanned file and line_number (the pre-0.8.5 shapes:
# the matched source line, and path:line). Remediation is a fixed string per
# rule, mirrored here from internal/scanner/codeguard.go in DefenseClaw 0.8.10.
REMEDIATION = {
    "CG-CRED-001": "Move credentials to environment variables or a secrets manager",
    "CG-CRED-002": "Rotate the key and store in AWS Secrets Manager or environment variables",
    "CG-CRED-003": "Remove the private key from source code; use a certificate store or secrets manager",
    "CG-EXEC-001": "Use parameterized execution or an allowlist of commands",
    "CG-EXEC-002": "Avoid shell=True; pass arguments as a list",
    "CG-NET-001": "Validate and allowlist outbound URLs",
    "CG-DESER-001": "Use yaml.safe_load or json for deserialization; never unpickle untrusted data",
    "CG-SQL-001": "Use parameterized queries with bind variables",
    "CG-CRYPTO-001": "Use SHA-256 or stronger; see codeguard-0-additional-cryptography",
    "CG-PATH-001": "Canonicalize paths and validate against an allowed root directory",
}
def _redacted(v):
    return isinstance(v, str) and v.startswith("<redacted")
try:
    with open(os.path.join(os.environ.get("SCAN_ROOT", "."), scan_file), errors="replace") as fh:
        src_lines = fh.read().splitlines()
except Exception:
    src_lines = []
for f in findings:
    line = f.get("line_number")
    path = os.path.join(os.environ.get("SCAN_ROOT", "."), scan_file)
    if _redacted(f.get("location")) and isinstance(line, int):
        f["location"] = f"{path}:{line}"
    if _redacted(f.get("description")) and isinstance(line, int) and 0 < line <= len(src_lines):
        f["description"] = src_lines[line - 1].strip()
    if _redacted(f.get("remediation")) and f.get("id") in REMEDIATION:
        f["remediation"] = REMEDIATION[f["id"]]

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
ACC="$ACC" ERRS="$ERRS" python3 -c '
import json, os
try:
    with open(os.environ["ACC"]) as fh:
        acc = json.load(fh)
except Exception:
    acc = []
try:
    with open(os.environ["ERRS"]) as fh:
        errors = [json.loads(l) for l in fh if l.strip()]
except Exception:
    errors = [{"file": "", "error": "could not read scanner errors"}]
print(json.dumps({"findings": acc, "errors": errors}))
' 2>/dev/null || echo '{"findings":[],"errors":[{"file":"","error":"could not aggregate scanner output"}]}'
exit 0
