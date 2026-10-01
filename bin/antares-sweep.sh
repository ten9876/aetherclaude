#!/opt/homebrew/bin/bash
# Antares full-repo sweep — run the Detector across a CWE list, N passes each,
# union the candidates (with a confidence tally), optionally fuzz-validate the
# ones that have a harness, and write a report.
#
# Runs SERIAL by default: the M4's single GPU is the throughput bottleneck, so
# concurrent 1B inferences finish only ~10% faster than serial while reserving
# 4x the KV cache — not worth it for an overnight batch. (ANTARES_SWEEP_CONCURRENCY
# can still raise it.)
#
# The Detector explores the WHOLE repo per run, so the natural sweep unit is a
# CWE category (not a file). Because exploration is stochastic, each CWE is run
# PASSES times and the candidates are unioned — a file flagged by more
# passes/CWEs ranks higher.
#
# Advisory + fail-open: produces a report for review; it never files issues or
# edits code. Runs nightly via com.aetherclaude.antares-sweep (2am PT).
#
# Tunables (env): ANTARES_SWEEP_PASSES (3), ANTARES_SWEEP_CONCURRENCY (4),
#   ANTARES_SWEEP_MAX_COMMANDS (15), ANTARES_SWEEP_VALIDATE (1),
#   ANTARES_SWEEP_FUZZ_SECONDS (40), ANTARES_SWEEP_REPO.
set -uo pipefail

REPO="${ANTARES_SWEEP_REPO:-/Users/aetherclaude/workspace/AetherSDR}"
DETECTOR="/Users/aetherclaude/bin/antares-detector.py"
FUZZER="/Users/aetherclaude/bin/fuzz-finding.sh"
OUTDIR="/Users/aetherclaude/data/antares/sweeps"
LOG="/Users/Shared/aetherclaude/logs/antares-sweep.log"
PASSES="${ANTARES_SWEEP_PASSES:-3}"
CONCURRENCY="${ANTARES_SWEEP_CONCURRENCY:-1}"
MAX_COMMANDS="${ANTARES_SWEEP_MAX_COMMANDS:-15}"
VALIDATE="${ANTARES_SWEEP_VALIDATE:-1}"
FUZZ_SECONDS="${ANTARES_SWEEP_FUZZ_SECONDS:-40}"

log(){ echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') SWEEP: $*" | tee -a "$LOG"; }

# CWE categories relevant to a C++/Qt networking + DSP app, with a short
# generic description used to seed the model.
declare -A DESC=(
  [CWE-787]="Out-of-bounds write"
  [CWE-125]="Out-of-bounds read"
  [CWE-416]="Use after free"
  [CWE-476]="NULL pointer dereference"
  [CWE-415]="Double free"
  [CWE-190]="Integer overflow or wraparound"
  [CWE-191]="Integer underflow"
  [CWE-120]="Buffer copy without checking size of input (classic overflow)"
  [CWE-122]="Heap-based buffer overflow"
  [CWE-131]="Incorrect calculation of buffer size"
  [CWE-824]="Access of uninitialized pointer"
  [CWE-457]="Use of uninitialized variable"
  [CWE-401]="Missing release of memory after effective lifetime (leak)"
  [CWE-362]="Concurrent execution using shared resource (race condition)"
  [CWE-367]="Time-of-check time-of-use (TOCTOU) race"
  [CWE-78]="OS command injection"
  [CWE-134]="Uncontrolled format string"
  [CWE-22]="Improper limitation of a pathname (path traversal)"
  [CWE-319]="Cleartext transmission of sensitive information"
  [CWE-295]="Improper certificate validation"
  [CWE-20]="Improper input validation"
)

# Optional subset (space-separated CWE ids in ANTARES_SWEEP_CWES) — for quick
# runs/tests; unknown ids get a generic description.
if [ -n "${ANTARES_SWEEP_CWES:-}" ]; then
    declare -A _sub=()
    for c in $ANTARES_SWEEP_CWES; do _sub[$c]="${DESC[$c]:-$c vulnerability class}"; done
    unset DESC; declare -A DESC
    for c in "${!_sub[@]}"; do DESC[$c]="${_sub[$c]}"; done
fi

[ -x "$DETECTOR" ] || { log "no detector at $DETECTOR — abort"; exit 0; }
[ -d "$REPO/src" ] || { log "no repo at $REPO — abort"; exit 0; }
curl -sf -o /dev/null --max-time 3 http://127.0.0.1:11434/api/tags 2>/dev/null || {
    log "model server down — abort"; exit 0; }

# Single-instance lock (mkdir is atomic).
LOCKDIR="/tmp/antares-sweep.lock"
mkdir "$LOCKDIR" 2>/dev/null || { log "a sweep is already running — abort"; exit 0; }
WORK="$(mktemp -d -t antares-sweep.XXXXXX)"
trap 'rmdir "$LOCKDIR" 2>/dev/null; rm -rf "$WORK"' EXIT

mkdir -p "$OUTDIR"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"
HEAD="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
REPORT="$OUTDIR/sweep-${TS}.json"

log "start — ${#DESC[@]} CWEs × ${PASSES} pass(es), concurrency ${CONCURRENCY}, HEAD ${HEAD}"
started=$(date +%s)

run_one() {
    local cwe="$1" pass="$2"
    /usr/bin/python3 "$DETECTOR" --repo "$REPO" --cwe "$cwe" \
        --context "Repository-wide sweep for ${cwe}: ${DESC[$cwe]}. Locate source files that contain this vulnerability class." \
        --issue "sweep" --max-commands "$MAX_COMMANDS" \
        > "$WORK/run-${cwe}-p${pass}.json" 2>/dev/null || echo '{}' > "$WORK/run-${cwe}-p${pass}.json"
}

# Bounded-concurrency job pool.
for cwe in "${!DESC[@]}"; do
    for ((p=1; p<=PASSES; p++)); do
        while [ "$(jobs -rp | wc -l)" -ge "$CONCURRENCY" ]; do wait -n 2>/dev/null || break; done
        run_one "$cwe" "$p" &
    done
done
wait
log "detector runs complete ($(( $(date +%s) - started ))s) — aggregating"

# Union candidates across every (cwe × pass) run into a ranked report.
/usr/bin/python3 - "$WORK" "$REPORT" "$TS" "$HEAD" "$PASSES" "${#DESC[@]}" <<'PY'
import json, glob, os, sys
work, report, ts, head, passes, ncwe = sys.argv[1:7]
cand = {}   # file -> {cwes:set, hits:int, rationale:str}
runs = clean = vuln = 0
for path in glob.glob(os.path.join(work, "run-*.json")):
    runs += 1
    try:
        d = json.load(open(path))
    except Exception:
        continue
    if d.get("verdict") == "vulnerable":
        vuln += 1
    elif d.get("verdict") in ("clean", "budget_exhausted", "server_unreachable", "error", "timeout"):
        clean += 1
    cwe = d.get("cwe", "")
    for f in (d.get("candidates") or []):
        f = str(f).strip()
        # keep path-like candidates (files), drop bare symbol names
        if not f or (("/" not in f) and ("." not in f)):
            continue
        e = cand.setdefault(f, {"file": f, "cwes": set(), "hits": 0, "rationale": ""})
        e["cwes"].add(cwe)
        e["hits"] += 1
        if not e["rationale"] and d.get("rationale"):
            e["rationale"] = d["rationale"][:220]
items = sorted(cand.values(), key=lambda e: (e["hits"], len(e["cwes"])), reverse=True)
for e in items:
    e["cwes"] = sorted(x for x in e["cwes"] if x)
out = {"generated_at": ts, "repo_head": head, "passes": int(passes),
       "cwe_count": int(ncwe), "runs": runs, "vulnerable_runs": vuln,
       "candidates": items}
json.dump(out, open(report, "w"), indent=2)
print("%d unique candidate file(s) from %d runs" % (len(items), runs))
PY

# Fuzz-validate candidates that have a registered harness (advisory).
if [ "$VALIDATE" = "1" ] && [ -x "$FUZZER" ]; then
    # Canonical live-clone tools dir (bin is a symlink farm into /Users/Shared).
    tools="/Users/Shared/aetherclaude/tools/validator"; [ -d "$tools" ] || tools=""
    llvm="$(/opt/homebrew/bin/brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)"
    if [ -n "$tools" ] && [ -x "$llvm/bin/clang++" ]; then
        # unique candidate files with a harness
        while IFS= read -r f; do
            case "$f" in
                *AdifParser*)
                    log "validating ${f} (fuzz ${FUZZ_SECONDS}s)"
                    vout="$WORK/validate.json"
                    "$FUZZER" --repo "$REPO" --file "src/core/AdifParser.cpp" \
                        --harness "$tools/adif_fuzz.cpp" --dict "$tools/adif.dict" \
                        --seed "$tools/corpus/valid.adi" --seconds "$FUZZ_SECONDS" \
                        --out "$vout" >/dev/null 2>&1 || true
                    v="$(jq -r '.verdict // "error"' "$vout" 2>/dev/null || echo error)"
                    # annotate the report entry
                    jq --arg f "$f" --arg v "$v" \
                       '(.candidates[] | select(.file|test("AdifParser"))) += {validation:$v}' \
                       "$REPORT" > "$REPORT.tmp" 2>/dev/null && mv "$REPORT.tmp" "$REPORT"
                    log "  ${f} -> ${v}" ;;
            esac
        done < <(jq -r '.candidates[].file' "$REPORT" 2>/dev/null | sort -u)
    else
        log "validation skipped — no LLVM/tools"
    fi
fi

cp "$REPORT" "$OUTDIR/latest.json" 2>/dev/null || true
top=$(jq -r '.candidates[:8][] | "  \(.hits)× \(.cwes|join(",")) — \(.file)\(if .validation then " ["+.validation+"]" else "" end)"' "$REPORT" 2>/dev/null)
log "done in $(( $(date +%s) - started ))s — report: $REPORT"
log "top candidates:"
printf '%s\n' "$top" | tee -a "$LOG"
