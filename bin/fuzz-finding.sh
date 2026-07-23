#!/opt/homebrew/bin/bash
# Foundry Validator (fuzzing mode) — confirm/refute an Antares Detector finding
# by letting libFuzzer GENERATE inputs against the real code under ASan+UBSan.
#
# Unlike validate-finding.sh (fixed corpus), this seeds libFuzzer with one valid
# input + an ADIF token dictionary and lets it DISCOVER the crashing input on
# its own, then saves the reproducer. A sanitizer trip => CONFIRMED (with the
# reproducing bytes); a clean run within the time budget => UNCONFIRMED.
#
# Apple clang ships no libFuzzer runtime, so this uses Homebrew LLVM clang.
#
# Usage:
#   fuzz-finding.sh --repo <AetherSDR> [--file src/core/AdifParser.cpp]
#                   [--seconds 45] [--out verdict.json]
set -uo pipefail

REPO=""; OUT=""; SECS=45; CWE="CWE-787"
FILE="src/core/AdifParser.cpp"
# Resolve through the deploy symlink farm (/Users/aetherclaude/bin -> Shared).
_src="${BASH_SOURCE[0]:-$0}"
while [ -L "$_src" ]; do _d="$(cd -P "$(dirname "$_src")" && pwd)"; _src="$(readlink "$_src")"; case "$_src" in /*) ;; *) _src="$_d/$_src";; esac; done
SELF_DIR="$(cd -P "$(dirname "$_src")" && pwd)"
HARNESS="$SELF_DIR/../tools/validator/adif_fuzz.cpp"
DICT="$SELF_DIR/../tools/validator/adif.dict"
SEED="$SELF_DIR/../tools/validator/corpus/valid.adi"   # seed only VALID input
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --file) FILE="$2"; shift 2;;
    --seconds) SECS="$2"; shift 2;;
    --cwe) CWE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --harness) HARNESS="$2"; shift 2;;
    --dict) DICT="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$REPO" ] && [ -d "$REPO/src" ] || { echo "need --repo <AetherSDR checkout>" >&2; exit 2; }
[ -f "$HARNESS" ] || { echo "missing harness $HARNESS" >&2; exit 2; }

QT="$(/opt/homebrew/bin/brew --prefix qt 2>/dev/null || echo /opt/homebrew/opt/qt)"
LLVM="$(/opt/homebrew/bin/brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)"
CXX="$LLVM/bin/clang++"
MOC="$QT/share/qt/libexec/moc"; [ -x "$MOC" ] || MOC="$QT/bin/moc"
[ -x "$CXX" ] || { echo "LLVM clang not found at $CXX (brew install llvm)" >&2; exit 3; }
[ -x "$MOC" ] || { echo "moc not found under $QT" >&2; exit 2; }
SDK="$(xcrun --show-sdk-path 2>/dev/null)"

BUILD="$(mktemp -d -t fuzz.XXXXXX)"; ART="$BUILD/artifacts"; CORP="$BUILD/corpus"
mkdir -p "$ART" "$CORP"
trap 'rm -rf "$BUILD"' EXIT
[ -f "$SEED" ] && cp "$SEED" "$CORP/" 2>/dev/null || true

cat > "$BUILD/stubs.cpp" <<'CPP'
#include "core/CtyDatParser.h"
namespace AetherSDR {
QString CtyDatParser::resolvePrimaryPrefix(const QString&) const { return {}; }
}
CPP

"$MOC" -I"$REPO/src" "$REPO/src/core/AdifParser.h" -o "$BUILD/moc_AdifParser.cpp" 2>"$BUILD/moc.err" \
  || { echo "moc failed:"; cat "$BUILD/moc.err"; exit 3; }

SAN="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g"
INC="-I$REPO/src -F$QT/lib -I$QT/lib/QtCore.framework/Headers"
[ -n "$SDK" ] && INC="$INC -isysroot $SDK"
BIN="$BUILD/fuzz_bin"

echo "== building libFuzzer target ($FILE) under fuzzer+ASan+UBSan =="
if ! "$CXX" -std=c++20 -stdlib=libc++ $SAN $INC \
      "$REPO/$FILE" "$BUILD/moc_AdifParser.cpp" "$BUILD/stubs.cpp" "$HARNESS" \
      -F"$QT/lib" -framework QtCore -o "$BIN" 2>"$BUILD/build.err"; then
  echo "BUILD FAILED:"; tail -30 "$BUILD/build.err"; exit 3
fi
echo "  built: $BIN"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
DICT_ARG=""; [ -f "$DICT" ] && DICT_ARG="-dict=$DICT"

echo "== fuzzing for ${SECS}s (seed: valid ADIF only; fuzzer must discover the bug) =="
run_log="$BUILD/fuzz.log"
"$BIN" -max_total_time="$SECS" -timeout=10 -rss_limit_mb=4096 -print_final_stats=1 \
       -artifact_prefix="$ART/" $DICT_ARG "$CORP" >"$run_log" 2>&1
code=$?

# Adjudicate: a crash artifact (or a sanitizer report in the log) => CONFIRMED.
crash="$(ls "$ART"/crash-* "$ART"/oom-* "$ART"/timeout-* 2>/dev/null | head -1)"
trip="$(grep -hE 'runtime error:|ERROR: AddressSanitizer|SUMMARY: (Address|Undefined)' "$run_log" | head -1 | sed 's/^[[:space:]]*//')"
execs="$(grep -oE 'stat::number_of_executed_units: [0-9]+' "$run_log" | grep -oE '[0-9]+' | tail -1)"

if [ -n "$crash" ] || [ -n "$trip" ]; then
  overall="CONFIRMED"
  repro_hex="$( [ -n "$crash" ] && head -c 80 "$crash" | xxd -p | tr -d '\n' )"
  repro_txt="$( [ -n "$crash" ] && head -c 80 "$crash" | tr -c '[:print:]' '.' )"
  echo ""
  echo "== VERDICT: CONFIRMED  ($CWE @ $FILE) after ~${execs:-?} execs =="
  echo "   trip:   ${trip:-<deadly signal>}"
  echo "   repro:  ${repro_txt:-n/a}"
else
  overall="UNCONFIRMED"
  echo ""
  echo "== VERDICT: UNCONFIRMED  ($CWE @ $FILE) — no crash in ${SECS}s / ${execs:-?} execs =="
fi

esc(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n' | cut -c1-300; }
payload="{\"file\":\"$FILE\",\"cwe\":\"$CWE\",\"mode\":\"libfuzzer\",\"verdict\":\"$overall\",\"execs\":\"${execs:-}\",\"detail\":\"$(esc "${trip:-}")\",\"repro_hex\":\"${repro_hex:-}\"}"
[ -n "$OUT" ] && printf '%s\n' "$payload" > "$OUT"
printf '%s\n' "$payload"
[ "$overall" = "CONFIRMED" ] && exit 1 || exit 0
