#!/opt/homebrew/bin/bash
# Foundry Validator (prototype) — turn an Antares Detector finding into ground
# truth by executing the REAL code under AddressSanitizer + UndefinedBehavior-
# Sanitizer against crafted malicious input.
#
#   Detector says:  "src/core/AdifParser.cpp is CWE-787 (out-of-bounds write)"
#   Validator does: build that file + a driver under ASan/UBSan, feed it the
#                   corpus, and report per input:
#                     TRIP      -> a sanitizer fired  (CONFIRMED, with file:line)
#                     CLEAN     -> parsed without a trip (does not reproduce)
#                   plus a control input that MUST stay clean (valid-use check).
#
# This is a prototype wired for the AdifParser finding; the build list
# (--file / --stub) is finding-specific, everything else is reusable. It builds
# locally (Homebrew Qt); the production testbed build belongs in CI/Docker.
#
# Usage:
#   validate-finding.sh --repo <dir> [--cwe CWE-787] [--out verdict.json]
set -uo pipefail

REPO=""; CWE="CWE-787"; OUT=""
FILE="src/core/AdifParser.cpp"          # the Detector-localized file to compile
HARNESS_REL="tools/validator/adif_validate.cpp"
CORPUS_REL="tools/validator/corpus"
CONTROL="valid.adi"                     # must parse cleanly (valid use preserved)
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --cwe) CWE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --file) FILE="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$REPO" ] || { echo "need --repo <AetherSDR checkout>" >&2; exit 2; }
[ -d "$REPO/src" ] || { echo "no src/ under $REPO" >&2; exit 2; }

HARNESS="$REPO/$HARNESS_REL"; CORPUS="$REPO/$CORPUS_REL"
[ -f "$HARNESS" ] || { echo "missing harness $HARNESS" >&2; exit 2; }

QT="$(/opt/homebrew/bin/brew --prefix qt 2>/dev/null || echo /opt/homebrew/opt/qt)"
MOC="$QT/share/qt/libexec/moc"; [ -x "$MOC" ] || MOC="$QT/bin/moc"
[ -x "$MOC" ] || { echo "moc not found under $QT" >&2; exit 2; }
CXX="${CXX:-/usr/bin/clang++}"

BUILD="$(mktemp -d -t validator.XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT

# One-symbol stub for the null-guarded DXCC branch so we link JUST AdifParser
# (CtyDatParser is a plain class; the method is never called at runtime).
cat > "$BUILD/stubs.cpp" <<'CPP'
#include "core/CtyDatParser.h"
namespace AetherSDR {
QString CtyDatParser::resolvePrimaryPrefix(const QString&) const { return {}; }
}
CPP

# AdifParser has Q_OBJECT -> moc the header for its meta-object symbols.
"$MOC" -I"$REPO/src" "$REPO/src/core/AdifParser.h" -o "$BUILD/moc_AdifParser.cpp" 2>"$BUILD/moc.err" \
  || { echo "moc failed:"; cat "$BUILD/moc.err"; exit 3; }

SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
# Homebrew Qt6 on macOS ships frameworks — bare <QString> resolves via the
# framework's Headers dir; linking is -F<libdir> -framework QtCore.
INC="-I$REPO/src -F$QT/lib -I$QT/lib/QtCore.framework/Headers"
FW="-F$QT/lib -framework QtCore"
BIN="$BUILD/validate_bin"

echo "== building $FILE + driver under ASan+UBSan =="
if ! "$CXX" -std=c++20 -g $SAN $INC \
      "$REPO/$FILE" "$BUILD/moc_AdifParser.cpp" "$BUILD/stubs.cpp" "$HARNESS" \
      $FW -o "$BIN" 2>"$BUILD/build.err"; then
  echo "BUILD FAILED:"; tail -30 "$BUILD/build.err"; exit 3
fi
echo "  built: $BIN"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:exitcode=99"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=99"

FILEBASE="$(basename "$FILE")"
confirmed=0; control_ok="unknown"; results=""
echo "== running corpus against the real parser =="
for f in "$CORPUS"/*.adi; do
  name="$(basename "$f")"
  log="$BUILD/run-$name.log"
  "$BIN" "$f" >"$log" 2>&1; code=$?
  trip=""
  if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|SUMMARY: (Address|Undefined)" "$log"; then
    trip="$(grep -hE "runtime error:|SUMMARY:|ERROR: AddressSanitizer" "$log" | head -1 | sed 's/^[[:space:]]*//')"
    hit_here=$(grep -c "$FILEBASE" "$log" 2>/dev/null || echo 0)
  else
    hit_here=0
  fi
  if [ -n "$trip" ]; then
    verdict="TRIP"; [ "$name" != "$CONTROL" ] && confirmed=1
    [ "$name" = "$CONTROL" ] && control_ok="no"
    printf '  [TRIP ] %-18s exit=%s  %s\n' "$name" "$code" "$trip"
  else
    verdict="CLEAN"
    [ "$name" = "$CONTROL" ] && control_ok="yes"
    printf '  [clean] %-18s exit=%s  %s\n' "$name" "$code" "$(grep -h harness "$log" | head -1)"
  fi
  results="${results}${results:+,}{\"input\":\"$name\",\"verdict\":\"$verdict\",\"exit\":$code,\"in_localized_file\":$([ "${hit_here:-0}" -gt 0 ] && echo true || echo false),\"detail\":\"$(printf '%s' "${trip:-}" | sed 's/"/\\"/g' | cut -c1-200)\"}"
done

if [ "$confirmed" -eq 1 ]; then
  overall="CONFIRMED"
else
  overall="UNCONFIRMED"
fi
echo ""
echo "== VERDICT: $overall  ($CWE @ $FILE) · valid-use control: $control_ok =="

payload="{\"file\":\"$FILE\",\"cwe\":\"$CWE\",\"verdict\":\"$overall\",\"control_clean\":\"$control_ok\",\"results\":[$results]}"
[ -n "$OUT" ] && printf '%s\n' "$payload" > "$OUT"
printf '%s\n' "$payload"
[ "$overall" = "CONFIRMED" ] && exit 1 || exit 0
