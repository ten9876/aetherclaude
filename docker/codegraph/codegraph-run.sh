#!/bin/bash
# Codegraph nightly entrypoint. Runs inside the aetherclaude-codegraph
# container.
#
# Expected bind mounts:
#   /src     — AetherSDR source tree (e.g. /Users/aetherclaude/workspace/AetherSDR)
#   /tools   — aetherclaude bin/ dir with codegraph-extract-clangd.py & analyzer
#   /out     — host data dir; final codegraph.db is written here
#
# Steps:
#   1. cmake -B /tmp/build with CMAKE_EXPORT_COMPILE_COMMANDS=ON.
#      The build dir is *inside* the container so we never write to
#      the host source tree.
#   2. Run the clangd extractor → /tmp/codegraph.db
#   3. Run the analyzer (Louvain communities) on that db
#   4. Atomically move it into /out so the dashboard's lazy reload
#      never sees a half-written file.

set -euo pipefail

SRC=/src
TOOLS=/tools
OUT=/out
BUILD=/tmp/build
# Build the new db inside /out (a bind-mounted host directory) so the
# final rename is intra-filesystem and atomic. Writing in /tmp first
# and mv'ing across breaks on cross-fs renames AND can fail on the
# existing target's permissions.
TMP_DB=$OUT/codegraph.db.new

t0=$(date +%s)
echo "[codegraph-run] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Step 1: cmake configure (cheap — ~0.5s). We use Ninja because the
# CI image has it and it skips a few cmake gotchas around ExternalProject
# downloads. We do NOT --build; we only need compile_commands.json.
echo "[codegraph-run] cmake configure"
cmake -B "$BUILD" -S "$SRC" \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      > /tmp/cmake.log 2>&1 || {
        echo "[codegraph-run] cmake failed — see /tmp/cmake.log"
        tail -40 /tmp/cmake.log
        exit 1
      }

if [[ ! -f "$BUILD/compile_commands.json" ]]; then
    echo "[codegraph-run] no compile_commands.json produced"
    exit 1
fi
echo "[codegraph-run] ccdb size: $(wc -l < "$BUILD/compile_commands.json") lines"

# Step 2: extract. Use all available cores; the host (Mac Mini M4)
# has 10 perf cores, and libclang parse is mostly CPU-bound.
JOBS=$(nproc)
echo "[codegraph-run] extract (jobs=$JOBS)"
python3 "$TOOLS/codegraph-extract-clangd.py" \
        "$SRC/src" \
        "$TMP_DB" \
        "$BUILD/compile_commands.json" \
        -j "$JOBS" \
        -v

# Step 3: analyze (Louvain communities).
echo "[codegraph-run] analyze"
python3 "$TOOLS/codegraph-analyze.py" "$TMP_DB"

# Step 4: atomic publish. mv within $OUT is intra-filesystem and atomic;
# the dashboard's per-request sqlite3.connect() picks up the new file
# on the next read. Also clean up the WAL/SHM sidecars that sqlite may
# have left next to the new db (we wrote with WAL journal_mode).
mv -f "$TMP_DB" "$OUT/codegraph.db"
for sidecar in "$TMP_DB-wal" "$TMP_DB-shm"; do
    [[ -f "$sidecar" ]] && rm -f "$sidecar"
done
# Group-writable so the doc-extraction pass (which runs as
# aetherclaude on the host, not jeremy who owns the file) can update
# concept + INFERRED-edge rows without permissions errors.
chmod g+w "$OUT/codegraph.db" || true
echo "[codegraph-run] published $OUT/codegraph.db ($(stat -c%s "$OUT/codegraph.db") bytes)"

t1=$(date +%s)
echo "[codegraph-run] done in $((t1 - t0))s"
