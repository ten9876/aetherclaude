# Codegraph extractor image — derived from the AetherSDR CI image,
# adds clang/libclang/python-clang so codegraph-extract-clangd.py can
# run libclang against AetherSDR's compile_commands.json.
#
# The base image already has every dev header AetherSDR's CMakeLists
# can find_package(), which is exactly what libclang's TU parser needs
# to resolve includes. Adding clang lets us parse those TUs without
# pulling LLVM's full toolchain ourselves.
#
# Build (locally on the Mac Mini):
#   docker build -t aetherclaude-codegraph:latest \
#                /Users/Shared/aetherclaude/docker/codegraph
#
# Run:
#   docker run --rm \
#     -v /Users/aetherclaude/workspace/AetherSDR:/src:ro \
#     -v /Users/Shared/aetherclaude/bin:/tools:ro \
#     -v /Users/aetherclaude/data:/out \
#     aetherclaude-codegraph:latest \
#     /codegraph-run.sh
#
# A wrapper /codegraph-run.sh is provided so the launchd plist stays
# a one-liner — it cmake-configures the build dir, runs the extractor,
# and runs the analyzer.

FROM ghcr.io/ten9876/aethersdr-ci:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    python3-clang \
    python3-networkx \
    python3-louvain \
    && rm -rf /var/lib/apt/lists/*

# The extractor uses /usr/lib/llvm-*/lib/libclang.so on Ubuntu, but
# distros vary in the symlink name. python3-clang's cindex.py will
# search common locations — we add a symlink at the bare path the
# extractor's _LIBCLANG_CANDIDATES list checks first, so it finds
# libclang without distro-specific probing.
RUN ln -sf $(find /usr/lib -name 'libclang.so*' | sort | tail -1) /usr/lib/libclang.so || true

COPY codegraph-run.sh /codegraph-run.sh
RUN chmod +x /codegraph-run.sh

ENTRYPOINT ["/bin/bash"]
