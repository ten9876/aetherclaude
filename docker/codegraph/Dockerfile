# Codegraph extractor image — self-contained Ubuntu 24.04 with the
# dev headers AetherSDR uses + clang/libclang/python-clang.
#
# We use Ubuntu directly (not the ghcr.io aethersdr-ci base) because
# that base is published as amd64-only — on the Mac Mini M4 it would
# run under qemu emulation at ~10x slowdown (~45 min full extraction
# vs ~3 min native). Ubuntu's multi-arch manifest pulls arm64 natively
# on Apple Silicon.
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

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# AetherSDR dev headers (mirrors .github/docker/Dockerfile in the
# AetherSDR repo) + clang/libclang/python-clang for the extractor.
# Kept as a single layer so the docker build cache stays compact.
RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    pkg-config \
    g++ \
    git \
    patch \
    curl \
    make \
    python3 \
    qt6-base-dev \
    qt6-multimedia-dev \
    qt6-websockets-dev \
    qt6-serialport-dev \
    qt6-base-private-dev \
    qt6-shader-baker \
    qt6-shadertools-dev \
    libgl1-mesa-dev \
    libasound2-dev \
    libfftw3-dev \
    libhidapi-dev \
    qtkeychain-qt6-dev \
    portaudio19-dev \
    libpipewire-0.3-dev \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    libmosquitto-dev \
    ca-certificates \
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
