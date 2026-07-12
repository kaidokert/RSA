# Dev image for iterating on ct-ctgrind locally.
#
# Build once (the native arm64 build matches the aarch64 CI row; add
# --platform linux/amd64 for the x86_64 leg — note that row also sets
# RUSTFLAGS="-C target-feature=+lzcnt,+bmi1", which SIGILLs inside
# Valgrind under emulation, so an emulated amd64 run only covers the
# baseline ISA):
#   docker build -t ct-ctgrind-dev -f ct-verify/ct-ctgrind/Dockerfile .
#
# Then run from the repo root (`ct-ctgrind` is a member of the nested
# `ct-verify` workspace, so build from there and use the workspace's
# absolute target path):
#   docker run --rm -v "$PWD:/work" -w /work/ct-verify \
#       -e CARGO_TARGET_DIR=/work/target/docker \
#       ct-ctgrind-dev \
#       bash -c "cargo build --release -p ct-ctgrind && \
#                valgrind --tool=memcheck --error-limit=no --error-exitcode=0 \
#                  --suppressions=ct-ctgrind/ct-ctgrind.supp -q \
#                  /work/target/docker/release/ct-ctgrind"
#
# Matches the CI image (ubuntu-latest = 24.04) so Valgrind versions and
# crabgrind's C header dependencies line up.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential curl valgrind ca-certificates pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain 1.87 --profile minimal --no-modify-path && \
    rustup --version && cargo --version

WORKDIR /work
