#!/bin/sh
# Panic-free audit: cross-build the audit staticlib and assert no panic
# machinery was synthesized into it. Usage: check.sh [target-triple]
# (defaults to thumbv7m-none-eabi; requires the rustup target and the
# llvm-tools-preview component).
#
# The grep targets `core::panicking` entry points. The crate's own
# `#[panic_handler]` (`rust_begin_unwind`, a lang item) is always emitted
# and is deliberately NOT matched; what must be absent is anything that
# reaches core's panic machinery — its presence means some audited path
# can actually panic.
set -eu

TARGET="${1:-thumbv7m-none-eabi}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
NM="$(rustc --print sysroot)/lib/rustlib/${HOST}/bin/llvm-nm"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
ARCHIVE="${TARGET_DIR}/${TARGET}/release/libpanic_free_audit.a"

if [ ! -x "$NM" ]; then
    echo "error: llvm-nm not found at $NM (install the llvm-tools-preview component)" >&2
    exit 2
fi

cargo build --release -p panic-free-audit --features panic-handler --target "$TARGET"

FOUND="$("$NM" "$ARCHIVE" | grep -E 'core9panicking|panic_fmt|unwrap_failed|expect_failed|panic_bounds_check|slice_(start|end)_index' || true)"
if [ -n "$FOUND" ]; then
    echo "panic machinery found in ${ARCHIVE}:" >&2
    echo "$FOUND" >&2
    exit 1
fi
echo "OK: no panic symbols in ${ARCHIVE}"
