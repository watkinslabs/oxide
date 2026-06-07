#!/usr/bin/sh
# tealdeer 1.7.1 build recipe — static-musl binaries checked in as
# vendor/tealdeer/tldr-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc. The cargo bin is named tldr.
set -e
cd "$(dirname "$0")"
SRC="tealdeer-1.7.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-tealdeer.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# Isolate from oxide2's root [workspace]: tealdeer's own Cargo.toml has no
# [workspace] table, so cargo walks up and adopts the kernel workspace.
# Append an empty one to pin tealdeer as its own standalone package. Idempotent.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/tldr" tldr-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/tldr" tldr-aarch64

strip tldr-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" tldr-aarch64 2>/dev/null || true
echo "tealdeer: $(ls -la tldr-x86_64 tldr-aarch64 | awk '{print $NF, $5}')"
