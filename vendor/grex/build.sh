#!/usr/bin/sh
# grex 1.4.5 build recipe — static-musl binaries checked in as
# vendor/grex/grex-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
set -e
cd "$(dirname "$0")"
SRC="grex-1.4.5"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-grex.sh first" >&2; exit 1; }
# grex's Cargo.toml has no [workspace]; without one it gets pulled into the
# parent oxide2 workspace. Add an empty guard so it builds standalone.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/grex" grex-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/grex" grex-aarch64

strip grex-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" grex-aarch64 2>/dev/null || true
echo "grex: $(ls -la grex-x86_64 grex-aarch64 | awk '{print $NF, $5}')"
