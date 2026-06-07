#!/usr/bin/sh
# hyperfine 1.19.0 build recipe — static-musl binaries checked in as
# vendor/hyperfine/hyperfine-{x86_64,aarch64}. Rust tool: built via cargo
# against the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
set -e
cd "$(dirname "$0")"
SRC="hyperfine-1.19.0"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-hyperfine.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# Detach from the oxide parent workspace if cargo complains. Idempotent.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" 2>/dev/null || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/hyperfine" hyperfine-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/hyperfine" hyperfine-aarch64

strip hyperfine-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" hyperfine-aarch64 2>/dev/null || true
echo "hyperfine: $(ls -la hyperfine-x86_64 hyperfine-aarch64 | awk '{print $NF, $5}')"
