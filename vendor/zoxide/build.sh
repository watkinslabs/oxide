#!/usr/bin/sh
# zoxide 0.9.6 build recipe — static-musl binaries checked in as
# vendor/zoxide/zoxide-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
set -e
cd "$(dirname "$0")"
SRC="zoxide-0.9.6"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-zoxide.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# zoxide ships as a bare crate (no [workspace] table). Appending an empty
# [workspace] pins the workspace root here so cargo doesn't walk up into the
# oxide repo's own workspace. Idempotent.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/zoxide" zoxide-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/zoxide" zoxide-aarch64

strip zoxide-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" zoxide-aarch64 2>/dev/null || true
echo "zoxide: $(ls -la zoxide-x86_64 zoxide-aarch64 | awk '{print $NF, $5}')"
