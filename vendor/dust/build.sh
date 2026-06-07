#!/usr/bin/sh
# dust 1.1.1 build recipe — static-musl binaries checked in as
# vendor/dust/dust-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
set -e
cd "$(dirname "$0")"
SRC="dust-1.1.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-dust.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# dust's Cargo.toml is a member-less package that may resolve oxide's parent
# workspace; append an empty [workspace] table so cargo treats it standalone.
if ! grep -q '^\[workspace\]' "$SRC/Cargo.toml"; then
  printf '\n[workspace]\n' >> "$SRC/Cargo.toml"
fi

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/dust" dust-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/dust" dust-aarch64

strip dust-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" dust-aarch64 2>/dev/null || true
echo "dust: $(ls -la dust-x86_64 dust-aarch64 | awk '{print $NF, $5}')"
