#!/usr/bin/sh
# eza 0.20.24 build recipe — static-musl binaries checked in as
# vendor/eza/eza-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc. eza's build.rs reads
# optional GIT_* metadata and falls back gracefully when absent.
set -e
cd "$(dirname "$0")"
SRC="eza-0.20.24"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-eza.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# eza ships a rust-toolchain.toml pinning channel 1.78 (too old for
# edition2024) and no [workspace] table, so cargo walks up into the
# oxide workspace root. Drop the pin (use oxide's nightly) and make the
# eza crate its own workspace root so cargo stops walking up. Idempotent.
rm -f "$SRC/rust-toolchain.toml" "$SRC/rust-toolchain"
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/eza" eza-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/eza" eza-aarch64

strip eza-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" eza-aarch64 2>/dev/null || true
echo "eza: $(ls -la eza-x86_64 eza-aarch64 | awk '{print $NF, $5}')"
