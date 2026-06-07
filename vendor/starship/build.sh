#!/usr/bin/sh
# starship 1.21.1 build recipe — static-musl binaries checked in as
# vendor/starship/starship-{x86_64,aarch64}. Rust tool: built via cargo
# against the *-unknown-linux-musl targets with +crt-static (no
# dynamic-linker dependency, matching the rest of the static-musl
# userspace). aarch64 links through the vendored cross-musl-gcc.
#
# Features: --no-default-features. Defaults (battery, notify, gix-max-perf)
# drop a C/cmake dependency: gix-max-perf wants zlib-ng (cmake), notify
# pulls notify-rust→zbus/D-Bus. --no-default-features leaves gix on its
# pure-Rust max-performance-safe path (RustCrypto sha1, no cmake/zlib-ng),
# so the whole build stays pure-Rust + static-musl.
set -e
cd "$(dirname "$0")"
SRC="starship-1.21.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-starship.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# Keep this crate out of the oxide2 root workspace (cargo refuses to build a
# crate it thinks belongs to an enclosing workspace). Empty [workspace] guard.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --no-default-features --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/starship" starship-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --no-default-features --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/starship" starship-aarch64

strip starship-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" starship-aarch64 2>/dev/null || true
echo "starship: $(ls -la starship-x86_64 starship-aarch64 | awk '{print $NF, $5}')"
