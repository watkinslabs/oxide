#!/usr/bin/sh
# bat 0.24.0 build recipe — static-musl binaries checked in as
# vendor/bat/bat-{x86_64,aarch64}. Rust tool: built via cargo against
# the *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
set -e
cd "$(dirname "$0")"
SRC="bat-0.24.0"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-bat.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# bat's Cargo.toml has no [workspace] table, so it gets absorbed into the
# oxide root workspace and fails. Add an empty [workspace] to make it
# standalone (idempotent).
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

# bat's default syntax engine is onig_sys (C oniguruma), which needs a musl
# C toolchain for each target. Use the pure-Rust fancy-regex backend instead
# (--no-default-features --features minimal-application,regex-fancy) so the
# build has no C dependency and cross-compiles cleanly.
# NOTE: bat's `minimal-application` feature hard-wires `regex-onig`, so
# enabling it always pulls the C oniguruma dep regardless of also requesting
# regex-fancy (cargo unions features). Enumerate minimal-application's
# components minus regex-onig, plus regex-fancy, to get a pure-Rust build.
FEATURES="--no-default-features --features clap,etcetera,paging,wild,regex-fancy"

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl $FEATURES )
cp "$SRC/target/x86_64-unknown-linux-musl/release/bat" bat-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl $FEATURES )
cp "$SRC/target/aarch64-unknown-linux-musl/release/bat" bat-aarch64

strip bat-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" bat-aarch64 2>/dev/null || true
echo "bat: $(ls -la bat-x86_64 bat-aarch64 | awk '{print $NF, $5}')"
