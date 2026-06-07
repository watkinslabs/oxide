#!/usr/bin/sh
# xh 0.23.0 build recipe — static-musl binaries checked in as
# vendor/xh/xh-{x86_64,aarch64}. Rust tool: built via cargo against the
# *-unknown-linux-musl targets with +crt-static (no dynamic-linker
# dependency, matching the rest of the static-musl userspace). aarch64
# links through the vendored cross-musl-gcc.
#
# TLS: rustls (pure-Rust, ring/aws-lc) — NOT native-tls/openssl, so no
# openssl C dep is pulled into the static build. xh's `rustls` feature
# maps to reqwest/rustls-tls{,-webpki-roots,-native-roots}. Built with
# --no-default-features so native-tls can never sneak in; we re-add only
# `rustls` (+ `network-interface`, needed for SO_BINDTODEVICE platforms).
set -e
cd "$(dirname "$0")"
SRC="xh-0.23.0"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-xh.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

FEATURES="rustls,network-interface"

# xh's Cargo.toml has no [workspace]; it sits inside the oxide2 workspace
# tree, so cargo refuses to build it standalone. Add an empty [workspace]
# guard to detach it. Idempotent.
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

# xh hardcodes syntect with `regex-onig` (oniguruma) for response-body
# syntax highlighting — a C dependency requiring a C compiler/oniguruma.
# To keep the static-musl build C-dep-free, swap to syntect's pure-Rust
# `regex-fancy` backend (fancy-regex crate). Idempotent.
sed -i 's/"regex-onig"/"regex-fancy"/g' "$SRC/Cargo.toml"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --no-default-features --features "$FEATURES" \
    --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/xh" xh-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --no-default-features --features "$FEATURES" \
    --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/xh" xh-aarch64

strip xh-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" xh-aarch64 2>/dev/null || true
echo "xh: $(ls -la xh-x86_64 xh-aarch64 | awk '{print $NF, $5}')"
