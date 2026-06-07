#!/usr/bin/sh
# yazi 0.4.2 build recipe — static-musl binaries checked in as
# vendor/yazi/yazi-{x86_64,aarch64} (+ ya-{x86_64,aarch64} if yazi-cli
# builds). Rust tool: built via cargo against the *-unknown-linux-musl
# targets with +crt-static (no dynamic-linker dependency, matching the
# rest of the static-musl userspace). aarch64 links + C-compiles through
# the vendored cross-musl-gcc.
#
# yazi-fm produces the `yazi` TUI binary; yazi-cli produces `ya`.
# yazi is already a cargo workspace (do NOT append [workspace]).
#
# Features / source edits:
#  - default `vendored-lua` is KEPT (mlua/vendored builds Lua 5.4 from
#    bundled C source — self-contained, cross-compiles via the musl CC).
#  - syntect's `regex-onig` (C oniguruma via onig_sys) is swapped to the
#    pure-Rust `regex-fancy` backend in yazi-fm/Cargo.toml + yazi-plugin/
#    Cargo.toml. onig_sys fails under gcc-14 (-Werror=incompatible-
#    pointer-types) and is needless C; fancy-regex is pure Rust, no C lib.
#  - tikv-jemalloc-sys + mlua vendored Lua are the remaining bundled C;
#    they build from source via the musl CC. CFLAGS relaxes the gcc-14
#    incompatible-pointer-type error for those bundled C sources.
# No external/host C library is required.
set -e
cd "$(dirname "$0")"
SRC="yazi-0.4.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-yazi.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"
CROSS_AR="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-ar"

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

CFLAGS_RELAX="-Wno-incompatible-pointer-types -Wno-error"

# --- x86_64 (native host CC) ---
( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CFLAGS="$CFLAGS_RELAX" \
    cargo build --release --target x86_64-unknown-linux-musl -p yazi-fm -p yazi-cli )
cp "$SRC/target/x86_64-unknown-linux-musl/release/yazi" yazi-x86_64
[ -f "$SRC/target/x86_64-unknown-linux-musl/release/ya" ] && cp "$SRC/target/x86_64-unknown-linux-musl/release/ya" ya-x86_64

# --- aarch64 (vendored cross-musl-gcc for link + C deps) ---
( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    AR_aarch64_unknown_linux_musl="$CROSS_AR" \
    TARGET_CC="$CROSS_CC" TARGET_AR="$CROSS_AR" \
    CFLAGS_aarch64_unknown_linux_musl="$CFLAGS_RELAX" \
    cargo build --release --target aarch64-unknown-linux-musl -p yazi-fm -p yazi-cli )
cp "$SRC/target/aarch64-unknown-linux-musl/release/yazi" yazi-aarch64
[ -f "$SRC/target/aarch64-unknown-linux-musl/release/ya" ] && cp "$SRC/target/aarch64-unknown-linux-musl/release/ya" ya-aarch64

strip yazi-x86_64 2>/dev/null || true
[ -f ya-x86_64 ] && strip ya-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && {
  "${CROSS_CC%gcc}strip" yazi-aarch64 2>/dev/null || true
  [ -f ya-aarch64 ] && "${CROSS_CC%gcc}strip" ya-aarch64 2>/dev/null || true
}
echo "yazi: $(ls -la yazi-x86_64 yazi-aarch64 2>/dev/null | awk '{print $NF, $5}')"
[ -f ya-x86_64 ] && echo "ya: $(ls -la ya-x86_64 ya-aarch64 2>/dev/null | awk '{print $NF, $5}')"
