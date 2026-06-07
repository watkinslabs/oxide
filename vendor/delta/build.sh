#!/usr/bin/sh
# delta (git-delta) 0.18.2 build recipe — static-musl binaries checked in as
# vendor/delta/delta-{x86_64,aarch64}. Rust tool: built via cargo against the
# *-unknown-linux-musl targets with +crt-static (no dynamic-linker dependency,
# matching the rest of the static-musl userspace). aarch64 links through the
# vendored cross-musl-gcc.
#
# C-dep avoidance (per task: prefer pure-Rust over cross-building C deps):
#   * delta's syntax engine is syntect, whose DEFAULT regex backend is
#     onig (C oniguruma). delta also pulls bat's `minimal-application`
#     feature, which hard-wires `regex-onig`. Both routes drag in the
#     onig_sys C build, which did not cross-build under musl-gcc here
#     (onig_sys st.c compile failed).
#   * Fix is pure-Rust fancy-regex: switch syntect + bat to `regex-fancy`
#     (no C dep). Patches applied idempotently below:
#       - syntect: default-features=false + features=["default-fancy"]
#       - bat: drop `minimal-application` + `regex-onig`; keep paging; add
#         `regex-fancy`.
#   * Dropping `minimal-application` removes bat::config::get_pager_executable
#     (gated on that feature). delta calls it in src/env.rs; we inline a
#     faithful pure-Rust copy (bat 0.24.0 pager.rs/config.rs) so no behavior
#     changes and no onig.
#   * git2/libgit2-sys (the other C dep) cross-builds cleanly via cmake + the
#     vendored cross CC, so it is left as-is (vendored libgit2, no system dep).
set -e
cd "$(dirname "$0")"
SRC="delta-0.18.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-delta.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
CROSS_CC="$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

# delta's Cargo.toml has no [workspace] table, so it gets absorbed into the
# oxide root workspace and fails. Add an empty [workspace] to make it
# standalone (idempotent).
grep -q '^\[workspace\]' "$SRC/Cargo.toml" || printf '\n[workspace]\n' >> "$SRC/Cargo.toml"

# syntect → pure-Rust fancy-regex (idempotent).
grep -q 'default-fancy' "$SRC/Cargo.toml" || \
  sed -i 's|^syntect = "5.0.0"$|syntect = { version = "5.0.0", default-features = false, features = ["default-fancy"] }|' "$SRC/Cargo.toml"

# bat → drop minimal-application + regex-onig; use regex-fancy (idempotent).
if grep -q 'regex-onig' "$SRC/Cargo.toml"; then
  perl -0pi -e 's/bat = \{ version = "0.24.0", default-features = false, features = \[\s*"minimal-application",\s*"paging",\s*"regex-onig",\s*\] \}/bat = { version = "0.24.0", default-features = false, features = [\n    "paging",\n    "regex-fancy",\n] }/s' "$SRC/Cargo.toml"
fi

# Inline a pure-Rust copy of bat::config::get_pager_executable(None) into
# src/env.rs (the real one is gated behind the dropped minimal-application
# feature). Idempotent: only patches if the bat:: call is still present.
if ! grep -q 'fn bat_pager_executable' "$SRC/src/env.rs"; then
  sed -i 's|bat::config::get_pager_executable(None),|bat_pager_executable(),|' "$SRC/src/env.rs"
  # Insert the free fn just before the test module.
  perl -0pi -e 's/\n#\[cfg\(test\)\]/\n\/\/ Faithful inline of bat::config::get_pager_executable(None) (gated behind\n\/\/ bat'"'"'s `minimal-application` feature, which hard-wires regex-onig — the C\n\/\/ oniguruma dep). Reproduced here so delta builds against the pure-Rust\n\/\/ regex-fancy backend with no C dependency. Mirrors bat 0.24.0\n\/\/ src\/pager.rs::get_pager + src\/config.rs::get_pager_executable.\nfn bat_pager_executable() -> Option<String> {\n    fn is_known_color_unsafe(bin: \&str) -> bool {\n        \/\/ '"'"'more'"'"'\/'"'"'most'"'"' do not support colors; '"'"'bat'"'"' would recurse.\n        match std::path::Path::new(bin).file_stem().map(|s| s.to_string_lossy()) {\n            Some(s) => matches!(s.as_ref(), "more" | "most" | "bat"),\n            None => false,\n        }\n    }\n    let bat_pager = env::var("BAT_PAGER");\n    let pager = env::var("PAGER");\n    let (cmd, from_generic_pager) = match (\&bat_pager, \&pager) {\n        (Ok(bat_pager), _) => (bat_pager.as_str(), false),\n        (_, Ok(pager)) => (pager.as_str(), true),\n        _ => ("less", false),\n    };\n    let parts = shell_words::split(cmd).ok()?;\n    let (bin, _args) = parts.split_first()?;\n    \/\/ Only the generic PAGER var is silently rewritten to `less`.\n    if from_generic_pager \&\& is_known_color_unsafe(bin) {\n        Some("less".to_string())\n    } else {\n        Some(bin.clone())\n    }\n}\n\n#[cfg(test)]/s' "$SRC/src/env.rs"
fi

rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl )
cp "$SRC/target/x86_64-unknown-linux-musl/release/delta" delta-x86_64

( cd "$SRC" && RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CROSS_CC" \
    CC_aarch64_unknown_linux_musl="$CROSS_CC" \
    cargo build --release --target aarch64-unknown-linux-musl )
cp "$SRC/target/aarch64-unknown-linux-musl/release/delta" delta-aarch64

strip delta-x86_64 2>/dev/null || true
"$CROSS_CC" --version >/dev/null 2>&1 && "${CROSS_CC%gcc}strip" delta-aarch64 2>/dev/null || true
echo "delta: $(ls -la delta-x86_64 delta-aarch64 | awk '{print $NF, $5}')"
