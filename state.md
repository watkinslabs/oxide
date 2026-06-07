# Session hand-off

## Headline
- **CI is GREEN again** (#1607, branch B62). It had been red 40+ runs (pre-existing,
  from the 2026-06-06 kernel-crate refactor; boot-smoke is local-only so it never
  surfaced). Fixed two classes: (a) host-compile of kernel-only crates in
  `cargo test --workspace` — gated mm-pmm `kalloc_grow`, crate-gated console/devpts/
  kmain `#![cfg(oxide-kernel)]`, dropped a stray `use crate::live::*` in procfs tests;
  (b) build-kernel jobs needed musl-gcc/cross-toolchain → added `OXIDE_STUB_BLOBS=1`
  compile-check mode (xtask writes empty placeholder rootfs/vDSO blobs; CI never boots).
- **Userspace tooling backlog: 13 vendored + boot-verified** — rg, fd, bat, eza, jq,
  tldr, hyperfine, dust, sd, btm, procs, zoxide, ncdu (#1604-1608, F399-F402).
- Earlier this session: syscalls 345→381; full one-file-per-syscall migration (224
  `<NNN>_<name>.rs` modules, lib.rs 967→114, dispatch in dispatch.rs); console/GPU,
  login-shell, arm SMP=2 all resolved. All merged.

## Vendoring pattern (FOLLOW THIS — source build, no prebuilt binaries)
Per tool: `tools/fetch-<tool>.sh` (fetch+sha256+extract source) + `vendor/<tool>/build.sh`
(cross-build static-musl BOTH arches → checked-in `<bin>-{x86_64,aarch64}`) + a
`vendor/.gitignore` allowlist block (`*` denies; add `!<tool>/ !<tool>/build.sh
!<tool>/<bin>-x86_64 !<tool>/<bin>-aarch64` + source/tarball ignore) + a tuple in the
rootfs.rs staging loop (`("<dir>","<bin>","/usr/bin/<name>")`).
- Rust: `cargo build --release --target {x86_64,aarch64}-unknown-linux-musl` with
  `RUSTFLAGS="-C target-feature=+crt-static"`; aarch64 linker/CC = vendored
  `vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc`. Append empty
  `[workspace]` to the crate Cargo.toml (else absorbed into the kernel workspace).
  Template: `tools/fetch-ripgrep.sh` + `vendor/ripgrep/build.sh`.
- C: autotools `--host=<arch>-linux-musl` static; config.cache for cross probes; UAPI
  via `vendor/lib/uapi-stage.sh`. ncurses tools link `vendor/ncurses/install-<arch>`.
  Template: `vendor/bash/build.sh`, `vendor/ncdu/build.sh`.
- **Parallel sub-agents work great** — one tool per agent (create fetch+build.sh + run
  the build + report); orchestrator wires `.gitignore`+`rootfs.rs` centrally (shared
  files — agents must NOT touch them). Then boot-test the batch + commit.

## Open — tooling backlog (continue)
- C (autotools-musl): htop (ncurses✓), tree, dos2unix, curl (openssl✓+zlib✓), wget
  (openssl✓), rsync, dialog (ncurses✓), man-db (needs gdbm). tmux needs libevent (vendor
  first). mc needs glib (hard). C++: btop, lnav (musl+libstdc++ finicky).
- Go (need Go toolchain set up first): lazygit, fzf, yq.
- More Rust (cargo-musl, easy): delta, choose, yazi (heavy). neovim is C.

## First task next session
```
cd /home/nd/oxide2 && git checkout main && git pull
# continue vendoring: fan out agents for the next batch (htop, tree, dos2unix, curl, wget),
# wire gitignore+rootfs centrally, boot-test, commit per batch. CI stays green (stub-blobs).
gh run list --limit 3   # confirm main still green
```

## Gotchas
- CI build-kernel uses `OXIDE_STUB_BLOBS=1` (compile-check only; doesn't build the real
  rootfs). Real build+boot is the LOCAL pre-push smoke. Don't "fix" CI to build the real
  rootfs unless you also add musl-gcc + cross-toolchain to pr.yml.
- Branch numbers: derive from git log every time. Max F=402, B=62.
- alice/swordfish is a working login for boot-tests (root's password differs).
