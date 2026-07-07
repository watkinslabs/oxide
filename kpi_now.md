# KPI handoff - 2026-07-07

Current branch: `F691-kpi-runtime-compiler-glue`
Current worktree: `/home/nd/oxide/worktrees/F691-kpi-runtime-compiler-glue`

F690 is complete and merged as PR #2833.

F691 is implemented locally and ready for final publish flow:
- Runtime/compiler exports are in `crates/kernel/modules/src/linux_runtime.rs`.
- Export registration is wired from `crates/kernel/modules/src/registry.rs`.
- `crates/arch/hal-x86_64/src/linux_retpoline.rs` owns the x86 retpoline thunk assembly; `modules` only exports arch-provided addresses.
- `kpi_fix.md` marks F691 `VERIFIED`.

Validation already completed:
- `cargo test -q -p modules linux_runtime -- --test-threads=1`
- `cargo test -q -p modules -- --test-threads=1`
- `cc -std=gnu11 -Ikpi/include -ffreestanding -Wall -Wextra -Werror -fsyntax-only tools/kpi-header-smoke.c`
- `clang -target x86_64-unknown-none -std=gnu11 -Ikpi/include -ffreestanding -Wall -Wextra -Werror -fsyntax-only tools/kpi-header-smoke.c`
- `clang -target aarch64-unknown-none -std=gnu11 -Ikpi/include -ffreestanding -Wall -Wextra -Werror -fsyntax-only tools/kpi-header-smoke.c`
- `git diff --check`
- Line caps are under 500 lines for touched Rust files.
- `cargo run -q -p xtask -- kernel --arch x86_64`
- `cargo run -q -p xtask -- kernel --arch aarch64` passed on rerun after the fresh worktree fetched the aarch64 cross toolchain and generated `vdso-aarch64.so`.
- `make smoke`: x86 reached `oxide login:` in 36s; arm reached `oxide login:` in 46s.
- Fedora 6.16 audit against `target_core_mod`, `libcomposite`, `null_blk`, `e1000`, and `virtio_net` shows no missing rows for the F691 target symbols.

Still required before shutdown-safe completion:
- Commit, fetch/merge fresh `origin/main`, push branch, open PR, merge PR, fast-forward `/home/nd/oxide/kernel`, delete branch/worktree.
