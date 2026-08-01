# B1671 — debug feature compile gate

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1671 | med | `debug-stderr` did not compile (`001_write.rs`, `020_writev.rs` read `Task::name` as a plain field; it is a `Spinlock<[u8; TASK_COMM_LEN]>`). Six more `c.name.as_bytes()` sites under `debug-uevent` / `debug-udevdb` / `debug-mount` / `debug-wakelat` / `debug-displaystack` were the same defect. | B1663 boot: `xtask grub --features debug-boot,debug-stderr` failed to build `syscalls`. | B1671 |
| FIXED B1671 | med | `debug-memtest` did not compile: `smoke::memtest::run` took `&Pmm<B>` while the caller holds `&Pmm<B, I>` (the `IrqGate` parameter was added to `Pmm` without updating this signature). | `E0308` at `kmain/src/kmain/early.rs:281`. | B1671 |
| FIXED B1671 | med | `debug-atexit` did not compile: `hal/src/zerotrap.rs` used `PAGE_SIZE_BYTES` without importing it. | Two `E0425` in `hal`. | B1671 |
| FIXED B1671 | med | `debug-mount` did not compile on aarch64: `user_as/fault.rs` imported the x86-only `STEP_*` statics under a feature-only cfg. | `E0432` in `pmm`, aarch64 only. | B1671 |
| FIXED B1671 | med | `make feature-gate` covered only `debug-all` — a curated 11-feature aggregate — leaving ~75 declared `debug-*` features uncompiled by any routine gate. The gate now enumerates every `debug-*` key in kmain's `[features]`, so a feature added later is covered without editing the Makefile. | The four rows above all survived months inside the old gate's blind spot. | B1671 |
| OPEN | low | `debug-atexit` is excluded from the routine gate: it is mutually exclusive with `debug-stderr` by design (`020_writev` selects the richer `[DYNERR]` tracer when atexit is on), so enabling both hides the `debug-stderr` writev block from the type checker. Covered by the separate non-routine `make feature-gate-atexit`. | Cfg is `all(feature = "debug-stderr", not(feature = "debug-atexit"))`. | — |
