# State 2026-05-03 (session 8 EOD)

Resumable checkpoint — current snapshot only. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`. **For per-session history of what landed see `CHANGELOG.md`** — this file is no longer the historical log.

## Phase

**Phase 1 substantially done. R06 closed project-wide.** 134 PRs total; 463 hosted tests pass; both arches boot through Limine into `kernel_main`, parse ACPI, bring up PMM, splice kernel-device MMIO mappings into the live page tables (PMM-backed walker), enable LAPIC (x86) / GIC (arm), take real timer IRQs, and run a 4-kthread cooperative scheduler smoke driven by timer-set `NEED_RESCHED`. Every spec-listed `klog::*` call site (`write_raw`, `write_hex_u64`, `write_dec_u64`, `set_byte_sink`; `kinfo!`/`kdebug!`/`kerror!`/`kfatal!`/`klog!`) sits inside a `#[cfg(feature = "debug-<sub>")]` or `debug_<sub>!` macro-pair scope; default builds emit zero log bytes. `spec-lint` enforces this via `code/klog-ungated`.

Last verified-green at session-8 EOD:
```
$ cargo run -p xtask -- spec-lint            # → spec-lint: clean (code/klog-ungated live)
$ cargo run -p xtask -- test                 # → 463 hosted tests, 0 failures
$ cargo run -p xtask -- kernel  --arch x86_64                   # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                  # builds clean
$ cargo run -p xtask -- kernel  --arch x86_64  --features debug-all
$ cargo run -p xtask -- kernel  --arch aarch64 --features debug-all
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  preempt: kthread 4 done
[INFO]  preempt: done yields=0 ticks=16
[…] [INFO]  boot: kernel ready, halting
$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
… same trace, identical structure …
```

## What landed since previous EOD

See `CHANGELOG.md § Session 8` for the per-PR table.

- **#133** (`R03-klog-gate-boot-crates`): boot-crate UART sink install + CPU/MMU dump gated under per-crate `debug-boot` feature.
- **#134** (`C20-spec-lint-klog-ungated`): `code/klog-ungated` lint live; sweep removes stub `init() { klog::kinfo!(...) }` placeholders from 20 stub crates and gates `hal-{x86_64,aarch64}/src/fault.rs` printers under a new `debug-irq` feature on each hal crate.

## What's done overall

### Spec corpus (44 / 46 FROZEN)

Unchanged from session 7. R05/R06 in `docs/04` are now fully implemented + lint-enforced.

### Tooling

Unchanged plus:
- `tools/spec-lint`: new `code/klog-ungated` rule. Walks each kernel-crate `.rs` file, tracks per-brace gated state (`debug_<sub>!` macro prefix, `#[cfg(feature = "debug-<sub>")]` attribute on the line above, parent gated), detects every spec-listed klog::* call at its column. Externally-gated submodules (parent-file `#[cfg(...)] pub mod foo;`) skipped. `crates/klog/**` and test files skipped.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib + `kernel_main(&BootInfo)` + `#[global_allocator]` + per-arch device-bringup smoke + cooperative scheduler smoke | builds host + both kernel targets; default builds emit zero kernel klog |
| `kernel/src/{acpi,kthread,ksched}.rs` | cfg-gated at module declaration to their respective `debug-{acpi,sched}` feature | unchanged |
| `kernel/src/{lapic,gic,arm_timer,pl011,pmm_setup,preempt}.rs` | always-on production bring-up modules | klog calls inside individually wrapped in `debug_<sub>!` |
| `crates/hal-{x86_64,aarch64}/` | + IDT/VBAR + IRQ asm stubs + device-VA mapper + Context + PtRegs + MMU + FPU + fault printer | fault.rs body under `debug-irq` (new in session 8) |
| `crates/boot-{x86_64,aarch64}/` | `_start` → UART sink (gated) → IDT/VBAR install → `kernel_main` | klog calls now gated under per-crate `debug-boot` (new in session 8) |
| `crates/limine-proto/` | shared protocol types + magic-words pinning | unchanged |
| `crates/{block,drv,elf,err,firmware,iouring,ipc,modules,net,nscg,obs,pci,power,procfs,sched,security,syscall,tty,vfs,vmm}/` | stub `init()` returning `Err(NotImplemented)` | placeholder `klog::kinfo!("X: init stub");` lines removed in session 8 |

Workspace test count: **463 passed, 0 failed.**

### klog-gating invariant (R06 — fully implemented + enforced)

Every `klog::*` call site sits inside one of:
- `#[cfg(feature = "debug-<sub>")]` block, attribute on enclosing fn / mod, or
- a `debug_<sub>!` macro pair (cfg-on → body, cfg-off → empty).

Per-subsystem features now declared in:
- `kernel/Cargo.toml` — `debug-{pmm,vmm,irq,acpi,sched,boot}` + `debug-all`.
- `crates/boot-{x86_64,aarch64}/Cargo.toml` — `debug-boot` + `debug-all`.
- `crates/hal-{x86_64,aarch64}/Cargo.toml` — `debug-irq` + `debug-all`.

`fatal!` is the lone exception (`docs/04§4.0`). `code/klog-ungated` lint enforces every other call site project-wide; CI gate on every PR via `xtask spec-lint`.

## What's NOT done (pending tasks)

1. **True IRQ-exit preemption** — requires every task to carry a synthetic iretq/eret frame on its stack so the IRQ asm epilogue can pop scratch + iretq into freshly-spawned tasks. Current scheduling is cooperative-with-timer-wake. The protocol change is per `14§4` — needs `Context::new_kernel` to pre-populate stack frames for IRQ exit, not just for `Context::switch` `ret`.
2. **First userspace `iretq`/`eret` smoke** (Phase 2 boundary) — `Context::new_user` exists in HAL crates but the actual transition to ring 3 / EL0 isn't wired. Needs user GDT + CS/SS (x86) or SPSR config (arm); user kernel-stack swap; syscall entry path; return-to-user path.
3. **Wire `crates/sched`'s real `RunqueueInner` into the kernel** — `kernel/src/ksched.rs` is a kernel-only Vec-based shim. The frozen spec (`13§5`) wants `Task` extended with `kernel_stack` + arch-context fields and the kernel using `RunqueueInner::pick_next_task`. Plumbing-heavy refactor; doesn't unblock anything immediately so deferred.
4. **MmuOps walker** (`20§5`/`21§5`) — PTE encoding ✓ from session 5; the walker still needs refactoring out of the inline `vmm::map_device_4k` and made arch-generic.
5. **Page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown.
6. **Block writeback / procfs surface / VFS dentry cache / IPC bodies / userspace platform** — all unchanged from session 7 EOD pending list.
7. **CI matrix update** to exercise each `debug-<sub>` feature in addition to no-features and `debug-all` (per `04§3` "release no-features, release debug-all, dev each debug-* solo").
8. **Files over 500-line soft cap** (touch on next edit):
    - `kernel/src/lib.rs` ~640
    - `kernel/src/ksched.rs` ~430
    - `tools/spec-lint/src/code_lint.rs` ~444 (new, after session 8)

## Repo state

```
main (origin/main): 4a44a32 Merge pull request #134 from watkinslabs/C20-spec-lint-klog-ungated

134 PRs landed total. Branches preserved (no deletions).

Session 8 (PRs #133 – #134, 2 PRs): R03 boot-crate klog gating + C20 code/klog-ungated lint
  + cleanup sweep (stub crates, hal fault printers).
```

Active local branches at EOD: `main` (working tree clean). Recent feature branches preserved: `R03-klog-gate-boot-crates`, `C20-spec-lint-klog-ungated`.

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## Active discipline (must hold)

- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`.
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- AI-density per `08`. Cross-ref form: `<doc>§<sec>`.
- `cargo run -p xtask -- spec-lint` clean before commit (now includes `code/klog-ungated`).
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- File length ≤ 1000 lines hard, 500 soft.
- **R06 (now lint-enforced)**: every `klog::*` call site MUST be cfg-gated under a `debug-<sub>` feature. Default builds emit zero log bytes. Runtime per-target level filter is NOT a substitute — gating is at the call site, not inside the logger.
- Force-push to main: explicit user instruction only.
- No `Co-Authored-By:` trailers.

## Resume protocol next session

1. `cd /home/nd/oxide2 && git status` (clean, on `main`).
2. `git log --oneline -5` (HEAD = #134 merge or descendant).
3. Read this file (`state.md`).
4. Read `CLAUDE.md`.
5. Read `docs/MANIFEST.md`.
6. `cargo run -p xtask -- spec-lint` (`spec-lint: clean`).
7. `cargo run -p xtask -- test` (≥463 passed, 0 failed).
8. `cargo run -p xtask -- kernel --arch x86_64` then `--arch aarch64` (both build clean).
9. Optional sanity: `cargo run -p xtask -- qemu --arch x86_64 --features debug-all` and same for arm — should print the cooperative-scheduler smoke + reach `boot: kernel ready, halting`.

## Suggested next branches

| Option | Branch idea | Why pick this |
|---|---|---|
| **True IRQ-exit preemption** | `P1-81-preempt-iret-frames` | Extend `Context::new_kernel` so a fresh kthread's stack has a synthetic iretq/eret frame; flip the IRQ dispatcher tail to drain `NEED_RESCHED` + `Context::switch` directly (not deferred). The big architectural step; ~400-600 LOC plus careful asm. |
| **First userspace `eret` smoke** | `P1-82-userspace-first-eret` | Cross the Phase 1→2 line. Build a minimum ELF, set up user GDT (x86) / SPSR config (arm), eret to ring 3 / EL0, handle a single syscall, return. Largest single jump; needs preempt landed first or accepts no scheduling. |
| **CI matrix per-feature** | `C21-ci-debug-feature-matrix` | Update CI to exercise each `debug-<sub>` solo per `04§3` "dev each debug-* solo" recipe. Mechanical xtask + workflow tweak. |
| **Wire real RunqueueInner** | `P1-83-sched-real-runqueue` | Migrate `kernel/src/ksched.rs` shim to `crates/sched`'s `RunqueueInner` per `13§5`. Plumbing-heavy refactor; doesn't unblock anything immediately. |

If unsure: **true IRQ-exit preemption** is the major architectural milestone closing out Phase 1 cleanly before the userspace boundary. Otherwise the **userspace `eret` smoke** is the gating Phase-2 deliverable.

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether the cooperative-with-timer-wake scheduling form is acceptable for the rest of Phase 1, or whether true preemption is the gating milestone for Phase 2.
- Whether to move `kernel/src/ksched.rs` logic into `crates/sched/` (extending `Task` per `13§5`) before Phase 2, or after the userspace `eret` lands.
- Should production builds be silent on a fault, or should fault printers be unconditionally on (counter to R06 strict reading)? Current state: silent halt unless `--features debug-irq`.
