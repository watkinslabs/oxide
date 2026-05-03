# State 2026-05-03 (session 11 EOD)

Resumable checkpoint — current snapshot only. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`. **For per-session history of what landed see `CHANGELOG.md`** — this file is no longer the historical log.

## Phase

**Phase 1 substantially done. True IRQ-exit preemption live (R07) + 64-task ctxsw canary green + arch-generic page-table walker.** 141 PRs total; 470 hosted tests pass; both arches boot through Limine into `kernel_main`, parse ACPI, bring up PMM, splice kernel-device MMIO mappings into the live page tables (PMM-backed walker), enable LAPIC (x86) / GIC (arm), take real timer IRQs, run a 4-kthread preempt smoke, then a 64-kthread × 16-iter ctxsw register-canary smoke that validates callee-save preservation across `oxide_context_switch` (per `14§8`). The timer ISR drains `NEED_RESCHED` and `oxide_context_switch`s into the chosen task at the IRQ epilogue tail; fresh kthreads built via `Context::new_kernel_with_irq_frame` are entered via the synthetic IRQ frame's `iretq`/`eret`. Every spec-listed `klog::*` call site sits inside a `#[cfg(feature = "debug-<sub>")]` or `debug_<sub>!` macro-pair scope; default builds emit zero log bytes. `spec-lint code/klog-ungated` enforces project-wide.

Last verified-green at session-11 EOD:
```
$ cargo run -p xtask -- spec-lint            # → spec-lint: clean
$ cargo run -p xtask -- test                 # → 470 hosted tests, 0 failures
$ cargo run -p xtask -- kernel  --arch x86_64                   # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                  # builds clean
$ cargo run -p xtask -- kernel  --arch x86_64  --features debug-all
$ cargo run -p xtask -- kernel  --arch aarch64 --features debug-all
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  preempt: kthread 1..=4 enter / done
[INFO]  preempt: done yields=0 ticks=17
[INFO]  canary: install n=64
[INFO]  canary: done n=64 iters=16 ticks=1088
[…] [INFO]  boot: kernel ready, halting
$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
… same trace, preempt ticks=16, canary ticks=1088 …
```

`make ci` mirrors the full PR gate (lint + test + build + build-debug, both arches).

## What landed since previous EOD

See `CHANGELOG.md § Session 11` for the per-PR table.

- **#141** (`P1-85-mmu-walker-generic`): extract the 4-level walk loop shared between x86_64 (PML4→PDPT→PD→PT) and aarch64 EL1 (L0→L1→L2→L3) into `crates/hal/src/pt_walker.rs`. Both arches use 4 KiB granule, 512 entries per table, identical 39/30/21/12 VA-bit shifts; only entry bit semantics + privileged-register access differ. Generic `map_device_4k<W: PtWalker, F>` driver; `PtWalkerX86` / `PtWalkerArm` impls. Per-arch `map_device_4k` shims delegate. +5 hosted tests.
- **Sessions 9–10 carry-over** (PRs #136–#140): Makefile (#136), R07 preempt (#137), session-9 docs (#138), 64-task canary (#139), ksched split (#140). See `CHANGELOG.md`.

## What's done overall

### Spec corpus (44 / 46 FROZEN)

Unchanged structurally. R07 added in session 9:
- **R07** (`docs/14`): `Context::new_kernel_with_irq_frame` per arch + scaffold layout (x86: 136 B; arm: 192 B); `oxide_irq_resume_user` shared epilogue; `oxide_preempt_{cur,next}_ctx` plumbing.

### Tooling

Unchanged plus root `Makefile` (`make ci` mirrors PR gate).

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib + `kernel_main(&BootInfo)` + `#[global_allocator]` + per-arch device-bringup smoke + preempt + canary smoke | builds host + both kernel targets; default builds emit zero kernel klog |
| `kernel/src/{acpi,kthread,ksched,preempt_smoke,canary}.rs` | cfg-gated at module declaration (`debug-acpi`/`debug-sched`) | `preempt_smoke` + `canary` new in session 10 |
| `kernel/src/preempt.rs` | `NEED_RESCHED` flag + `oxide_preempt_{cur,next}_ctx` + `tick_pick_next` hook | unchanged from session 9 |
| `kernel/src/{lapic,gic}.rs` | dispatchers call `preempt::tick_pick_next` after EOI | unchanged from session 9 |
| `crates/hal-{x86_64,aarch64}/src/{context,irq,vbar}.rs` | `new_kernel_with_irq_frame` + `oxide_irq_resume_user` + schedule-on-exit asm; ARM frame 192 B saving ELR/SPSR | unchanged from session 9 |
| `crates/hal/src/pt_walker.rs` | arch-generic `PtWalker` trait + `map_device_4k` driver | new in session 11 |
| `crates/hal-{x86_64,aarch64}/src/vmm.rs` | `PtWalkerX86`/`PtWalkerArm` impls + thin `map_device_4k` shims | refactored session 11 |
| `crates/hal-{x86_64,aarch64}/src/fault.rs` | exception printer body under `debug-irq` | unchanged |
| `crates/boot-{x86_64,aarch64}/` | per-crate `debug-boot` gate | unchanged |
| `crates/limine-proto/` | shared protocol types + magic-words pinning | unchanged |
| Other crates | unchanged from session 8 EOD |

Workspace test count: **470 passed, 0 failed.** (+5 over session 10 — pt_walker driver + per-arch pack/unpack roundtrips.)

### IRQ-exit preemption (R07 — fully implemented)

Per-vector IRQ stub flow (both arches):
1. CPU pushes iretq/eret frame; stub pushes scratch GPs + (x86) vec/err pad + (arm) ELR/SPSR.
2. `bl/call oxide_irq_dispatch` → Rust dispatcher (lapic/gic) bumps tick + EOI, then calls `preempt::tick_pick_next`.
3. Picker (`ksched::tick_pick_next_for_irq_exit`, gated `debug-sched`) picks next not-`done` kthread, stages `(prev,next)` in `oxide_preempt_{cur,next}_ctx`.
4. Asm reads `oxide_preempt_next_ctx`; if non-null, calls `oxide_context_switch(cur,next)`. Both paths fall through to `oxide_irq_resume_user`.
5. Resume label pops scratch + restores ELR/SPSR (arm) + iretq/eret. Fresh kthreads enter via the synthetic IRQ frame; previously-preempted kthreads return to where they were interrupted.

`fatal!` is the lone exception. Cooperative `tick_yield` voluntary path retained for the kthread "I'm done, give boot back" edge.

## What's NOT done (pending tasks)

1. **64-task 1h canary soak** (`docs/14§8`) — bounded version landed (#139). The full 64 × 1ms × 1h soak requires the background CI infra per `40§3` which is still spec-only.
2. **First userspace `iretq`/`eret` smoke** (Phase 2 boundary) — `Context::new_user` exists in HAL crates but the actual transition to ring 3 / EL0 isn't wired. Needs a kernel-owned GDT (Limine's GDT lacks user descriptors), user CS/SS for x86 / SPSR config for arm, user kernel-stack swap, syscall entry path, return-to-user path. Largest single jump.
3. **Wire `crates/sched`'s real `RunqueueInner` into the kernel** — `kernel/src/ksched.rs` is a kernel-only Vec-based shim. Frozen spec (`13§5`) wants `Task` extended with `kernel_stack` + arch-context fields and the kernel using `RunqueueInner::pick_next_task`. Plumbing-heavy refactor.
4. **MmuOps trait full surface** (`20§5`/`21§5`) — arch-generic 4 KiB walker landed in #141 (`PtWalker`); the wider `MmuOps::map`/`unmap`/`translate` (with 2 MiB / 1 GiB / 2 MiB block sizes) still needs implementation. Today's `map_device_4k` only covers the 4 KiB Device-attr leaf path.
5. **Page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown.
6. **Block writeback / procfs surface / VFS dentry cache / IPC bodies / userspace platform** — unchanged from session 8 EOD pending list.
7. **CI matrix update** to exercise each `debug-<sub>` feature solo (per `04§3` recipe). Presupposes a real CI workflow file exists; that's still spec-only at `docs/40`.
8. **Files over 500-line soft cap**:
    - `kernel/src/lib.rs` ~700 (grew with canary smoke wiring; candidate split: extract per-arch device-map smokes to `device_map_smoke.rs`).
    - `tools/spec-lint/src/code_lint.rs` ~444 (under cap).
    - `kernel/src/ksched.rs` 367 (under cap, split in session 10).

## Repo state

```
main (origin/main): 1d8940e Merge pull request #141 from watkinslabs/P1-85-mmu-walker-generic

141 PRs landed total. Branches preserved (no deletions).

Session 9  (PRs #136 – #138):
  C22-makefile               — make wrapper
  P1-81-preempt-iret-frames  — true IRQ-exit preemption (R07)
  C23-state-eod-session-9    — session-9 docs

Session 10 (PRs #139 – #140):
  P1-83-ctxsw-canary         — 64-task ctxsw register canary
  C24-ksched-split           — split ksched.rs into shared core + preempt_smoke

Session 11 (PR #141):
  P1-85-mmu-walker-generic   — arch-generic 4-level page-table walker
```

Active local branches at EOD: `main` (working tree clean). Recent feature branches preserved.

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## Active discipline (must hold)

- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`.
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- AI-density per `08`. Cross-ref form: `<doc>§<sec>`.
- `cargo run -p xtask -- spec-lint` clean before commit (`code/klog-ungated` live).
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- File length ≤ 1000 lines hard, 500 soft.
- **R06 (lint-enforced)**: every `klog::*` call site MUST be cfg-gated under a `debug-<sub>` feature.
- **R07 (live)**: kthread `Context` records that may be entered via the IRQ tail MUST be built with `new_kernel_with_irq_frame`, not the bare `new_kernel` (which has no synthetic IRQ frame).
- Force-push to main: explicit user instruction only.
- No `Co-Authored-By:` trailers.

## Resume protocol next session

1. `cd /home/nd/oxide2 && git status` (clean, on `main`).
2. `git log --oneline -5` (HEAD = #137 merge or descendant).
3. Read this file (`state.md`).
4. Read `CLAUDE.md`.
5. Read `docs/MANIFEST.md`.
6. `make lint` (`spec-lint: clean`).
7. `make test` (≥465 passed, 0 failed).
8. `make build` (both arches build clean).
9. Optional sanity: `make qemu-x86` + `make qemu-arm` — should print the preempt-smoke + reach `boot: kernel ready, halting`.

## Suggested next branches

| Option | Branch idea | Why pick this |
|---|---|---|
| **MmuOps full surface** | `P1-87-mmu-ops-impl` | Implement `MmuOps::{map,unmap,translate,flush_va,flush_all_local}` for both arches on top of the new `pt_walker`. Includes 2 MiB / 1 GiB block-leaf support. Mechanical, contained. |
| **First userspace `eret` smoke** | `P1-82-userspace-first-eret` | Cross the Phase 1→2 line. Needs kernel-owned GDT, user CS/SS, eret-to-EL0/CPL3, syscall entry/exit. Largest single jump; significant design surface. Recommend reviewing scope with the user before starting. |
| **Wire real RunqueueInner** | `P1-84-sched-real-runqueue` | Migrate `kernel/src/ksched.rs` shim to `crates/sched`'s `RunqueueInner` per `13§5`. Plumbing-heavy refactor; doesn't unblock anything immediately. |
| **Page-fault path** | `P1-86-pf-cow-fork` | `11§5` + `11§7` page-fault entry, COW, fork, TLB shootdown. Substantial. |

If unsure: pause and surface the **userspace eret design surface** to the user before proceeding — it bakes in significant Phase-2 architectural choices (kernel-owned GDT vs Limine-extending, syscall fast-path skeleton, user kstack model).

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether to move `kernel/src/ksched.rs` logic into `crates/sched/` (extending `Task` per `13§5`) before Phase 2, or after the userspace `eret` lands.
- Should production builds be silent on a fault, or should fault printers be unconditionally on (counter to R06 strict reading)? Current state: silent halt unless `--features debug-irq`.
- v1 GDT design: kernel-owned GDT replacing Limine's at boot, or extend Limine GDT with user descriptors via a small bring-up step? Needed before Phase 2.
