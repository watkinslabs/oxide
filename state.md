# State 2026-05-02 (session 2 EOD)

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**Spec corpus FROZEN. Allocator + sync substrate landed with extensive tests + Linux discipline rules.** 50 PRs landed; 126 hosted tests pass; both kernel targets build clean. Boot wiring + bodies for vmm/sched/etc. are next.

## What's done in session 2 (PRs #42–#50)

| PR | Branch | Lands |
|---|---|---|
| #42 | `P1-03-pmm-bodies` | Linux-class buddy: bitmap-truth (`10§3` I1), XOR-buddy O(1) merge, multi-region init, reserve_early, audit. 47 tests inc. proptest oracle 200×600 ops + 2 GiB boot test. |
| #43 | `R03-uapi-and-build-chain` | UAPI surface (`15§6.7`), LFS build chain (`07§3.4`, `29§4.1`), glossary (`01§10`). Five FROZEN specs revised. |
| #44 | `C13-file-size-rule` | 1000-line hard / 500 soft file-length cap; `spec-lint length` + `08§7` + CLAUDE.md. |
| #45 | `P1-04-slab-bodies` | Cache<T,B> with redzone+poison+freed-fill, partial/drained/PMM-return state machine. 25 tests inc. concurrent + proptest oracle. |
| #46 | `P1-05-hal-x86-aarch64-irqgate` | hal-x86_64/aarch64: IrqGate (`pushfq+cli`/`mrs daif+msr daifset`), halt, mmio_barrier. PMM+slab parameterized over IrqGate so `lock_irqsave` actually disables IRQs. |
| #47 | `R04-klog-percpu-ring` | `04§4.1`–`§4.6`: klog "safe in any ctx" frozen invariant + per-CPU lockless ring + NMI ringlet + drop policy. Eliminates context audit at every klog call site. |
| #48 | `B05-pmm-lockfree-page-ptr` | Real lock-order bug fix: slab→pmm.page_ptr was acquiring Buddy(0) while holding Slab(10) — violates `06§3.6`. Backing moved out of lock; page_ptr lock-free. |
| #49 | `P1-06-sync-percpu` | `sync::PerCpu<T, S: CpuLocalSource>` per `06§4`. MAX_CPUS=256, cacheline-padded. NoopCpuLocal + HostedCpuLocal under `hosted` feature. |
| #50 | `P1-07-slab-magazines` | Per-CPU magazine fast path per `12§3.2`. Cache<T,B,I,S>; alloc/free fast paths lock-free via PerCpu<Magazine>. Cookie management in common-path free for cross-path double-free detection. |

## What's done overall

### Spec corpus (44 / 46 FROZEN; revised this session)

- All 44 originally FROZEN specs still frozen.
- R03 (#43): `01`, `07`, `15`, `29`, `29a` revised inline (UAPI + build chain).
- R04 (#47): `04` revised (klog safe-in-any-ctx).
- C13 (#44): `08` revised (file-length cap §7).
- DRAFT-living: `00`, `05`.

### Tooling

- `tools/spec-lint/`: `docs|code|length|manifest|xref|all`.
  - `length`: 1000-line cap on `crates/**`, `kernel/**`, `tools/**`, `docs/**` (excludes `docs/v2/`).
  - Header rule allows `## Revision YYYY-MM-DD` on non-charter specs.
  - Submodule + `cfg(test)` handling for multi-file kernel crates.
- `tools/xtask/`: unchanged from session 1.
- `Cargo.toml` workspace + `rust-toolchain.toml` (`nightly-2026-05-01`).
- `.github/workflows/pr.yml` — green on every PR.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib; `kernel_main(&BootInfo)` emits "init started" | builds host + both kernel targets |
| `crates/hal/` | trait-only: `MmuOps`, `CpuOps`, `Context`, `IrqOps`, `TimerOps` + `PAGE_SIZE_BYTES`/`PAGE_SHIFT` | builds; 2 hosted tests |
| `crates/hal-x86_64/` | x86_64 IrqGate + halt + mmio_barrier (cfg-gated asm) | builds; 4 hosted tests |
| `crates/hal-aarch64/` | aarch64 IrqGate + halt + mmio_barrier | builds; 4 hosted tests |
| `crates/sync/` | Spinlock<T,C> + 15 LockClass + IrqGate + NoopIrq + PerCpu<T,S> + NoopCpuLocal + HostedCpuLocal | builds; 12 hosted tests |
| `crates/klog/` | macros + `.klog_strings` + Uart trait | builds; 3 hosted tests; **per-CPU ring impl pending per `04§4`** |
| `crates/boot-x86_64/`, `crates/boot-aarch64/` | shell `_start`, BSS stack, stub BootInfo | shells only — no asm |
| `crates/pmm/` | full Linux-class buddy w/ bitmap-truth; lock-free `page_ptr`; generic over IrqGate | 47 hosted tests; proptest oracle |
| `crates/slab/` | Cache<T,B,I,S> with per-CPU magazines + redzone+poison; `drain_local_magazine` | 30 hosted tests; proptest oracle |
| `crates/{vmm,sched,syscall,vfs,block,modules,procfs,ipc,security,nscg,net,tty,iouring,elf,power,firmware,pci,drv,obs,err}/` | one no_std crate per frozen spec; `init() -> NotImplemented` stub | all build |
| `targets/{x86_64,aarch64}-unknown-oxide-kernel.json` | rustc target specs | both produce `libkernel.rlib` |
| `link/{x86_64,aarch64}-kernel.ld` | linker scripts | not yet exercised |

Workspace test count: **126 passed, 0 failed**.

### Linux-discipline rules in place

| Concern | How enforced |
|---|---|
| `lock_irqsave` actually disables IRQs on kernel target | Pmm + Cache generic over `IrqGate`; kernel passes arch gate (#46) |
| Slab uses `lock_irqsave` not plain `lock` | #46 — per `12§4` reachable-from-softirq |
| klog safe in any ctx | `04§4.1` frozen invariant; impl pending |
| pmm `page_ptr` lock-order safe from slab | #48 — backing held outside Buddy spinlock |
| Locked regions: no sleep / klog (when ready) / cross-subsystem alloc | Audited #46 + #50; slab drops lock before pmm calls |
| File-length cap | #44 — `spec-lint length` 1000-line hard cap |
| NMI safe via dedicated ringlet | `04§4.3` spec'd; impl pending |
| Lockdep / partial-order runtime check | ✗ planned `debug-lockdep` cargo feature |

## What's NOT done (pending tasks)

In rough order:

1. **klog real impl** per `04§4`: per-CPU MPSC lockless ring, fixed-size records, drainer poll fn (kthread integration deferred). Validates the R04 contract in code.

2. **HAL impl beyond IrqGate**: `CpuOps::current_cpu` (read GS_BASE/TPIDR_EL1), `MmuOps::map/unmap`, `Context` (asm ctx-switch per `14§5`/`14§6`), `IrqOps` (APIC/GICv3), `TimerOps`. Each is days of asm.

3. **Boot crates real bodies**: x86_64 `_start` asm + Limine handoff; aarch64 `_start` asm + EDK2/U-Boot+DTB. UART backends (16550 PIO / PL011 MMIO).

4. **vmm bodies** (`11`): VMA tree (rbtree), page-fault handler, COW. VMA tree hosted-testable; PTE updates need HAL MmuOps.

5. **sched bodies** (`13`): 3-class + runqueues + cgroup quota. Needs Context.

6. **syscall dispatch** (`15`): table + UserPtr<T> + per-arch syscall_entry asm.

7. **Subsequent subsystems** in `boot-flow.md` order: vfs → block → procfs → ipc → security → nscg → net → tty → iouring → elf → pci → drv → firmware → power → obs → modules → err → init.

8. **Userspace platform** per `29a`: musl 1.2.5 fork, ld-oxide, init, busybox-equivalent.

9. **Phase 0 finishing**:
   - `xtask qemu` real impl: spawn QEMU, expect "init started" + clean exit.
   - `.github/workflows/{bg-soak,release,dockerfile,weekly}.yml` (only `pr.yml` exists).
   - **Phase 0 exit gate**: hello-world boots both arches via QEMU.

10. **Atomic cookie CAS in slab** (P1-07 known limitation): cross-CPU concurrent double-free undetected. Lands when first regression bites.

11. **Bench history + soak runner** per `40`.

12. **Files over 500-line soft cap** (trim on next touch):
    - `docs/15-syscall-abi.md` 745 (large frozen ABI table; defensible)
    - `crates/pmm/src/lib.rs` 623
    - `crates/slab/src/lib.rs` 508

## Repo state

```
main (origin/main): 9bee613 Merge pull request #50 from watkinslabs/P1-07-slab-magazines

50 PRs landed total. Branches preserved (no deletions).

Session 2 (PRs #42–#50, 9 PRs):
  P1-03 → R03 → C13 → P1-04 → P1-05 → R04 → B05 → P1-06 → P1-07
```

Remote: `origin = git@github.com:watkinslabs/oxide.git`.

## Active discipline (must hold)

- Branch-per-feature + PR-mandatory: `gh pr create` + `gh pr merge --merge --delete-branch=false`.
- Numbered branch scheme: `F/B/D/R/Z/C/P<n>-<NN>` + kebab title.
- Cool-off ≥48h default; solo waiver per `02§1.4`.
- AI-density per `08`.
- Cross-ref form: `<doc>§<sec>`. Always `cargo run -p spec-lint -- all` before commit.
- `panic = "abort"`, `kassert!` only, no `static mut`, no `dyn HAL`, `// SAFETY:` ≥30 chars.
- File length ≤ 1000 lines hard, 500 soft.
- Lock discipline: `lock_irqsave` for any spinlock shared with IRQ ctx; never call cross-subsystem allocators inside a lock; magazines use PerCpu (preempt-off contract).
- Force-push to main: explicit user instruction only.

## Resume protocol next session

1. Read `state.md` (this file).
2. Read `CLAUDE.md`.
3. Read `docs/MANIFEST.md`.
4. `git log --oneline -10` and `git status`.
5. `cargo run -p spec-lint -- all` — clean.
6. `cargo test --workspace` — 126 tests pass.
7. `cargo run -p xtask -- kernel --arch x86_64 --profile dev` — `libkernel.rlib`.
8. Pick next pending. Two highest-leverage options:
   - **klog real impl (P1-08)** — closes gap between R04 spec and code; unblocks production klog calls.
   - **vmm VMA tree (P1-09)** — next in `boot-flow.md` dep order; hosted-testable without HAL MmuOps.

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether to chase Phase 0 boot gate (boot asm + UART) vs continuing subsystem bodies.
