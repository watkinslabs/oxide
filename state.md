# State 2026-05-02 (session 5 EOD)

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**HAL bodies + boot bring-up.** 80 PRs landed; 437 hosted tests pass; both kernel targets build clean. Session 5 landed the per-arch HAL implementation surface (CpuOps / TimerOps / Context / PtRegs / MMU types + flush asm / FPU lazy-save) and the boot front halves (Limine + Flat Device Tree handoff parsers + 16550 / PL011 UART drivers + real `_start` asm with stack swap). All assembly stays cfg-gated inside the per-arch crates per `07§5`; layout-pinning tests catch any field reorder before silent corruption.

Last verified-green at session-5 EOD:
```
$ cargo run -p spec-lint -- all   # → clean
$ cargo test --workspace          # → 437 passed, 0 failed
$ cargo run -p xtask -- kernel --arch x86_64 --profile dev   # → libkernel.rlib
$ cargo run -p xtask -- kernel --arch aarch64 --profile dev  # → libkernel.rlib
```

## What's done in session 3 (PRs #53–#61)

| PR | Branch | Lands |
|---|---|---|
| #53 | `P1-08-klog-percpu-ring` | Vyukov MPSC ring per `04§4.1`–`§4.4`; per-CPU `Ring<N>`, NMI ringlet, drop counter, single-consumer drainer. |
| #54 | `P1-09-vmm-vma-tree` | `UserVirtAddr` per `01§1` + `VmaTree` (BTreeMap) per `11§4`: insert+merge, remove_range, mprotect_range, audit. |
| #55 | `P1-10-kalloc-global` | New `crates/kalloc/`: sorted-hole-list `GlobalAlloc` over a 16 MiB BSS heap. `KMalloc=200` lock class. `#[global_allocator]` wired into kernel/lib.rs (cfg `oxide-kernel`). Boot path runs a VmaTree smoke round-trip. |
| #56 | `P1-11-vmm-address-space` | `RwLock<T,C>` in sync (reader-prefer); `vmm::AddressSpace` per `11§3`: `new` (Arc), `mmap` (hint+fixed), `munmap`, `mprotect`, `find_vma`, `audit`. First-fit hole search across user range. |
| #57 | `P1-12-pmm-page-meta` | `PageMeta` (16 B per page: refcount/flags/mapping) + `PageMetaArr` per `11§8`. `PageFlags::{DIRTY,REFERENCED,LOCKED,RESERVED}`. |
| #58 | `P1-13-sched-runqueue` | `crates/sched/`: `Task`, `SchedClass::{Rt,Normal,Idle}`, `SchedPolicy`, `TaskState`. `RtRunqueue` (100-prio FIFO + u128 bitmap), `CfsRunqueue` (BTreeMap by (vruntime,tid)), `RunqueueInner::pick_next_task` (RT > Normal > Idle). |
| #59 | `P1-14-syscall-dispatch` | `crates/syscall/`: `Errno` (Linux numbers), `SyscallArgs`, `SyscallFn`, 462-entry `SYSCALL_TABLE` (all enosys), `dispatch(nr,args)→i64` with `15§1.3` encoding. `UserPtr<T>` + `UserSlice<T>` range/alignment validation per `15§1.4`. |
| #60 | `P1-15-ipc-waitqueue` | `crates/ipc/`: `WaitQueue<C>` per `06§6`. `add_waiter` / `remove_waiter` / `wake_one` / `wake_all` / `with_lock_held`. CAS Sleeping→Runnable on wake. |
| #61 | `P1-16-vfs-foundation` | `crates/vfs/`: `types` (FileType, OpenFlags, StatxMask, PollMask, VfsError), `Inode` trait (subset), `Dentry` (positive+negative), `File` (read/write/seek + O_RDONLY/WRONLY/APPEND), `FdTable` (alloc/close/dup/dup2/cloexec), lexical path splitter. |

## What's done in session 4 (PRs #62–#70)

| PR | Branch | Lands |
|---|---|---|
| #62 | `C16-state-eod-session-3` | state.md session-3 EOD checkpoint. |
| #63 | `P1-17-block-pagecache` | `crates/block/`: `BlockDevice` trait + `BlockRequest` + `MemDisk` test backing; `PageCache` (sync `read_page` / `write_page` / `fsync` / `invalidate`) with `CachedPage` + PG_* flags. Lock discipline: fsync snapshots dirty list under cache lock, calls device outside it. |
| #64 | `P1-18-procfs-pseudo` | `crates/procfs/`: shared pseudo-FS primitive used by procfs/sysfs/devfs (`19§3`). `PseudoFs` tree of `PseudoLeaf` with `mkdir` / `register` / `unregister` / `read` / `write` / `list` / `exists`. `StaticBytesOps` + `DynamicOps<F>` helpers. |
| #65 | `P1-19-ipc-signals` | `crates/ipc/`: per-task `SignalState` per `24§4`. `Signal` enum (Linux 1..=31 / 34..=64), `SignalSet(u64)` bitmap, `SigAction` table, `SigInfo`. `send` + `pop_deliverable`; standard signals collapse to pending bit, RT signals enqueue siginfo and may bump `queue_dropped`. SIGKILL+SIGSTOP unmaskable enforced on every mutator. |
| #66 | `C17-state-mid-session-4` | state.md mid-session-4 checkpoint. |
| #67 | `P1-20-elf-parser` | `crates/elf/`: ELF64 header validation + program-header walker per `31§4`; `LoadSegment` + `PT_INTERP` extraction; W^X enforcement (`31§2` invariant 3); rejects executable PT_GNU_STACK. |
| #68 | `P1-21-net-foundation` | `crates/net/`: `MacAddr` / `Ipv4Addr` / `Ipv6Addr` / `IpAddr` / `Port` / `IpProto` / `NetIfaceId` / `eth_p`; `Pkt` packet buffer with `push`/`pop`/`put`/`trim`/`reset`; RFC 9293 11-state TCP machine + `transition` table per `25§7`. |
| #69 | `P1-22-obs-trace` | `crates/obs/`: software `Counter` (atomic u64 + global registry) + static `TracePoint` (cheap-branch enable bit + global `Tracer` callback) per `37§3`-§6. |
| #70 | `P1-23-modules-symtab` | `crates/modules/`: kernel symbol table per `18§7`. `KsymEntry`, `export` / `export_module` / `unexport_module` / `resolve` (with GPL gating per invariant 5) / `is_exported` / `snapshot`. Adds `sync::Modules = 65` lock class. |

## What's done in session 5 (PRs #71–#80)

| PR | Branch | Lands |
|---|---|---|
| #71 | `C18-state-eod-session-4` | state.md session-4 EOD checkpoint. |
| #72 | `P1-24-hal-cpuops-timerops` | `X86CpuOps` + `X86TimerOps` (`mov %gs:0`, `wrgsbase`, `rdtsc` with calibrated `TSC_KHZ`) + `ArmCpuOps` + `ArmTimerOps` (`mrs/msr tpidr_el1`, `mrs cntvct_el0` with calibrated `CNTFRQ_KHZ`). |
| #73 | `P1-25-hal-context` | `ContextX86_64` + `ContextAArch64` per `14§5` / `14§6`; `oxide_context_switch` + `oxide_trampoline_kernel` global_asm! per arch; layout-pinning tests so any field reorder breaks before silent corruption. |
| #74 | `P1-26-hal-pt-regs` | `PtRegsX86_64` + `PtRegsAArch64` per `15§1.1`/`§1.2` + `oxide_dispatch_from_pt_regs_*` Rust bridge that converts the saved register frame to `SyscallArgs`, calls `syscall::dispatch`, writes the i64 result back to the userspace-visible return register. |
| #75 | `P1-27-hal-mmu-types` | `PteX86_64` + `PteArm64` bitflags per `20§5` / `21§5`; 4-level walk constants + `va_to_indices`; native↔arch flag conversion (W^X via NX / PXN+UXN); TLB flush asm (`invlpg` / `mov cr3, cr3` / `tlbi vae1is` / `tlbi vmalle1`). |
| #76 | `P1-28-hal-fpu` | `FpuStateX86_64` (FXSAVE 512 B) + `FpuStateAArch64` (q0..q31 + fpcr/fpsr 528 B); `fpu_save` / `fpu_restore` (FXSAVE/FXRSTOR ; stp/ldp + mrs/msr fpcr+fpsr); `fpu_disable` / `fpu_enable` (CR0.TS ; CPACR_EL1.FPEN); per-arch `FPU_OWNER: AtomicPtr<_>`. |
| #77 | `P1-29-boot-x86-start` | `crates/boot-x86_64/`: Limine ≥ 6.0 protocol — request id magic constants, `RequestHeader<R>` with `AtomicPtr` response slot, `LIMINE_MEMMAP` / `_HHDM` / `_RSDP` statics in `.limine_requests`, `MemmapKind → kernel::BootMemKind` mapping. 16550A UART driver (115200-8N1, FIFO) with port-IO asm cfg-gated and host-fallback recorder. Linker script gets `.limine_requests` section. |
| #78 | `P1-30-boot-aarch64-start` | Mirror for aarch64: PL011 driver per ARM PrimeCell r1p5 (24 MHz QEMU virt clock → IBRD=13/FBRD=1, 8N1, FIFO); FDT header parser per `36§4` with magic / version / totalsize validation. |
| #79 | `P1-31-boot-x86-real-start` | Real `_start` for x86_64: inline asm swaps RSP to `KERNEL_STACK + STACK_SIZE`, calls `_start_rust` which reads `LIMINE_MEMMAP.response`, populates a `[BootMemRegion; 256]` BSS array via the new `populate_memmap_into` pure helper, tail-calls `kernel_main`. |
| #80 | `P1-32-boot-aarch64-real-start` | Mirror for aarch64: `_start(dtb_phys: u64)` stashes the DTB pointer in `DTB_PHYS_ADDR: AtomicU64` before swapping `sp`, calls `_start_rust` which validates `dtb::parse_header(view)` and falls back to an empty `BootInfo` on any error. `/memory` walker rides with PMM init. |

## What's done overall

### Spec corpus (44 / 46 FROZEN; revised earlier sessions)

Unchanged from session 2 EOD. R03/R04/C13 stand; no spec edits in session 3.

### Tooling

Unchanged: `tools/spec-lint`, `tools/xtask`, `Cargo.toml`, `rust-toolchain.toml`, `.github/workflows/pr.yml`.

### Kernel + per-subsystem crates

| Path | Role | Status |
|---|---|---|
| `kernel/` | lib; `kernel_main(&BootInfo)`; `#[global_allocator]` (cfg `oxide-kernel`); VmaTree boot smoke | builds host + both kernel targets |
| `crates/hal/` | trait-only + `UserVirtAddr` per `01§1` | builds; 2 hosted tests |
| `crates/hal-x86_64/` | IrqGate + halt + mmio_barrier + CpuOps + TimerOps + Context + PtRegs + MMU types + FPU lazy-save | builds; 27 hosted tests |
| `crates/hal-aarch64/` | IrqGate + halt + mmio_barrier + CpuOps + TimerOps + Context + PtRegs + MMU types + FPU lazy-save | builds; 28 hosted tests |
| `crates/boot-x86_64/` | Limine request slots + 16550 UART + real `_start` + memmap parser | builds; 13 hosted tests |
| `crates/boot-aarch64/` | DTB header parser + PL011 UART + real `_start` (DTB ptr stash) | builds; 12 hosted tests |
| `crates/sync/` | Spinlock + 17 LockClass (incl `KMalloc`, `Modules`) + IrqGate + PerCpu + RwLock | builds; 16 hosted tests |
| `crates/klog/` | macros + `.klog_strings` + Uart + `Ring<N>` MPSC + NMI ringlet | builds; 13 hosted tests |
| `crates/pmm/` | Linux-class buddy + lock-free page_ptr + `PageMetaArr` | 63 hosted tests; proptest oracle |
| `crates/slab/` | Cache<T,B,I,S> + per-CPU magazines | 30 hosted tests |
| `crates/kalloc/` | sorted-hole-list GlobalAlloc on 16 MiB BSS heap | 9 hosted tests |
| `crates/vmm/` | `Vma`, `VmaTree`, `AddressSpace` (RwLock-wrapped) + invariant audit | 34 hosted tests |
| `crates/sched/` | Task + SchedClass + RtRunqueue + CfsRunqueue + RunqueueInner::pick_next_task | 20 hosted tests |
| `crates/syscall/` | Errno + UserPtr/UserSlice + 462-entry dispatch table | 17 hosted tests |
| `crates/ipc/` | WaitQueue<C> + SignalState (per-task signals per `24§4`) | 24 hosted tests |
| `crates/vfs/` | Inode+Dentry+File+FdTable+path split | 25 hosted tests |
| `crates/block/` | BlockDevice + BlockRequest + MemDisk + PageCache (sync read/write/fsync/invalidate) | 16 hosted tests |
| `crates/procfs/` | shared pseudo-FS primitive (procfs/sysfs/devfs use this) | 16 hosted tests |
| `crates/elf/` | ELF64 header + phdr walker + W^X (`31§2`-§4) | 18 hosted tests |
| `crates/net/` | addr (Mac/Ipv4/Ipv6/IpAddr/IpProto) + Pkt buffer + RFC 9293 TCP states | 30 hosted tests |
| `crates/obs/` | software Counter + static TracePoint + global registries | 11 hosted tests |
| `crates/modules/` | kernel symbol table (export / resolve / GPL gating / unload) | 11 hosted tests |
| `crates/{security,nscg,tty,iouring,power,firmware,pci,drv,err}/` | one no_std crate per frozen spec; `init() -> NotImplemented` stub | all build |
| `targets/{x86_64,aarch64}-unknown-oxide-kernel.json` | rustc target specs | both produce `libkernel.rlib` |
| `link/{x86_64,aarch64}-kernel.ld` | linker scripts | not yet exercised |

Workspace test count: **437 passed, 0 failed**.

### Linux-discipline rules in place

| Concern | How enforced |
|---|---|
| `lock_irqsave` actually disables IRQs on kernel target | Pmm + Cache generic over `IrqGate`; kernel passes arch gate |
| Slab uses `lock_irqsave` not plain `lock` | per `12§4` reachable-from-softirq |
| klog safe in any ctx | `04§4.1` frozen invariant; ring impl ✓ (PR #53); macro→ring wiring deferred to HAL CpuOps |
| pmm `page_ptr` lock-order safe from slab | backing held outside Buddy spinlock |
| Locked regions: no sleep / klog (when ready) / cross-subsystem alloc | spotcheck audited at each PR |
| File-length cap | `spec-lint length` 1000-line hard cap |
| NMI safe via dedicated ringlet | `04§4.3` impl ✓ (PR #53) |
| Kernel global allocator | kalloc `#[global_allocator]` ✓ (PR #55) |
| BTreeMap usable in kernel | ✓ — vmm::VmaTree links cleanly |
| Reader-writer concurrency | `RwLock<T,C>` ✓ (PR #56) |
| Per-page metadata | `PageMetaArr` ✓ (PR #57) — slab allocation from PMM at boot pending |
| Lockdep / partial-order runtime check | ✗ planned `debug-lockdep` cargo feature |

## What's NOT done (pending tasks)

In rough order. Per-arch HAL bodies + boot front halves landed in session 5; what remains needs the **kernel-side direct-map + IDT/EL1-vector setup + PMM init + per-CPU bring-up** to be threaded together.

1. **`MmuOps::map`/`unmap`/`translate` walker**: PTE encoding ✓ (#75); flush asm ✓ (#75). Walker needs the kernel direct-map (linker-resident; needs an HHDM offset pulled from Limine), a PMM handle for intermediate-table allocation, and a global active-PT-root tracker.

2. **`oxide_syscall_entry` trampoline asm** (`15§4.1`): `PtRegs` struct + dispatch bridge ✓ (#74). The asm landing pad needs KPTI + per-CPU kernel stack + `syscall` MSR (`LSTAR` / `EFER.SCE`) bring-up.

3. **`IrqOps` (APIC + GICv3)** (`22§*`): IDT install (x86) + VBAR_EL1 install (arm); LVT vector setup; APIC base discovery via ACPI MADT / GIC distributor + redistributor MMIO programming. Once vectors exist, `set_oneshot` body lights up.

4. **VMM page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown — needs MmuOps walker + per-AS PT spinlock.

5. **sched::schedule()**: `Context::switch` ✓ (#73); needs per-CPU `Spinlock<RunqueueInner>` + `need_resched` + `preempt_count` plumbing; `wake_up` cross-CPU IPI (IrqOps); `timer_tick` (TimerOps deadline + IRQ vector).

6. **Boot post-`_start` work**: `_start` ✓ (#79, #80); IDT setup + KPTI table bootstrap + UART hookup to klog macros so `kinfo!("init started")` actually emits in QEMU; `/memory` DTB walker + Limine framebuffer / RSDP responses populated through to consumers.

3. **VMM page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown. Needs HAL MmuOps + per-AS PT spinlock.

4. **sched::schedule()**: Context::switch + per-CPU spinlock around `RunqueueInner` + need_resched + preempt_count. `wake_up` cross-CPU IPI (HAL IrqOps). `timer_tick` (HAL TimerOps).

5. **block writeback daemon** (`17§3`-§4): async submit ring + soft-IRQ completion + dirty list. Foundation `BlockDevice` + `PageCache` ✓ (PR #63); writeback timing, radix-tree, PG_LOCKED waiters pending.

6. **procfs / devfs / sysfs surface** (`19§4`-§5): per-pid procfs (drives off sched), sysfs KObj tree, devfs DevId multiplexing. Shared pseudo-FS primitive ✓ (PR #64); per-FS surface pending.

7. **VFS extensions**: dentry cache (`16§4` open-addressed RCU), Superblock + Filesystem trait, mount table (`16§6`), full ~30-method Inode surface, `path_lookup` with symlink + RESOLVE_BENEATH + mount crossing.

8. **IPC bodies**: pipe, eventfd, signalfd, timerfd, futex, AF_UNIX. Each rides alongside its VFS file backing. Per-task `SignalState` data ✓ (PR #65); kernel→user signal *delivery* still pending (vDSO trampoline + syscall return path).

9. **Subsequent subsystems** in `boot-flow.md` order: security → nscg → net → tty → iouring → elf → pci → drv → firmware → power → obs → modules → err.

10. **Userspace platform** per `29a`: musl 1.2.5 fork, ld-oxide, init, busybox-equivalent.

11. **Phase 0 finishing**:
    - `xtask qemu` real impl: spawn QEMU, expect "init started" + clean exit.
    - `.github/workflows/{bg-soak,release,dockerfile,weekly}.yml` (only `pr.yml` exists).
    - **Phase 0 exit gate**: hello-world boots both arches via QEMU.

12. **Atomic cookie CAS in slab** (P1-07 known limitation): cross-CPU concurrent double-free undetected.

13. **Bench history + soak runner** per `40`.

14. **Files over 500-line soft cap** (trim on next touch):
    - `docs/15-syscall-abi.md` 745 (large frozen ABI table; defensible)
    - `crates/pmm/src/lib.rs` 626

## Repo state

```
main (origin/main): 0868892 Merge pull request #80 from watkinslabs/P1-32-boot-aarch64-real-start

80 PRs landed total. Branches preserved (no deletions).

Session 3 (PRs #53–#61, 9 PRs):  P1-08 → P1-16
Session 4 (PRs #62–#70, 9 PRs):  C16 → P1-17 → P1-18 → P1-19 → C17 → P1-20 → P1-21 → P1-22 → P1-23
Session 5 (PRs #71–#80, 10 PRs): C18 → P1-24 → P1-25 → P1-26 → P1-27 → P1-28 → P1-29 → P1-30 → P1-31 → P1-32
```

Active local branches at EOD: `main`. Working tree clean.

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

Run these in order; expected outputs in parens.

1. `cd /home/nd/oxide2 && git status` (clean, on `main`)
2. `git log --oneline -5` (HEAD = the C16 merge or this commit's descendant)
3. Read this file (`state.md`).
4. Read `CLAUDE.md`.
5. Read `docs/MANIFEST.md` for spec corpus + freeze-order.
6. `cargo run -p spec-lint -- all` (`spec-lint: clean`)
7. `cargo test --workspace` (`437 passed, 0 failed` — number grows as new tests land)
8. `cargo run -p xtask -- kernel --arch x86_64 --profile dev` (produces `libkernel.rlib`)
9. `cargo run -p xtask -- kernel --arch aarch64 --profile dev` (same)

Then pick the next branch. HAL primitives + boot front halves are in; next thread is wiring them together for an actual hello-world boot.

| Option | Branch idea | Why pick this |
|---|---|---|
| **IDT + APIC stub** | `P1-33-hal-idt-apic` | x86_64 IDT install + APIC base discovery + LVT timer vector. Unblocks `set_oneshot` body + the syscall trampoline's IRQ-state assumptions. |
| **MmuOps walker** | `P1-33-mmu-walker` | Builds on #75 PTE encoding. Needs an HHDM offset (parse `LIMINE_HHDM` response) + a PMM handle for intermediate tables. ~400 LOC + tests. |
| **klog UART hookup** | `P1-33-klog-uart-emit` | Wire `kinfo!`/`kerror!` macro emit path to the boot crate's UART so kernel_main's "init started" actually prints in QEMU. Smallest unit-of-progress. |

If unsure: **klog UART hookup**. Smallest scope-bounded win and produces a *visible* boot trace, which makes everything else easier to debug.

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether to chase Phase 0 boot gate (boot asm + UART) vs continuing subsystem bodies. ⇒ Session 3 chose subsystem bodies; ask again if priorities shift.
