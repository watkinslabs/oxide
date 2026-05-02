# State 2026-05-02 (session 3 EOD)

Resumable checkpoint. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`.

## Phase

**HAL-independent kernel foundation broad.** 61 PRs landed; 256 hosted tests pass; both kernel targets build clean. Heap, address space, page metadata, scheduler runqueue, syscall dispatch, wait queue, and VFS foundation all linked into the kernel rlib. What's blocked from here is mostly HAL bodies (Context::switch, MmuOps, IrqOps, TimerOps, syscall_entry asm).

Last verified-green at session-3 EOD:
```
$ cargo run -p spec-lint -- all   # → clean
$ cargo test --workspace          # → 256 passed, 0 failed
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
| `crates/hal-x86_64/` | IrqGate + halt + mmio_barrier | builds; 4 hosted tests |
| `crates/hal-aarch64/` | IrqGate + halt + mmio_barrier | builds; 4 hosted tests |
| `crates/sync/` | Spinlock + 16 LockClass (incl `KMalloc`) + IrqGate + PerCpu + RwLock | builds; 16 hosted tests |
| `crates/klog/` | macros + `.klog_strings` + Uart + `Ring<N>` MPSC + NMI ringlet | builds; 13 hosted tests |
| `crates/boot-x86_64/`, `crates/boot-aarch64/` | shells; no asm | builds |
| `crates/pmm/` | Linux-class buddy + lock-free page_ptr + `PageMetaArr` | 63 hosted tests; proptest oracle |
| `crates/slab/` | Cache<T,B,I,S> + per-CPU magazines | 30 hosted tests |
| `crates/kalloc/` | sorted-hole-list GlobalAlloc on 16 MiB BSS heap | 9 hosted tests |
| `crates/vmm/` | `Vma`, `VmaTree`, `AddressSpace` (RwLock-wrapped) + invariant audit | 34 hosted tests |
| `crates/sched/` | Task + SchedClass + RtRunqueue + CfsRunqueue + RunqueueInner::pick_next_task | 20 hosted tests |
| `crates/syscall/` | Errno + UserPtr/UserSlice + 462-entry dispatch table | 17 hosted tests |
| `crates/ipc/` | WaitQueue<C> | 9 hosted tests |
| `crates/vfs/` | Inode+Dentry+File+FdTable+path split | 25 hosted tests |
| `crates/{block,modules,procfs,security,nscg,net,tty,iouring,elf,power,firmware,pci,drv,obs,err}/` | one no_std crate per frozen spec; `init() -> NotImplemented` stub | all build |
| `targets/{x86_64,aarch64}-unknown-oxide-kernel.json` | rustc target specs | both produce `libkernel.rlib` |
| `link/{x86_64,aarch64}-kernel.ld` | linker scripts | not yet exercised |

Workspace test count: **256 passed, 0 failed**.

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

In rough order. Most of the remaining front-half is HAL-blocked.

1. **HAL impl beyond IrqGate**: `CpuOps::current_cpu` (read GS_BASE/TPIDR_EL1), `MmuOps::map/unmap`, `Context` (asm ctx-switch per `14§5`/`14§6`), `IrqOps` (APIC/GICv3), `TimerOps`, `syscall_entry` trampoline. Each is days of asm. **Blocks: vmm fault path / sched.schedule() / sched.timer_tick / syscall trampoline / klog macro→ring wiring.**

2. **Boot crates real bodies**: x86_64 `_start` asm + Limine handoff; aarch64 `_start` asm + EDK2/U-Boot+DTB. UART backends (16550 PIO / PL011 MMIO).

3. **VMM page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown. Needs HAL MmuOps + per-AS PT spinlock.

4. **sched::schedule()**: Context::switch + per-CPU spinlock around `RunqueueInner` + need_resched + preempt_count. `wake_up` cross-CPU IPI (HAL IrqOps). `timer_tick` (HAL TimerOps).

5. **block + page-cache** (`17`): BlockDevice trait, page cache over PMM pages, dirty/writeback. Hosted-testable except for any DMA bits.

6. **procfs / devfs / sysfs** (`19`) — pseudo-FS Inode impls atop the VFS foundation that just landed.

7. **VFS extensions**: dentry cache (`16§4` open-addressed RCU), Superblock + Filesystem trait, mount table (`16§6`), full ~30-method Inode surface, `path_lookup` with symlink + RESOLVE_BENEATH + mount crossing.

8. **IPC bodies**: pipe, eventfd, signalfd, timerfd, futex, AF_UNIX. Each rides alongside its VFS file backing.

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
main (origin/main): 7e9a107 Merge pull request #61 from watkinslabs/P1-16-vfs-foundation

61 PRs landed total. Branches preserved (no deletions).

Session 3 (PRs #53–#61, 9 PRs):
  P1-08 → P1-09 → P1-10 → P1-11 → P1-12 → P1-13 → P1-14 → P1-15 → P1-16
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
7. `cargo test --workspace` (`256 passed, 0 failed` — number grows as new tests land)
8. `cargo run -p xtask -- kernel --arch x86_64 --profile dev` (produces `libkernel.rlib`)
9. `cargo run -p xtask -- kernel --arch aarch64 --profile dev` (same)

Then pick the next branch. Three highest-leverage HAL-free options:

| Option | Branch idea | Why pick this |
|---|---|---|
| **block + page-cache** | `P1-17-block-pagecache` | Closes the ext4 / fs-tmpfs blocker. BlockDevice trait + page cache over PMM are hosted-testable; DMA bits ride later. |
| **procfs / devfs / sysfs** | `P1-17-pseudo-fs` | First real users of the VFS foundation just landed. Each is small (single Inode impl per file). Unblocks `/proc/self`, `/dev/null`, `/sys/kernel/*`. |
| **HAL CpuOps / MmuOps stubs** | `P1-17-hal-impl-x86` | If you accept some asm now, this is the thing that unblocks everything in the right column of "What's NOT done": vmm fault path, sched.schedule(), syscall_entry. ≤200 LOC asm per HAL surface per `15§4.1`. |

If unsure: **block + page-cache**. It's bounded scope and unblocks the FS half of the boot stack.

## Open questions for user (deferred)

- README.md CI status badge.
- Atomic cookie CAS in slab (cross-CPU double-free).
- Whether to chase Phase 0 boot gate (boot asm + UART) vs continuing subsystem bodies. ⇒ Session 3 chose subsystem bodies; ask again if priorities shift.
