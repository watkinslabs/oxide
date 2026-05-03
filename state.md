# State 2026-05-03 (session 22b EOD — fork landed)

Resumable checkpoint — current snapshot only. Update at session exit. Next session reads this first along with `CLAUDE.md` and `docs/MANIFEST.md`. **For per-session history of what landed see `CHANGELOG.md`** — this file is no longer the historical log.

## Phase

**Phase 2 multi-process userspace live on x86_64.** `sys_fork` (P2-15b, slot 57) clones the parent's `AddressSpace` (VMA-tree copy via P2-15a; mapped pages NOT yet copied — child re-demand-pages from KernelBytes for code, fresh-zero for Anonymous), allocates a fresh PT root, spawns a child user `Task`, returns child_tid to parent via the normal sysret path. Child resumes at the post-syscall RIP with rax=0 — the canonical fork distinguisher — via the synthesised IRQ-tail iretq frame. The CFS runqueue picks both processes; **the AS-swap branch in `schedule()` (`MmuOps::activate(next.mm.root_pa)`) fires for the first time** when the scheduler crosses from parent to child. `sys_exit` (P2-13d) cleanly Zombies + reschedules each; when both are exited, the picker falls through to idle and boot resumes. **209 PRs total; 524 hosted tests.** `make ci` mirrors the full PR gate.

Last verified-green at session-22b EOD:
```
$ cargo run -p xtask -- spec-lint                              # spec-lint: clean
$ cargo run -p xtask -- test                                   # 524 passed, 0 failed
$ cargo run -p xtask -- kernel  --arch x86_64                  # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                 # builds clean
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  user-as: root_pa=…de73000 activated                   ← per-AS PML4 active (P2-19)
[INFO]  boot: kernel ready, halting
[INFO]  elf-smoke: load ok entry=0x400080 brk=0x401000        ← ELF parse + PT_LOAD register
[INFO]  elf-smoke: spawned tid=0xC0DE0001 entry=0x400080 sp=0x502000
[INFO]  sys_fork: parent_tid=0xC0DE0001 child_tid=4096 child_root=0x810000 ← P2-15b fork
[INFO]  syscall: nr=0x39 rv=0x1000                            ← parent gets child_tid
P                                                              ← parent write
[INFO]  syscall: nr=0x1 rv=0x2
[INFO]  sys_exit: code=0                                       ← parent exits
C                                                              ← child runs (rax=0)
[INFO]  syscall: nr=0x1 rv=0x2
[INFO]  sys_exit: code=0                                       ← child exits
[INFO]  elf-smoke: user task exited cleanly, boot resumed     ← schedule() returned to boot

$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
…
[INFO]  user-as: root_pa=…4a6f4000 activated
[INFO]  boot: kernel ready, halting
[INFO]  elf-smoke-arm: load ok entry=0x400080 brk=0x401000
[INFO]  drop-to-el0: elr=0x400080 sp_el0=0x502000
el
[INFO]  syscall: nr=0x1 rv=0x3
[INFO]  syscall: nr=0x3c rv=0x0
[INFO]  elf-smoke-arm: ok EL0 BRK elr=0x4000a4 esr=0xf2000000  ← arm still uses
[FAULT] esr=0xf2000000 ec=0x3c (brk) far=…  elr=0x4000a4         direct drop-to-EL0
                                                                  (no Task wrapper yet —
                                                                   arm sys_exit unwind
                                                                   rides P2-13e)
```

Original verification block (session-20 EOD) preserved below for ref:

```
$ cargo run -p xtask -- spec-lint            # → spec-lint: clean
$ cargo run -p xtask -- test                 # → 518 hosted tests, 0 failures
$ cargo run -p xtask -- kernel  --arch x86_64                   # builds clean
$ cargo run -p xtask -- kernel  --arch aarch64                  # builds clean
$ cargo run -p xtask -- qemu    --arch x86_64  --features debug-all
…
[INFO]  pf-recover: ok pa=… magic=00c0ffeedeadbeef
[INFO]  user-map-smoke: ok pa=… flags=0x0d
[INFO]  boot: kernel ready, halting
[INFO]  userspace-eret-smoke: about to iretq cs=0x4b rip=0x400000 ss=0x43 rsp=0x501000
[INFO]  syscall: nr=0x9 rv=0x1000          ← mmap returned base (lazy, no frames yet)
hi                                           ← user wrote to mmap → demand-page silent
[INFO]  syscall: nr=0x1 rv=0x3
[INFO]  syscall: nr=0x3c rv=0x0
[INFO]  userspace-sysret-smoke: ok ring3 #UD rip=0x400048
[FAULT] vec=6 (#UD) rip=0x400048           ← deliberate halt landmark

$ cargo run -p xtask -- qemu    --arch aarch64 --features debug-all
…
[INFO]  user-map-smoke: ok pa=… flags=0x0d
[INFO]  boot: kernel ready, halting
[INFO]  userspace-eret-smoke-arm: about to eret elr=0x400000 sp_el0=0x501000
[INFO]  syscall: nr=0x27 rv=0x1                                ← getpid via SVC
[INFO]  userspace-sysret-smoke-arm: ok EL0 BRK elr=0x400008
[FAULT] esr=0xf2000000 ec=0x3c (brk) elr=0x400008             ← halt landmark
```

**Key change in trace this session vs. last**: the demand-page #PF is now **invisible**. P2-12 restructured the fault dispatcher so resolved faults are silent (matches Linux `vmm::fault` tracepoint semantics per docs/14). The user write to `(%rax)` faults, `vmm::AddressSpace::handle_page_fault` resolves it (zero-fill anon frame from PMM, MmuOps::map with vma.prot, return true), CPU retries silently. Previously this logged a loud `[FAULT]` line; now only unrecoverable faults print.

`make ci` mirrors the full PR gate (lint + test + build + build-debug, both arches).

## What landed since previous EOD

See `CHANGELOG.md` for the per-PR table.

**Session 22b** (PRs #208 – #209): two merged PRs landing fork.

- **#208 P2-15a** (`P2-15a-as-fork`): `AddressSpace::fork(new_root_pa)`
  clones the VMA tree into a fresh AS. KernelBytes-backed VMAs share
  the source's `&'static [u8]` slice; Anonymous VMAs reset rss=0.
  Mapped pages NOT copied — child re-demand-pages on first access.
  Hosted-tested (4 new tests).
- **#209 P2-15b** (`P2-15b-sys-fork`): `sys_fork` syscall (nr=57).
  `oxide_user_rip / rflags / rsp` statics in `hal_x86_64::syscall`
  populated by the syscall asm stub before `call dispatch` so fork
  can read the user IRET frame without changing the dispatch
  signature. `sched::next_tid()` monotonic source. ELF blob updated
  to fork+branch+exit (200 B). x86_64 only this PR (arm sys_fork
  rides P2-13e arm user-Task parity).

**Session 22** (PRs #199 – #207): nine merged PRs. Big arc — laid
the per-AS PT root, wired the runqueue + schedule() AS-swap, then
built the ELF loader + KernelBytes-backed VMAs on top, drop-to-
ring3-via-VMA, arm parity, real user `Task` with `mm`, and graceful
`sys_exit` unwind. Phase 2 production-shaped userspace path is now
end-to-end on x86_64; arm runs the ELF path but doesn't yet spawn
as a Task (arm's IRQ frame doesn't save sp_el0 — fix rides next
session).

- **#199 P2-19** (`P2-19-as-pt-root`): per-AS PT root +
  `MmuOps::activate(root_pa)`. x86: `capture_kernel_master` +
  `new_user_pml4` (clones master entries 256..512 per `11§2`
  inv 5). arm: `capture_kernel_master` + `new_user_l0` (TTBR1
  unchanged across activate). `AddressSpace::new(root_pa)`.
  `user_as::init` activates the AS-private root.
- **#200 P2-13b** (`P2-13b-runqueue-wire`): real per-CPU
  `Runqueue` (atomics + `Spinlock<RunqueueInner>` per `13§6`),
  `schedule()` per `13§8` with the AS-swap branch
  (`MmuOps::activate(next.mm.root_pa)`), `schedule_from_irq`,
  `update_vruntime(prev)` so CFS rotates among ties. Migrated
  canary, preempt_smoke, ksched RR to spawn-based API. Idle
  doubles as the boot anchor (zeroed arch_ctx).
- **#201 P2-17** (`P2-17-vma-kernel-bytes`):
  `VmaBacking::KernelBytes { data: &'static [u8] }`. Demand-page
  copies bytes from the slice; tail past `data.len()` zero-fills.
- **#202 P2-16** (`P2-16-elf-loader`):
  `kernel::elf_load::load_static_blob` walks parsed PT_LOADs,
  MAP_FIXED-mmaps each as `KernelBytes`. Const-builds a 164-B
  hand-synthesised x86 ELF for the boot smoke.
- **#203 P2-16b** (`P2-16b-elf-drop-to-ring3`): factor
  `userspace_smoke::drop_to_ring3`; `elf_smoke::run` is now
  diverging — parses, loads, registers anon stack VMA, drops to
  ring 3. Replaces manual-mapping userspace_smoke on x86.
- **#204 P2-16c** (`P2-16c-elf-arm`): arm parity — factor
  `userspace_smoke_arm::drop_to_el0`, synthesise a 171-B aarch64
  ELF (movz/movk for buf VA), `elf_smoke_arm::run` replaces
  `userspace_smoke_arm::run`.
- **#205 P2-13c** (`P2-13c-spawn-user-task`):
  `ContextX86_64::new_user_with_irq_frame` (inherent — arm parity
  needs sp_el0 in IRQ frame, follow-up). `sched::spawn_user_thread`.
  `user_as::clone_global_arc()`. `elf_smoke::run_as_task` spawns
  ELF as `Arc<Task>` with `mm`, schedules into it.
- **#206 P2-13d** (`P2-13d-sys-exit-clean`): `kernel_sys_exit`
  intercepts nr=60 — stores exit_status, mark_done, schedule()
  back to boot. No more ud2-halt landmark; clean lifecycle.

**Session 21** (PRs #196 – #197): two PRs, both spec-driven (read
docs/11 and docs/13 first, then implemented exactly).

- **#196** (`P2-12-vmm-pagefault-integration`): real
  `vmm::AddressSpace::handle_page_fault` per docs/11 §5. Discovered
  during read that `crates/vmm` already had real mmap/munmap/find_vma
  on top of `VmaTree` (BTreeMap) — only PT-side integration + a
  fault hook were missing.
  - Added `FaultAccess`/`FaultKind`/`Vma::permits`/`VmaProt::to_page_flags`.
  - `AddressSpace::handle_page_fault<M, F>(va, fault, hhdm, alloc)`
    implements §5 verbatim for v1 (Anonymous + NotPresent): VMA lookup,
    prot check, frame alloc via callback, zero-fill via HHDM mirror,
    `MmuOps::map` with `vma.prot.to_pte_flags`. COW + File backing
    return NotImplemented pending `PageMeta::refcount` (§8) and VFS.
  - New `kernel/src/user_as.rs`: global single-task AS behind
    AtomicPtr (lock-free reads from fault context); per-arch
    `classify_*` decoders; `user_fault_handler` registered via
    `hal::install_fault_handler`; `glue_mmap`/`glue_munmap` for
    syscall_glue.
  - `kernel/src/syscall_glue.rs`: `kernel_mmap`/`kernel_munmap`
    now route through user_as. Replaces #191's bump-pointer mmap
    that leaked frames.
  - `userspace_smoke.rs` handler chains to user_as first. Blob
    extended with `mmap → write to mapped page → write+exit` so
    demand-paging is exercised at runtime.
  - **Fault dispatcher logging restructured**: log severity now
    depends on handler outcome. Resolved demand-page is silent
    (matches Linux, matches docs/14 trace-level for `vmm::fault`).
    Loud `[FAULT]` only when handler can't resolve (about to halt).
    Same fix on both arches. Was a pre-existing bug from #160.

- **#197** (`P2-13a-task-mm`): real `Task.mm: Option<Arc<AddressSpace>>`
  per docs/13 §5. Replaces the PhantomData<Pfn> placeholder. Two
  constructors: `Task::new` (kthread, mm=None) + `Task::new_user`
  (mm=Some). `crates/sched` gains `vmm` path-dep (correct direction:
  Linux's `include/linux/sched.h` includes `mm_types.h`). Hosted
  tests confirm CLONE_VM Arc-sharing semantics.

  **Note**: this is the data-shape change only. The runqueue side
  (per-task switch + AS swap on `schedule()` per §8) needs the real
  `RunqueueInner` wired into the kernel (currently `kernel/src/ksched.rs`
  is a Vec-backed cooperative shim from session 9). That's the next
  big refactor (called P2-13b in suggested-next-branches below).

**Sessions 19–20** (PRs #166 – #195): the big mass-PR session. See
the prior state.md revisions in git history if needed; brief summary:

Major landmarks:
- **#166-#170** Phase 1→2 boundary on x86 (kernel-owned GDT, TSS,
  interior-U=1, user-page smoke, first iretq).
- **#172** caller-saved GPR fix in x86 fault dispatcher; PF-recovery
  smoke. Audit later mirrored on arm in **#177**.
- **#173-#176** syscall MSRs + sysretq + dispatch glue + sys_write +
  sys_exit. User code now prints "hi" to UART then exits cleanly.
- **#178-#179** trivial syscalls (getpid/uid/gid/tid family) +
  sys_arch_prctl(ARCH_SET_FS) — gate to libc TLS.
- **#181-#182** arm walker TTBR0/TTBR1 selector + arm userspace
  eret smoke (BRK round-trip).
- **#183** sys_set_tid_address + sys_set_robust_list (musl/glibc
  startup needs these).
- **#184** arm SVC entry + dispatch — both arches now have full
  userspace syscall round-trip via the same dispatch table.
- **#185-#187** trivial syscall batches: mmap/mprotect/munmap/brk/
  sig*/readlink/getrandom/close/ioctl/fcntl/madvise/prlimit64.
- **#188** sys_clock_gettime via TimerOps (real monotonic time).
- **#189** sys_uname (real impl: 6 fields + per-arch machine).
- **#190** sys_writev (real impl: iterates iovec[]).
- **#191** sys_mmap MAP_ANON|MAP_PRIVATE (real impl: allocates +
  maps frames at a global bump pointer).
- **#192** refactor: validate_user_buf helper.
- **#193-#194** more stubs (read/lseek/dup*/pipe2/sigaltstack/
  nanosleep/sched_yield) + hotfix (binding sys_read at slot 0
  broke an old test asserting slot 0 returns -ENOSYS).

33 syscall slots bound: 0 (read -EBADF), 1 (write), 3 (close), 8
(lseek), 9 (mmap real), 10/11 (mprotect/munmap), 12 (brk), 13/14
(sigaction/sigprocmask), 16 (ioctl), 20 (writev real), 24 (sched_
yield), 28 (madvise), 32/33 (dup/dup2), 35 (nanosleep), 39 (getpid),
60 (exit), 63 (uname real), 72 (fcntl), 89 (readlink), 102-108
(uid/gid family), 131 (sigaltstack), 158 (arch_prctl real), 186
(gettid), 218 (set_tid_address), 228 (clock_gettime real), 273
(set_robust_list), 292 (dup3), 293 (pipe2), 302 (prlimit64), 318
(getrandom).

- **#166** (`P1-93-kernel-owned-gdt`): kernel-owned GDT in BSS replaces Limine's. Selector offsets mirror Limine v6 layout (`KERNEL_CS=0x28` / `KERNEL_DS=0x30` keep working unchanged); adds `USER_CS=0x3B` / `USER_DS=0x43` (DPL=3) for Phase 2. Far return uses `.byte 0x48, 0xCB` (REX.W + retf) — long-mode `lret` defaults to 32-bit which would have hung the prior abandoned attempt. Validated under qemu-mcp by stepping through `lgdt` + segment reloads + `lretq`. +8 hosted tests.
- **#167** (`P1-94-tss-install`): 64-bit TSS in BSS + 16-byte system descriptor at GDT[9..11] (selector 0x48). Boot path issues `ltr 0x48` after GDT install. `set_rsp0()` exposed for per-task switch-in. RSP0/IST stay zero pre-userspace; iomap_base = sizeof(TSS) so no IO bitmap. +9 hosted tests.
- **#168** (`P1-95-user-mapping`): `pack_table` sets U/S=1 unconditionally on interior PT entries. Per Intel SDM §4.6 every interior entry on a CPL=3 walk must have U/S=1; leaf U bit alone gates accessibility. ARM walker untouched (AP[2:1] gates per-leaf). +3 hosted tests.
- **#169** (`P1-96-user-page-smoke`): runtime smoke maps a 4 KiB user VA at 0x40_0000 with `USER|EXEC|READ` and translates back, asserting USER+EXEC round-trip on real CR3/TTBR0 walks. Validates the P1-95 fix end-to-end on both arches.
- **#170** (`P1-82-userspace-first-iretq`): drops to CPL=3 by building a synthetic IRET frame and executing `iretq`. User code is `int3`; CPU vectors back through IDT[3] (DPL=3 gate) → fault dispatcher → custom handler logs `userspace-eret-smoke: ok`. Bug surfaced + fixed: IDT[3]/IDT[4] gates now use `GATE_INT64_USER` (0xEE, DPL=3); previously a CPL=3 `int3` produced `#GP(IDT, vec=3)`. **Phase 1→2 boundary crossed.**

- **#159** (`C36-readme-ci-badge`): README updated from Phase-0 placeholder. CI badge wired to `pr.yml`; status section reflects current state; `make` quick-start; pointers to `state.md` / `CHANGELOG.md`.
- **#160** (`P1-86a-fault-decode`): per-arch fault printer decodes vectors + PFEC/ESR/DFSC labels. x86 emits `[FAULT] vec=0xe (#PF) … pf=NP-W-K`; arm emits `ec=0x25 (data-abort-same-el) … dfsc=permission-l3 W`. +8 hosted tests.
- **#161** (`P1-84-task-arch-ctx-buffer`): `crates/sched::Task` now carries `kernel_stack: AtomicPtr<u8>` + `arch_ctx: UnsafeCell<ArchCtxBuf>` (128 B opaque buffer per `13§5`). `Task::arch_ctx_ptr<C>()` cast helper with const size assert; compile-time fits-check in kernel for `ContextX86_64` / `ContextAArch64`. +3 hosted tests (489 total).
- **#162** (`P1-86b-fault-recover`): per-arch fault stub now branches on the dispatcher's bool return — handled → `iretq`/`eret` retry; not handled → halt as before. New `pub type FaultHandler` + `pub unsafe fn install_fault_handler(h)` per arch. Default handler returns false, behaviour preserved.
- **#163** (`B07-debug-irq-feature-chain`): latent fix. xtask `--features debug-all` only applies to its `-p`-selected packages; `hal-{x86_64,aarch64}/debug-irq` was unreachable since #160. Chain through `boot-{arch}/Cargo.toml::debug-irq = ["hal-<arch>/debug-irq"]` so the fault decoder is actually live in production builds.
- **#164** (`C37-qemu-mcp-server`): interactive QEMU+GDB control surface as an MCP server (`tools/qemu-mcp/server.py`). 13 tools (`qemu_start`/`break`/`continue`/`stepi`/`step`/`finish`/`regs`/`mem`/`disasm`/`backtrace`/`info`/`serial`/`stop`). Pure stdlib + `mcp` package; spawns QEMU with `-s -S` + `gdb --interpreter=mi3`. `.mcp.json` at repo root registers it for Claude Code auto-load on next session start.

### Abandoned-then-recovered

- **P1-93 kernel-owned GDT** ✅ landed as #166. Root cause of prior hang likely 32-bit `lret` operand-size; new asm uses explicit REX.W.
- **P1-86c page-fault recovery smoke** — still abandoned. Lower priority post-Phase 1→2 cross; re-attempt with the userspace path intact would let us deliberate-fault from CPL=3 instead of CPL=0, which is closer to the real demand-paging shape.

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
| `crates/hal/src/pt_walker.rs` | arch-generic `PtWalker` trait + `map_device_4k`/`map_4k`/`translate_4k`/`unmap_4k` drivers | session 11 + extended session 14 |
| `crates/hal-{x86_64,aarch64}/src/vmm.rs` | `PtWalkerX86`/`PtWalkerArm` impls + thin `map_device_4k` shims; new `pack_4k_leaf` for arch-neutral flags | session 11 + session 14 |
| `crates/hal-{x86_64,aarch64}/src/mmu_ops.rs` | `X86Mmu`/`ArmMmu` markers + `MmuOps` trait impl (4K only) + static-atomic state + setup APIs | new session 14 |
| `kernel/src/pmm_setup.rs` | `pmm_static()` + `alloc_one_frame()` bare-fn for MmuOps frame allocator | extended session 14 |
| `kernel/src/device_map_smoke.rs` | uses `<X86Mmu/ArmMmu as MmuOps>::map` | migrated session 14 |
| `kernel/src/mmuops_smoke.rs` | end-to-end MmuOps roundtrip smoke for 4 KiB + 2 MiB leaves | new sessions 16/17 |
| `crates/sched/src/task.rs` | `Task` carries `kernel_stack: AtomicPtr<u8>` + `arch_ctx: UnsafeCell<ArchCtxBuf>` (128 B opaque) per `13§5` | extended session 18 (#161) |
| `crates/hal-{x86_64,aarch64}/src/fault.rs` | `FaultHandler` + `install_fault_handler` registry; bool-return dispatch; vector + PFEC/ESR/DFSC label decoders | extended session 18 (#160, #162) |
| `tools/qemu-mcp/server.py` | 13-tool MCP server for QEMU+GDB control (Claude-side dev only) | new session 18 (#164) |
| `crates/hal-{x86_64,aarch64}/src/fault.rs` | exception printer body under `debug-irq` | unchanged |
| `crates/boot-{x86_64,aarch64}/` | per-crate `debug-boot` gate | unchanged |
| `crates/limine-proto/` | shared protocol types + magic-words pinning | unchanged |
| Other crates | unchanged from session 8 EOD |

Workspace test count: **489 passed, 0 failed.** (+24 over session 10: pt_walker driver, per-arch pack/unpack roundtrips, MmuOps round-trip per arch, 2M + 1G `map_at_level`, translate/unmap_at_va huge-leaf tests, fault-vector + PFEC/ESR/DFSC decoders, Task arch_ctx round-trip.)

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
4. **MmuOps full huge-page surface complete.** `MmuOps::{map,translate,unmap}` handle 4K/2M/1G (#152, #154). `flush_va` + `flush_all_local` arch-native. Today's only caller is the device-MMIO mapper (4K-only); broader callers land with the page-fault handler / userspace mmap path.
5. **Page-fault path** (`11§5` + `11§7`): COW, fork, TLB shootdown.
6. **Block writeback / procfs surface / VFS dentry cache / IPC bodies / userspace platform** — unchanged from session 8 EOD pending list.
7. **CI matrix update** to exercise each `debug-<sub>` feature solo (per `04§3` recipe). Presupposes a real CI workflow file exists; that's still spec-only at `docs/40`.
8. **Files over 500-line soft cap** (deferred — non-kernel code or test files):
    - `crates/pmm/src/tests.rs` (751) — split candidate per CLAUDE.md test-file rule.
    - `crates/pmm/src/lib.rs` (626).
    - `crates/slab/src/lib.rs` (508).
   All kernel-side code files now under cap. Recent splits: `ksched.rs` (367), `kernel/src/lib.rs` (423), `tools/xtask/src/main.rs` (184).

## Repo state

```
main (origin/main): <session-18 docs merge>

164 PRs landed total. Branches preserved (no deletions).

Session 9  (PRs #136 – #138):
  C22-makefile               — make wrapper
  P1-81-preempt-iret-frames  — true IRQ-exit preemption (R07)
  C23-state-eod-session-9    — session-9 docs

Session 10 (PRs #139 – #140):
  P1-83-ctxsw-canary         — 64-task ctxsw register canary
  C24-ksched-split           — split ksched.rs into shared core + preempt_smoke

Session 11 (PR #141):
  P1-85-mmu-walker-generic   — arch-generic 4-level page-table walker

Session 12 (PRs #142 – #143):
  C25-state-eod-session-11   — session-11 docs
  C26-device-map-smoke-split — split lib.rs (700 → 423) into debug_macros + device_map_smoke

Session 13 (PRs #144 – #147):
  C27-state-eod-session-12   — session-12 docs
  C28-spec-lint-no-dyn-hal   — lint dyn HAL traits
  C29-ci-debug-all-matrix    — CI matrix default + debug-all per arch
  C30-xtask-qemu-split       — split xtask main.rs (576 → 184) into image_qemu module

Session 14 (PRs #148 – #151):
  C31-state-eod-session-13   — session-13 docs
  P1-87-mmuops-impl-4k       — MmuOps trait impl per arch (4 KiB)
  P1-88-mmuops-wire-pmm      — wire MmuOps to PMM + migrate device-map smoke
  C32-state-eod-session-14   — session-14 docs

Session 15 (PRs #152 – #153):
  P1-89-mmu-huge-pages       — MmuOps huge-page support (2 MiB / 1 GiB)
  C33-state-eod-session-15   — session-15 docs

Session 16 (PRs #154 – #155):
  P1-90-mmu-huge-translate   — MmuOps translate/unmap recognise huge leaves
  C34-state-eod-session-16   — session-16 docs

Session 17 (PRs #156 – #158):
  P1-91-mmuops-smoke         — MmuOps end-to-end 4 KiB roundtrip smoke
  P1-92-mmuops-2m-smoke      — MmuOps end-to-end 2 MiB roundtrip smoke
  C35-state-eod-session-17   — session-17 docs

Session 18 (PRs #159 – #164):
  C36-readme-ci-badge        — README CI badge + Phase-1 status snapshot
  P1-86a-fault-decode        — per-arch fault vector / PFEC / ESR decoders
  P1-84-task-arch-ctx-buffer — Task carries kernel_stack + arch_ctx buffer
  P1-86b-fault-recover       — recoverable fault path (asm + bool dispatcher)
  B07-debug-irq-feature-chain — chain hal-<arch>/debug-irq via boot crates
  C37-qemu-mcp-server        — interactive QEMU+GDB MCP server

Session 19 (PRs #166 – #170):  ← Phase 1→2 boundary crossed
  P1-93-kernel-owned-gdt     — kernel-owned GDT replaces Limine's
  P1-94-tss-install          — 64-bit TSS + ltr; set_rsp0 exposed
  P1-95-user-mapping         — interior PT entries set U/S=1
  P1-96-user-page-smoke      — runtime user-mapping translate round-trip
  P1-82-userspace-first-iretq — drops to CPL=3, user int3, returns via #BP
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

## Suggested next branches (post-session-22b)

The "what we have vs. what we need" framing — read the spec first
in every case. docs/MANIFEST.md has the table of which spec covers
what.

| Option | Branch idea | Spec ref | Why pick this |
|---|---|---|---|
| **`execve()` syscall** | `P2-21-execve-static` | docs/15§5 + docs/31§4 | Wraps `load_static_blob`: take a kernel-side ELF index (until VFS), build new AS, **replace `current.mm` atomically** (needs `Task.mm` to be UnsafeCell or AtomicPtr — currently it's plain `Option<Arc<>>`), iretq directly to the new entry from the syscall handler (no return through dispatch). Pairs with fork → real "shell spawn process and exec command" cycle. With multiple kernel-static blobs (e.g. "hello", "bye"), parent fork + child execve becomes the demonstrable pattern. |
| **arm user-Task parity** | `P2-13e-arm-user-task` | docs/14§R07 | x86_64 spawns ELF as a real `Arc<Task>` and supports fork; arm still uses `drop_to_el0` directly with no Task wrapper. Need `Context::new_user_with_irq_frame` for arm — requires extending the IRQ frame to save/restore sp_el0 (currently a latent bug for multi-user-task on arm). Once landed, both arches share the spawn_user_thread + sys_exit + sys_fork paths. |
| **per-page copy in fork** | `P2-15c-fork-pgcopy` | docs/11§7 | Today's fork-naive inherits empty Anonymous VMAs and demand-re-pages KernelBytes. Real POSIX fork must copy the parent's mapped pages so heap/stack survive. Requires "install PTE in non-active PT" — either temporarily-activate-the-child trick or extend the walker to take an explicit root. Until this lands, fork is correct ONLY for static-PIE programs that don't share heap state at fork time. |
| **SIGSEGV delivery** | `P2-18-sigsegv` | docs/27 + docs/11§5 | When a user fault doesn't resolve (write to RO, exec on NX, unmapped read), kernel currently halts via the smoke fault handler. Linux delivers SIGSEGV. Even a minimal "kill task on protection fault" handler would let bad user code die without taking the kernel down — required for shell to survive a child segfaulting. Needs the signal subsystem (docs/27) — sigaction + sa_restorer + signal frame on user stack. |
| **page-copy in fork** | `P2-15b-fork-pgcopy` | docs/11§7 | Today's fork-naive plan inherits empty Anonymous VMAs. Real fork must copy the parent's mapped pages into child frames so heap/stack state survives. Requires "install PTE in non-active PT" — either temporarily-activate-the-child trick or extend the walker to take an explicit root. |
| **dual user-task smoke** | `P2-13f-multi-task` | docs/13§2 inv 1+2 | Spawn two user tasks against two different ASes (each load_static_blob'd independently). Validates the AS-swap branch (`MmuOps::activate(next.mm.root_pa)`) end-to-end — currently dead code because `prev.mm == next.mm` for v1's single user task. |

## Legacy suggested next branches (pre-session-22 — superseded)

The "what we have vs. what we need" framing — read the spec first
in every case, then implement EXACTLY what it says (Linux compat
surface). docs/MANIFEST.md has the table of which spec covers what.

| Option | Branch idea | Spec ref | Why pick this |
|---|---|---|---|
| **Wire real `RunqueueInner` into kernel** | `P2-13b-runqueue-wire` | docs/13 §6, §8 | Replace `kernel/src/ksched.rs` Vec-shim with the real per-CPU `Runqueue` struct (RT bitmap + CFS RB-tree + idle). Implement `schedule()` per §8 — including `if next.mm != prev.mm: switch_address_space(...)`. Makes `Task.mm` (P2-13a) actually functional. **Largest open structural item.** |
| **TLB shootdown plumbing** | `P2-14-tlb-shootdown` | docs/11 §6 | `munmap` currently does local `flush_va` only. Spec §6 mandates IPI broadcast to every CPU whose `current.mm == self`. Land the IPI machinery + per-CPU current-mm tracking. Single-CPU v1 = no-op fast path; SMP correctness gate. |
| **PageMeta + COW** | `P2-15-page-meta-cow` | docs/11 §5 (second match arm) + §8 | Per-page refcount + flags array sized by max PFN per §8 (~16 B/page = 0.4% RAM). Unblocks `fork()` (§7) and the COW PTE-downgrade-on-shared-write path. |
| **First real ELF execution** | `P2-16-elf-loader` | docs/29a + docs/31 | Static-PIE musl ELF embedded via `include_bytes!`; ELF parser walks PT_LOAD, registers VMAs (file-backed needs P2-17), drops to user. Demand-paging (P2-12) populates pages on first access. **The big payoff for Phase 2.** Depends on file-backed VMA support (P2-17) or workaround via memcpy on the kernel side. |
| **File-backed VMAs (anon-bytes shortcut)** | `P2-17-vma-bytes-backing` | extension of docs/11 §4 | Add a `VmaBacking::KernelBytes(&'static [u8])` variant so the ELF loader can map PT_LOAD segments before VFS exists. Real `File` backing waits for docs/16 (VFS). |
| **SIGSEGV delivery on user prot-fault** | `P2-18-sigsegv` | docs/27 + docs/11 §5 reject path | Currently a user write to a R-only VMA halts the kernel via the unhandled-fault path. Linux delivers SIGSEGV; needs the signal subsystem (docs/27). Until signals land, halt is "as good as it gets" but it's a real correctness gap. |

## Open questions for user (deferred)

- Atomic cookie CAS in slab (cross-CPU double-free).
- The autonomous `/loop` cadence — too aggressive? A per-PR explicit "go" felt safer (one bug shipped + hotfixed in #193/#194 during the rapid-fire run); the slower spec-read-then-design pattern in session 21 (PRs #196/#197) felt right but was only 2 PRs across the same wall-clock window.
- README.md CI status badge.
