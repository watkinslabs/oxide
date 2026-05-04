# Changelog

Per-session record of what landed on `main`. `state.md` carries the *current* snapshot; this file is the historical log. Each session ended with a `C<NN>-state-eod-session-<N>` checkpoint commit; the per-session "what's done" tables below were extracted from those checkpoints (oldest first). For per-PR detail see the merge commits or the corresponding `state.md` revision in git history (`git log --follow state.md`).

Cross-reference convention is `<doc>§<sec>` per `02`. PR ranges are inclusive.

---

## Session 1 (PRs #1 – #36) — 2026-05-02

**Subject**: spec corpus FROZEN; build infra + skeleton crates landed.

44 of 46 spec docs froze (cool-off waiver per `02§1.4`); only `00 master plan` and `05 pre-mortem` stay DRAFT permanently as living docs. Workspace compiles for host + both kernel targets.

- Charter freezes: `02`, `08`, `09`, `01`, `06`, `07`, `04`, `03`, `38`.
- Subsystem freezes: `10`–`19`, `20`, `21`, `22`, `23`, `24`–`28`, `29`, `29a`, `30`–`37`, `39`–`43`, `boot-flow.md`.
- Every spec's OQ section either resolved inline or moved to `docs/v2/<file>.md` per `02§9.8` (44 files).
- `tools/spec-lint/`: `docs|code|manifest|xref|all` + doc/code rules (`#![no_std]`, no `extern crate std`, no `static mut` outside test, no `panic!(fmt)`, `// SAFETY:` ≥30 chars, `# C:` on every `pub fn`).
- `tools/xtask/`: skeleton for `kernel|user|image|test|qemu|soak|bench|spec-lint|doc-check`. Real impls for `spec-lint`, `doc-check`, `kernel` build, `test --hosted`.
- `Cargo.toml` workspace + `rust-toolchain.toml` (`nightly-2026-05-01`).
- One `no_std` crate per frozen spec (`hal`, `klog`, `pmm`, `slab`, `vmm`, `sched`, `syscall`, `vfs`, `block`, `modules`, `procfs`, `ipc`, `security`, `nscg`, `net`, `tty`, `iouring`, `elf`, `power`, `firmware`, `pci`, `drv`, `obs`, `err`); each with `init() -> NotImplemented` stub.
- `targets/{x86_64,aarch64}-unknown-oxide-kernel.json`; `link/{x86_64,aarch64}-kernel.ld`.
- PR-mandatory + numbered branch scheme (`F/B/D/R/Z/C/P<n>-<NN>`) lockdown in `CLAUDE.md`.

22 hosted tests pass.

---

## Session 2 (PRs #42 – #50) — 2026-05-02

**Subject**: PMM + slab full bodies; klog producer-safety contract; HAL IrqGate; PerCpu.

| PR | Branch | Lands |
|---|---|---|
| #42 | `P1-03-pmm-bodies` | Linux-class buddy: bitmap-truth (`10§3` I1), XOR-buddy O(1) merge, multi-region init, reserve_early, audit. 47 tests inc. proptest oracle 200×600 ops + 2 GiB boot test. |
| #43 | `R03-uapi-and-build-chain` | UAPI surface (`15§6.7`), LFS build chain (`07§3.4`, `29§4.1`), glossary (`01§10`). Five FROZEN specs revised. |
| #44 | `C13-file-size-rule` | 1000-line hard / 500 soft file-length cap; `spec-lint length` + `08§7` + `CLAUDE.md`. |
| #45 | `P1-04-slab-bodies` | `Cache<T,B>` with redzone + poison + freed-fill, partial/drained/PMM-return state machine. 25 tests inc. concurrent + proptest oracle. |
| #46 | `P1-05-hal-x86-aarch64-irqgate` | hal-x86_64/aarch64: IrqGate (`pushfq+cli` / `mrs daif+msr daifset`), halt, mmio_barrier. PMM + slab parameterized over IrqGate so `lock_irqsave` actually disables IRQs. |
| #47 | `R04-klog-percpu-ring` | `04§4.1`–`§4.6`: klog "safe in any ctx" frozen invariant + per-CPU lockless ring + NMI ringlet + drop policy. Eliminates context audit at every klog call site. |
| #48 | `B05-pmm-lockfree-page-ptr` | Real lock-order bug fix: slab→pmm.page_ptr was acquiring Buddy(0) while holding Slab(10) — violates `06§3.6`. Backing moved out of lock; page_ptr lock-free. |
| #49 | `P1-06-sync-percpu` | `sync::PerCpu<T, S: CpuLocalSource>` per `06§4`. MAX_CPUS=256, cacheline-padded. NoopCpuLocal + HostedCpuLocal under `hosted` feature. |
| #50 | `P1-07-slab-magazines` | Per-CPU magazine fast path per `12§3.2`. `Cache<T,B,I,S>`; alloc/free fast paths lock-free via `PerCpu<Magazine>`. Cookie management in common-path free for cross-path double-free detection. |

---

## Session 3 (PRs #53 – #61) — 2026-05-02

**Subject**: klog ring + VMM tree + kalloc + AddressSpace + page metadata + sched + syscall + waitqueue + VFS foundation.

| PR | Branch | Lands |
|---|---|---|
| #53 | `P1-08-klog-percpu-ring` | Vyukov MPSC ring per `04§4.1`–`§4.4`; per-CPU `Ring<N>`, NMI ringlet, drop counter, single-consumer drainer. |
| #54 | `P1-09-vmm-vma-tree` | `UserVirtAddr` per `01§1` + `VmaTree` (BTreeMap) per `11§4`: insert+merge, remove_range, mprotect_range, audit. |
| #55 | `P1-10-kalloc-global` | New `crates/kalloc/`: sorted-hole-list `GlobalAlloc` over a 16 MiB BSS heap. `KMalloc=200` lock class. `#[global_allocator]` wired into `kernel/lib.rs` (cfg `oxide-kernel`). Boot path runs a VmaTree smoke round-trip. |
| #56 | `P1-11-vmm-address-space` | `RwLock<T,C>` in sync (reader-prefer); `vmm::AddressSpace` per `11§3`: `new` (Arc), `mmap` (hint+fixed), `munmap`, `mprotect`, `find_vma`, `audit`. First-fit hole search across user range. |
| #57 | `P1-12-pmm-page-meta` | `PageMeta` (16 B per page: refcount/flags/mapping) + `PageMetaArr` per `11§8`. `PageFlags::{DIRTY,REFERENCED,LOCKED,RESERVED}`. |
| #58 | `P1-13-sched-runqueue` | `crates/sched/`: `Task`, `SchedClass::{Rt,Normal,Idle}`, `SchedPolicy`, `TaskState`. `RtRunqueue` (100-prio FIFO + u128 bitmap), `CfsRunqueue` (BTreeMap by (vruntime,tid)), `RunqueueInner::pick_next_task` (RT > Normal > Idle). |
| #59 | `P1-14-syscall-dispatch` | `crates/syscall/`: `Errno` (Linux numbers), `SyscallArgs`, `SyscallFn`, 462-entry `SYSCALL_TABLE` (all enosys), `dispatch(nr,args)→i64` with `15§1.3` encoding. `UserPtr<T>` + `UserSlice<T>` range/alignment validation per `15§1.4`. |
| #60 | `P1-15-ipc-waitqueue` | `crates/ipc/`: `WaitQueue<C>` per `06§6`. `add_waiter` / `remove_waiter` / `wake_one` / `wake_all` / `with_lock_held`. CAS Sleeping→Runnable on wake. |
| #61 | `P1-16-vfs-foundation` | `crates/vfs/`: `types` (FileType, OpenFlags, StatxMask, PollMask, VfsError), `Inode` trait (subset), `Dentry` (positive+negative), `File` (read/write/seek + O_RDONLY/WRONLY/APPEND), `FdTable` (alloc/close/dup/dup2/cloexec), lexical path splitter. |

---

## Session 4 (PRs #62 – #70) — 2026-05-02

**Subject**: state checkpoint; block + page cache; pseudo-FS primitive; signals; ELF parser; net foundation; obs trace; modules symtab.

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

---

## Session 5 (PRs #71 – #80) — 2026-05-02

**Subject**: HAL CpuOps + TimerOps + Context + PtRegs + MMU types + FPU; boot-crate front halves (Limine x86, FDT arm) + real `_start` shells.

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

---

## Session 6 (PRs #81 – #86) — 2026-05-02

**Subject**: bootable kernel ELFs land — UART hookup, IDT/VBAR, `[[bin]]` shim crates with linker-script-driven layout.

| PR | Branch | Lands |
|---|---|---|
| #81 | `C19-state-eod-session-5` | state.md session-5 EOD checkpoint. |
| #82 | `P1-33-klog-uart-emit` | `LogSink = fn(&[u8])` byte-sink primitive in klog; `__klog_emit` formats `"[LEVEL] msg\n"` and dispatches through `BYTE_SINK: AtomicPtr<()>`. boot-x86_64 / boot-aarch64 install per-arch sinks (`Spinlock<Uart16550, Tty>` / `Spinlock<Pl011, Tty>`) at start of `_start_rust`. After this, `kinfo!` actually emits on the serial port. |
| #83 | `P1-34-hal-idt` | x86_64 IDT install per `22§4`: `IdtEntry` (16 B per Intel SDM Vol. 3 Fig. 6-7), `IdtPointer` (10 B), 256-entry static IDT, `oxide_idt_default_handler` (`cli; hlt; jmp 1b`), `install_default()` populates every entry + `lidt`s. CPU now survives first exception by halting cleanly instead of triple-faulting. |
| #84 | `P1-35-hal-vbar` | aarch64 mirror per `22§5`: 16-entry × 0x80-byte vector table at 0x800 alignment, `oxide_default_vector_handler` (`msr daifset, #0xf; wfi; b 1b`), `install_default()` writes `VBAR_EL1` + `isb`. |
| #85 | `P1-36-boot-trap-install` | `_start_rust` calls `install_default_idt()` / `install_default_vbar()` after the UART sink is installed, so any panic between IDT/VBAR install and `kernel_main` halts. `xtask kernel --arch <a>` extended to also build `boot-{arch}` — every PR's "kernel arches build" gate now exercises `_start` end-to-end. `.arch_extension fp` added to FP asm so it builds against the kernel's `-fp-armv8` target. |
| #86 | `P1-37-kernel-binary` | `crates/kernel-bin-x86_64/` + `crates/kernel-bin-aarch64/` — thin `[[bin]]` shims that pull `boot-{arch}::_start` into the link, supply a panic handler, and wire the linker script via `build.rs` (`-T link/<arch>-kernel.ld; -no-pie`). `xtask kernel --arch <a>` now produces real ELFs at the upper-half `KERNEL_BASE` per `07§6`: `oxide-x86_64` entry @ `0xFFFFFFFF80000000`, `oxide-aarch64` entry @ `0xFFFF000000000000`. `.limine_requests` lands at the correct VA in the x86 binary. spec-lint accepts `#![cfg_attr(..., no_std)]` for the host-stub case. |

End-of-session-6 verified-green:
- `cargo run -p spec-lint -- all` clean.
- `cargo test --workspace` → 451 passed, 0 failed.
- ELF entry points correct, `.limine_requests` section present.

---

## Session 7 (PRs #87 – #131) — 2026-05-03

**Subject**: bootloader integration → ACPI → kernel device-MMIO mapper → LAPIC + GIC enable → x86 + ARM IRQ infrastructure → first kthread → 3-way yield → 4-way RR → timer-driven cooperative scheduling. R05 + R06 spec revisions: per-subsystem `debug-{pmm,vmm,irq,acpi,sched,boot}` Cargo gates with the klog-must-be-gated invariant.

Long autonomous run. Highlights, oldest first:

| PR span | Subject |
|---|---|
| #87 – #91 | Bootloader integration: vendored Limine, GPT/ISO image build (`xtask image`), QEMU launcher (`xtask qemu`), `crates/limine-proto/` shared by both boot crates with magic-words pinned against upstream `limine.h`. |
| #92 | Critical fix: 4th magic word for HHDM/RSDP requests was `0x6342_8723_2167_8025` instead of `0x6398_4e95_9a98_244b` — bootloader was silently never writing the response. Pinning test catches it now. |
| #93 – #95 | `BootInfo.hhdm_offset` plumbed; PMM init from `BootInfo` (`pmm_setup::HhdmBacking`, `init_from_boot_info`); per-vector x86 fault stubs (`oxide_vec_0..31`) with stack-aligned `call oxide_fault_print_rust`. |
| #96 – #105 | Stability + xtask polish: QEMU `-cpu Haswell-v4` baseline (default qemu64 traps `SHRX` → BMI2 needed for `klog::write_hex_u64` in PMM init), Cargo pinning, kalloc smoke, slab-cache stack overflow workaround (16 K → 128 K). |
| #106 – #115 | ACPI fully decoded: RSDP parse, XSDT walk, MADT (LAPIC/IOAPIC/x2APIC/GICC/GICD/GICR), HPET, SPCR, MCFG, GTDT decoders. `BootInfo.rsdp_pa` plumbed. |
| #116 – #119 | Kernel device mapper: `hal_x86_64::vmm::map_device_4k` + `hal_aarch64::vmm::map_device_4k` splice 4 KiB Device-attr leaves into the live PML4 / TTBR1_EL1 using a caller-supplied PMM frame allocator. PL011 driver moves from semihost to real UART once PMM-backed mapping lands. |
| #120 – #123 | LAPIC enable + identity log + polled timer (x86); GICv2 enable + polled CNTV smoke (arm). |
| #124 – #125 | x86 IRQ entry stub for vec 0x40, IDT[0x40] hookup, LAPIC `timer_periodic` + STI. First real interrupt-driven kernel behaviour: `lapic: timer ticks=762`. |
| #126 | **ARM IRQ infrastructure** symmetric to x86 — VBAR slot 0x280 → asm GP-save → `oxide_arm_irq_dispatch` → IAR/EOIR + `TICK_COUNT++` + reload `CNTV_TVAL_EL0`. Same PR introduces R05 revision to `docs/04§3` adding per-subsystem `debug-{pmm,vmm,irq,acpi}` Cargo gates; every diagnostic call site now sits inside a `debug_<sub>!` macro pair so default builds elide. |
| #127 | First kernel-thread coroutine: build an arch `Context` via `new_kernel`, allocate a 16 KiB stack, `Context::switch` into it, kthread emits a klog line and switches back. |
| #128 | Three-way yield (boot → A → B → A → boot) — multi-frame stack discipline + arg-passing through trampoline. |
| #129 | 4-kthread cooperative round-robin scheduler smoke (`kernel/src/ksched.rs`). Tiny `KSched` with `Vec<KThread>` + `cur` cursor; each kthread yields N times then self-marks done; total 16 yields, returns to boot. |
| #130 | Timer-driven cooperative scheduling: timer ISRs set `NEED_RESCHED`; kthreads `hlt`/`wfi` until woken, observe the flag, cooperatively yield via `tick_yield`. Both arches: 4 kthreads, 3 ticks each, all done, 16 ticks total. *Honest scope note:* this is **cooperative-with-timer-wake**, not true preemption; true IRQ-exit preemption needs every task to carry a synthetic `iretq`/`eret` frame on its stack so the asm epilogue can iretq cleanly into a freshly-spawned task. Tracked for follow-up. |
| #131 | **R06 revision to `docs/04`**: every `klog::*` call site (level macros + byte-emit helpers + `set_byte_sink`) MUST be inside a per-subsystem `#[cfg(feature = "debug-<sub>")]` gate or a `debug_<sub>!` macro pair. Default builds emit zero log bytes; runtime per-target levels (`§4.5`) are not a substitute. Adds `debug-boot` feature for operational pulse (init started, pmm: ready, boot: kernel ready). Code sweep: every unconditional klog in `kernel/src/lib.rs` wrapped; `acpi`/`ksched`/`kthread` modules cfg-gated at declaration site. spec-lint check (`code/klog-ungated`) tracked for follow-up. |

End-of-session-7 verified-green:
- `cargo run -p xtask -- spec-lint` clean.
- `cargo run -p xtask -- test` → 463 passed, 0 failed.
- `xtask qemu --arch x86_64 --features debug-all` and `--arch aarch64` both reach `boot: kernel ready, halting` with cooperative-scheduler smoke output.

---

## Session 8 (PRs #133 – #134) — 2026-05-03

**Subject**: close the R06 sweep project-wide. Boot-crate klog gating + `code/klog-ungated` spec-lint enforcement.

| PR | Branch | Lands |
|---|---|---|
| #133 | `R03-klog-gate-boot-crates` | Apply R06 to `crates/boot-{x86_64,aarch64}/`. Each boot crate declares `debug-boot` + `debug-all` features mirroring `kernel`'s; UART sink install, CPU/MMU dump, and pl011 byte-emit helpers all sit behind `#[cfg(feature = "debug-boot")]` or a `debug_boot!` macro pair. Default builds register no klog sink, so even pre-`kernel_main` lines (`cpu vendor`, `cr0/cr3/cr4/efer`, `midr_el1`, `sctlr/tcr/mair`, `ttbr0/1`) are absent from the binary, not filtered at runtime. |
| #134 | `C20-spec-lint-klog-ungated` | Implements the lint R06 mandates. `tools/spec-lint/src/code_lint.rs` walks each kernel-crate `.rs` file, tokenising braces / `;` to track per-scope gated state. At each `{`, push gated=true if preceded on the same line by `debug_<sub>!`, the prior line carries `#[cfg(feature = "debug-<sub>")]`, or the parent is gated. Detects every spec-listed klog::* call (`write_raw`, `write_hex_u64`, `write_dec_u64`, `set_byte_sink`; `kinfo!`/`kdebug!`/`kerror!`/`kfatal!`/`klog!`) at the column it appears so single-line `debug_<sub>! { klog::...; }` is correctly recognised. Tracks externally-gated submodules (parent-file `#[cfg(...)] pub mod foo;`); skips `crates/klog/**` (logger impl) and test files. Closes the sweep: drops placeholder `klog::kinfo!("X: init stub");` lines from 20 stub crates, gates `crates/hal-{x86_64,aarch64}/src/fault.rs` exception-printer bodies under a new `debug-irq` feature on each hal crate. |

End-of-session-8 verified-green:
- `cargo run -p xtask -- spec-lint` clean (`code/klog-ungated` rule live).
- `cargo run -p xtask -- test` → 463 passed, 0 failed.
- `xtask kernel --arch {x86_64,aarch64}` builds clean default + `--features debug-all`.
- `xtask qemu --arch x86_64  --features debug-all` reaches `boot: kernel ready, halting` after the cooperative-scheduler smoke.
- `xtask qemu --arch aarch64 --features debug-all` same trace, identical structure.

---

## Session 9 (PRs #136 – #137) — 2026-05-03

**Subject**: root Makefile + true IRQ-exit preemption (R07).

| PR | Branch | Lands |
|---|---|---|
| #136 | `C22-makefile` | Root `Makefile` wrapping `xtask`. Targets: `make build|x86|arm|*-debug|test|lint|ci|qemu-x86|qemu-arm|clean|help`. `make ci` mirrors PR gate (lint + test + both arches default + debug-all). |
| #137 | `P1-81-preempt-iret-frames` | **True IRQ-exit preemption (R07).** Replaces cooperative-with-timer-wake with real preemption: timer ISR's epilogue drains `NEED_RESCHED` and `oxide_context_switch`s into the chosen task, returning via that task's stored IRQ frame. Per-arch `Context::new_kernel_with_irq_frame` builds a kernel stack with a synthetic IRQ frame (saved scratch GPs + vec/err pad on x86, saved x0..x18+x29+x30+ELR_EL1+SPSR_EL1 on arm) so a fresh task can be entered via the IRQ epilogue's iretq/eret. Shared resume label `oxide_irq_resume_user` per arch — the saved-RIP/LR fresh tasks store at scaffold base. IRQ stub does schedule-on-exit via `oxide_preempt_{cur,next}_ctx`. ARM bug riding alongside: stub at `vbar.rs:0x280` saved x0..x18+x29+x30 (176 B) but **not** ELR_EL1/SPSR_EL1 — frame extended to 192 B. x86 detail: iretq frame uses Limine v6+ GDT selectors (kernel CS=0x28, kernel DS=0x30); initial draft used 0x08 (legacy 16-bit code), iretq into a non-64-bit code segment caused a silent #GP halted via the fault path. R07 spec revision documents the layout. Layout pinned by per-arch hosted units (+2 tests over 463 baseline). |

End-of-session-9 verified-green:
- `make lint` clean.
- `make test` → 465 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` reaches `[INFO]  preempt: done yields=0 ticks=17 ... boot: kernel ready, halting` after the 4-kthread preempt smoke.
- `make qemu-arm --features debug-all` same trace, ticks=16.

---

## Session 10 (PRs #139 – #140) — 2026-05-03

**Subject**: 64-task ctxsw register canary + ksched.rs split.

| PR | Branch | Lands |
|---|---|---|
| #139 | `P1-83-ctxsw-canary` | 64-task ctxsw register-canary smoke per `docs/14§8`. Each canary kthread holds a unique per-task mark in callee-saved GP regs (r12..r15 on x86; x20..x28 on arm) across `hlt`/`wfi`. The IRQ may preempt; picker may switch to another kthread; eventually we get switched back; every reg must still hold the mark. On corruption: log fault values + `cli;hlt`/`daifset+wfi` so the smoke fails to complete (absence of `canary: done` line is the operator-visible signature). LLVM forbids `rbx`/`rbp` and `x18`/`x19`/`x29`/`x30` as `inout` operands; remaining callee-saves cover the test surface; `x19` exercised implicitly via the trampoline (loads `entry` from it). Bounded version (64 × 16-iter ≈ 1024 switches per arch); the full 1h soak is filed for background CI per `40§3`. Refactors `ksched::preempt_install_with(n, entry)` so the canary supplies its own kthread body; adds `mark_done` helper. |
| #140 | `C24-ksched-split` | Per the 500-line soft-cap discipline (`08§7`), split `kernel/src/ksched.rs` (505 → 367 lines). Extracted `smoke_preempt_x86` / `smoke_preempt_arm` / `preempt_kthread_entry` / `TICK_BUDGET` into new `kernel/src/preempt_smoke.rs` (146 lines). `KSched`/`KThread` fields exposed `pub(crate)` so `preempt_smoke` and `canary` can read scheduler state through the same shim. Behaviour preserved byte-for-byte: identical QEMU output on both arches (`preempt: done yields=0 ticks=17` x86 / `ticks=16` arm; `canary: done n=64 iters=16 ticks=1088` both arches). |

End-of-session-10 verified-green:
- `make lint` clean.
- `make test` → 465 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → preempt smoke + canary smoke + `boot: kernel ready, halting`.
- `make qemu-arm --features debug-all` → same trace.

---

## Session 11 (PR #141) — 2026-05-03

**Subject**: arch-generic 4-level page-table walker.

| PR | Branch | Lands |
|---|---|---|
| #141 | `P1-85-mmu-walker-generic` | Extract the 4-level walk loop shared between x86_64 (PML4→PDPT→PD→PT) and aarch64 EL1 (L0→L1→L2→L3) into `crates/hal/src/pt_walker.rs`. Both arches use 4 KiB granule, 512 entries per table, identical 39/30/21/12 VA-bit shifts; only entry bit semantics + privileged-register access differ. New `PtWalker` trait supplies per-arch bit semantics; generic `map_device_4k<W: PtWalker, F: FnMut() -> Option<u64>>` driver owns the loop + HHDM access. Per `07§5` no-`dyn`: monomorphizes per impl. `hal-x86_64::PtWalkerX86` (CR3 / INVLPG / P_BIT / PCD\|PWT\|NX) and `hal-aarch64::PtWalkerArm` (TTBR1_EL1 / TLBI VAE1IS / VALID\|TABLE / AttrIdx=Device\|SH=ISh\|AF\|PXN\|UXN). Per-arch `map_device_4k` shims delegate; surface unchanged for callers (kernel device-MMIO mapper). 5 new hosted tests (3 walker driver + 2 per-arch packing roundtrips); 4 KiB-aligned fake allocator via `#[repr(align(4096))]` wrapper since default `Box::new` only guarantees 8-byte alignment and the walker masks low 12 bits off the parent-slot pa. |

End-of-session-11 verified-green:
- `make lint` clean.
- `make test` → 470 passed, 0 failed (+5 over 465 baseline).
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt smoke + canary smoke pass; ticks counts unchanged from session 10; both reach `boot: kernel ready, halting`.

---

## Session 12 (PRs #142 – #143) — 2026-05-03

**Subject**: session-11 docs + lib.rs structural split.

| PR | Branch | Lands |
|---|---|---|
| #142 | `C25-state-eod-session-11` | session-11 EOD docs (P1-85 walker) |
| #143 | `C26-device-map-smoke-split` | Split `kernel/src/lib.rs` (700 → 423 lines, under 500-line soft cap per `08§7`). New `kernel/src/debug_macros.rs` (36) hoisted via `#[macro_use]` so all sibling modules see the `debug_<sub>!` macro pairs. New `kernel/src/device_map_smoke.rs` (300) holds `KERNEL_DEVICE_BASE` + per-arch HPET/LAPIC/GICD/GICC/PL011 phys+VA constants + `smoke_device_map_x86` / `smoke_device_map_arm` bodies. lib.rs `kernel_main` calls `device_map_smoke::*`. Behaviour preserved byte-for-byte. |

End-of-session-12 verified-green:
- `make lint` clean.
- `make test` → 470 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt smoke + canary smoke pass; ticks counts unchanged from session 11; both reach `boot: kernel ready, halting`.

---

## Session 13 (PRs #144 – #147) — 2026-05-03

**Subject**: spec-lint + CI hardening + tooling split.

| PR | Branch | Lands |
|---|---|---|
| #144 | `C27-state-eod-session-12` | session-12 EOD docs (lib.rs split) |
| #145 | `C28-spec-lint-no-dyn-hal` | `code/no-dyn-hal` lint rule per `07§5`. Forbids `dyn (MmuOps\|CpuOps\|Context\|IrqOps\|TimerOps)` at source level so the post-build vtable grep isn't the only gate. Detection: literal `dyn <Trait>` followed by a non-ident character; strings + line comments stripped. Verified via 3-line fixture (2 violations flagged, 1 prefix-clash control skipped). |
| #146 | `C29-ci-debug-all-matrix` | Extend `.github/workflows/pr.yml` build-kernel matrix to cover both default + `debug-all` per arch (4 jobs total) per `04§3` recipe. Per-debug-`<sub>` solo runs deferred (mostly redundant with `debug-all` aggregate). |
| #147 | `C30-xtask-qemu-split` | Split `tools/xtask/src/main.rs` (576 → 184 lines, well under cap). New `tools/xtask/src/image_qemu.rs` (404) holds `cmd_image`, `cmd_qemu`, and shared helpers (`repo_root`, `kernel_elf_path`, `check_vendor`, `build_disk_image`, `build_iso`, per-arch `qemu_run_*`, `which`). `parse_arg`, `run`, `cmd_kernel` exposed `pub(crate)` so the new module can call them. Behaviour unchanged. |

End-of-session-13 verified-green:
- `make lint` clean (`code/no-dyn-hal` rule live).
- `make test` → 470 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt smoke + canary smoke pass; ticks counts unchanged from session 12; both reach `boot: kernel ready, halting`.

---

## Session 14 (PRs #148 – #150) — 2026-05-03

**Subject**: MmuOps trait live end-to-end.

| PR | Branch | Lands |
|---|---|---|
| #148 | `C31-state-eod-session-13` | session-13 EOD docs |
| #149 | `P1-87-mmuops-impl-4k` | MmuOps trait impl per arch (4 KiB only). `pt_walker` extended with `pack_4k_leaf(pa, PageFlags)` + `map_4k`/`translate_4k`/`unmap_4k`. Per-arch `mmu_ops` modules with marker types (`X86Mmu`, `ArmMmu`), static-atomic state (`HHDM_OFFSET`, `FRAME_ALLOC`), idempotent setup APIs (`set_hhdm_offset`, `set_frame_alloc`). `hal::kassert!` macro. Huge-leaf paths (`P2M`/`P1G`) `kassert!` pending follow-up. +4 hosted tests (pack/unpack roundtrip per arch). |
| #150 | `P1-88-mmuops-wire-pmm` | End-to-end wire-up. `kernel/src/pmm_setup.rs` exposes `pmm_static()` + `alloc_one_frame()` bare fn. Boot path calls `mmu_ops::{set_hhdm_offset, set_frame_alloc}` after PMM init. `device_map_smoke` migrated from `vmm::map_device_4k` to `<X86Mmu/ArmMmu as MmuOps>::map(va, pa, WRITE\|NO_CACHE\|WRITE_THROUGH, P4K)`. MmuOps now used in production by the device-MMIO mapper; trait surface validated end-to-end on both arches via the device bring-up smokes. |

End-of-session-14 verified-green:
- `make lint` clean.
- `make test` → 474 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` — HPET cap reads, LAPIC enable + timer IRQs, preempt + canary smokes; halts clean.
- `make qemu-arm --features debug-all` — GIC enable, PL011 sink swap, CNTV IRQs, preempt + canary smokes; halts clean.

---

## Session 15 (PR #152) — 2026-05-03

**Subject**: MmuOps huge-page support.

| PR | Branch | Lands |
|---|---|---|
| #152 | `P1-89-mmu-huge-pages` | MmuOps huge-page support (2 MiB / 1 GiB). New `PtWalker::pack_block_leaf(pa, flags) -> u64` per arch packs a block leaf (x86 PD/PDPT with PS=1; arm L1/L2 with TABLE bit cleared). New `pt_walker::map_at_level<W,F>(va, leaf_level, leaf, hhdm, alloc)` generic walk-and-install: walker descends levels 0..N-1 allocating intermediates, then writes the pre-packed leaf at the parent table's index. `MmuOps::map` per arch dispatches by `PageSize` (P4K → leaf at L3; P2M → block leaf at L2; P1G → block leaf at L1) with alignment kasserts on `va`/`pa`. Translate / unmap stay 4 KiB only pending a caller. +2 hosted tests in `pt_walker::tests` for 2 MiB and 1 GiB installs. |

End-of-session-15 verified-green:
- `make lint` clean.
- `make test` → 476 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt + canary smokes pass; ticks unchanged from session 14; both reach `boot: kernel ready, halting`.

---

## Session 16 (PR #154) — 2026-05-03

**Subject**: MmuOps translate/unmap recognise huge leaves — completes the trait surface for huge pages.

| PR | Branch | Lands |
|---|---|---|
| #154 | `P1-90-mmu-huge-translate` | After P1-89 added `MmuOps::map` huge-page support, `translate` and `unmap` were still 4 KiB only. New `pt_walker::translate_at_va<W>(va, hhdm) -> Option<(pa, leaf, level)>` walks levels 0..3, stops at the first leaf encountered, and reconstructs the resolved PA as `leaf_pa \| in_leaf_offset`. Rejects huge entries at L0 (512 GiB; not legal in v1). New `pt_walker::unmap_at_va<W>(va, hhdm) -> Option<(leaf, level)>` zeroes the slot at the first leaf + locally TLB-invalidates. `MmuOps::translate` migrated; `MmuOps::unmap` migrated and adds a kassert that the torn-down leaf's level matches the caller's `PageSize`. +2 hosted tests in `pt_walker::tests` covering 2 MiB block-leaf translate round-trip + unmap clear. |

End-of-session-16 verified-green:
- `make lint` clean.
- `make test` → 478 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt + canary smokes pass; ticks unchanged from session 15; both reach `boot: kernel ready, halting`.

End of MmuOps phase: trait surface complete (map/translate/unmap for 4K/2M/1G; flush_va + flush_all_local arch-native). Today's only caller is the device-MMIO mapper (4K-only); broader callers land with the page-fault handler / userspace mmap path.

---

## Session 17 (PRs #156 – #157) — 2026-05-03

**Subject**: MmuOps end-to-end roundtrip smokes (4 KiB + 2 MiB).

| PR | Branch | Lands |
|---|---|---|
| #156 | `P1-91-mmuops-smoke` | Kernel-side MmuOps end-to-end roundtrip smoke. Alloc 4 KiB frame from PMM → `MmuOps::map` at `SCRATCH_VA = 0xffff_fd00_0000_0000` (L4 slot 0x1FD; disjoint from HHDM/device/kernel-image) → write 64-bit magic via the mapped VA → `MmuOps::translate` (verify PA round-trip + R\|W flags) → `MmuOps::unmap` → `MmuOps::translate` (verify None) → log `[INFO] mmuops-smoke: ok pa=... magic=...`. Generic over `M: MmuOps`; per-arch entry chooses `X86Mmu` / `ArmMmu`. Both arches now print the success line every boot. |
| #157 | `P1-92-mmuops-2m-smoke` | Same shape with `PageSize::P2M` and a buddy `Order(9)` PMM allocation. Validates the huge-page MmuOps path landed in P1-89/P1-90 in production. Skips silently if PMM lacks an Order-9 buddy. New `pmm_setup::alloc_contig(order)` helper for the higher-order alloc. Both arches now also print `[INFO] mmuops-smoke 2m: ok pa=... magic=...` every boot. |

End-of-session-17 verified-green:
- `make lint` clean.
- `make test` → 478 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → `mmuops-smoke: ok pa=000000000bf2c000` + `mmuops-smoke 2m: ok pa=000000000dc00000`; preempt + canary smokes pass; halts clean.
- `make qemu-arm --features debug-all` → `mmuops-smoke: ok pa=000000004a6f3000` + `mmuops-smoke 2m: ok pa=000000004e400000`; same.

The MmuOps trait is now exercised in production for both 4 KiB and 2 MiB leaves on every boot, on both arches.

---

## Session 18 (PRs #159 – #164) — 2026-05-03

**Subject**: README + fault-decoder + Task `arch_ctx` + recoverable fault path + latent-bug fix + qemu-mcp tooling. Two attempts (P1-93 kernel-owned GDT, P1-86c PF-recovery smoke) abandoned mid-PR at silent QEMU hangs; the qemu-mcp server (#164) is the unblocker for both in the next session.

| PR | Branch | Lands |
|---|---|---|
| #159 | `C36-readme-ci-badge` | README updated from the Phase-0 placeholder. CI badge wired to `pr.yml` (the workflow extended in C29 to cover default + debug-all on both arches). Status section reflects the current state; `make` quick-start; `state.md` + `CHANGELOG.md` linked from the entry points. |
| #160 | `P1-86a-fault-decode` | Per-arch fault printer decodes vectors + PFEC/ESR/DFSC labels so fault diagnostics are readable at a glance. x86: `vector_label` (Intel SDM Tab. 6-1) + `decode_pfec` (16-way P/W/U/I-fetch label). arm: `ec_label` (ESR_EL1.EC per ARM ARM D17.2.36) + `decode_dfsc` (DFSC sub-field per D17.2.40); for data/insn aborts also emits WnR R/W. Both decoders are `const fn`. +8 hosted tests (4 per arch). |
| #161 | `P1-84-task-arch-ctx-buffer` | Per `13§5`, extend `crates/sched::Task` with `kernel_stack: AtomicPtr<u8>` + `arch_ctx: UnsafeCell<ArchCtxBuf>` where `ArchCtxBuf` is a `#[repr(C, align(8))]` byte buffer of size `sched::ARCH_CTX_SIZE = 128`. Per-arch HAL `Context` types fit by compile-time assert (kernel/src/lib.rs); `Task::arch_ctx_ptr<C>()` cast helper compile-time-checks the size. Opaque-buffer approach (per session-design call); Task stays arch-agnostic; `Arc<Task>` API unchanged. `unsafe impl Sync for Task` documented under the runqueue's single-mutator-per-active-CPU invariant. +3 hosted tests; bumps `make test` 486 → 489. |
| #162 | `P1-86b-fault-recover` | First piece of P1-86 page-fault recovery. Per-arch fault path restructured so an installed handler can recover from a fault by returning `true`; default behaviour (halt) preserved when no handler is installed. `oxide_fault_print_rust` now returns `bool` on both arches. Asm: branches on the return — handled → drop frame + `iretq`/`eret`; not handled → park forever. New `pub type FaultHandler` + `pub unsafe fn install_fault_handler` per arch (atomic swap, returns previous for compose). ARM safety: ELR_EL1/SPSR_EL1 don't need explicit save across the `bl`; DAIF.AIF is masked on entry. |
| #163 | `B07-debug-irq-feature-chain` | Latent fix. xtask `--features debug-all` only applies to packages cargo selects via `-p` (kernel + boot-{arch} + kernel-bin-{arch}); `hal-{x86_64,aarch64}` aren't selected, so their `debug-irq` feature has been silently inactive since #160 added the fault-vector + PFEC/ESR decoder. Chain through the boot crates' `debug-irq`/`debug-all` features so the decoder is actually live in production builds. Found while debugging P1-86c (page-fault recovery), which surfaced the silence. |
| #164 | `C37-qemu-mcp-server` | Interactive QEMU+GDB control surface as an MCP server (`tools/qemu-mcp/server.py`). 13 tools — `qemu_start`/`break`/`continue`/`stepi`/`step`/`finish`/`regs`/`mem`/`disasm`/`backtrace`/`info`/`serial`/`stop`. Pure stdlib + the `mcp` Python package (already on Claude Code's path); spawns QEMU with `-s -S` + `gdb --interpreter=mi3`. Background reader threads drain serial + MI stdout into ring buffers; tool calls block on the GDB reader (30 s timeout) and on `qemu_continue` (120 s for the next `*stopped` event). `.mcp.json` at repo root registers the server for Claude Code auto-load on next session start. `make qemu-mcp` sanity-checks the module imports + lists its tools. |

### Abandoned mid-PR

- **P1-93 kernel-owned x86 GDT** — silent QEMU hang at the `retfq` after `lgdt`. Tried `.byte 0x48, 0xcb` to force 64-bit far-return encoding; still hung. Branch deleted; need gdb-stub single-stepping (now available via #164) to localise.
- **P1-86c page-fault recovery smoke** — handler attached + deliberate fault fired; dispatcher entered twice (proven via an unconditional `[FAULT-ENTRY]` print), then silence. Surfaced #163 (`hal-{arch}/debug-irq` was off in production) as a side artifact. Branch deleted; re-attempt via #164.

End-of-session-18 verified-green:
- `make lint` clean.
- `make test` → 489 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` + `make qemu-arm --features debug-all` — preempt + canary + mmuops smokes pass; ticks unchanged from session 17; both reach `boot: kernel ready, halting`.
- `make qemu-mcp` lists all 13 tools.


---

## Session 23 (PRs #234 – #261) — 2026-05-04

**Subject**: User-authorised autonomous Phase 3 batch. 28 PRs in one run, focused on libc-startup syscall coverage + the path to a real shell.

**Major bug fixes:**
- **#239 B09** — x86 syscall asm was discarding user's rdi/rsi/rdx/r10/r8/r9 across syscalls. Linux ABI preserves them; only rax/rcx/r11 are clobbered. ECHO blob's sys_write after sys_read had garbage args (buf=0x30, len=1016) and hung. Fix: load arg regs via `mov [rsp+N]` without consuming the slots, restore from same slots after dispatch returns. Without this fix, ANY user code reusing arg regs across syscalls breaks (musl libc routinely does).
- **#252 B10** — sys_write validated buf alone but not buf+cnt; matches the P3-11 overflow check now in sys_read.

**Userspace infrastructure:**
- **#235 P2-21c** — SysV initial stack at execve. ParsedElf gains phoff/phentsize/phnum, LoadedImage gains phdr_va. argc/argv*/NULL/envp*/NULL/auxv*/AT_NULL written at the top of the user stack VMA. Auxv carries AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/RANDOM/PLATFORM/EXECFN/UID/GID/etc — needed for static-PIE musl _start. v1 passes empty argv/envp.
- **#236 P3-04** — /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom in dev_misc.rs. LCG-backed random (NOT cryptographic).
- **#240 P3-02b** — init blob extended 2→3 iters, validates ECHO end-to-end.
- **#254 P3-17** — Procfs skeleton via StaticFileInode: /proc/{version,cpuinfo,meminfo,uptime,loadavg,stat,filesystems,mounts,self/maps,self/status} registered into devfs.
- **#256 P3-19** — Static /sys/kernel/random/{uuid,boot_id,entropy_avail}, /sys/devices/system/cpu/{online,possible}, /etc/{os-release,machine-id}.
- **#257 P3-20** — Hand-rolled CAT blob: open("/proc/version") + read(64) + write(fd=1) + close + exit. Init blob extended 3→4 iters. Boot trace ends with `oxide 0.1.0-pre #1 SMP PREEMPT` deterministically — full sys_open + procfs StaticFileInode + multi-byte sys_read + sys_write + sys_close validated end-to-end.
- **#260 P3-23** — PL011 RX on arm. tty.rs is now cross-arch; arm tick_poll_uart drains PL011 RX FIFO; arm ConsoleInode::read uses WAITERS+schedule pattern. arm stdin reaches x86 parity.

**Signal subsystem foundation:**
- **#258 P3-21** — Task gains sigpending+sigmask AtomicU64. sys_kill sets the bit, oxide_syscall_dispatch tail delivers (terminates with status 128+sig). No sa_handler dispatch yet.
- **#259 P3-22** — Real rt_sigprocmask: SIG_BLOCK/UNBLOCK/SETMASK update current.sigmask; SIGKILL+SIGSTOP unmaskable.

**Syscall coverage (24 new + improved):**
fstat/ioctl(TIOCGWINSZ,TCGETS)/getcwd/chdir/fchdir/kill/tgkill (#234), sys_brk (#231 prior), pipe2 (#232 prior), getrandom (#237), sched_yield via tick_yield (#238), gettid+set_tid_address real (#243), nanosleep+clock_nanosleep busy-wait (#248), readlink+readlinkat /proc/self/exe (#249), statx+rseq+membarrier (#250), real fcntl F_DUPFD/F_GETFL etc (#251), sys_read multi-byte uncapped (#247), futex/clone3/mprotect/madvise/prlimit64/rt_sigaction/sigaltstack stubs (#246), writev/readv via fd_table (#241), poll/ppoll/lseek (#245), getrlimit/setrlimit/getrusage/times/sysinfo (#261).

**Splits per docs/08§7 cap (1000 lines):**
- `kernel/src/syscall_glue_fs.rs` (P3-03) for fs-shaped syscalls.
- `kernel/src/syscall_glue_proc.rs` (P3-08) for process-shaped syscalls.
- `kernel/src/dev_misc.rs` (P3-04), `kernel/src/procfs.rs` (P3-17), `kernel/src/exec_stack.rs` (P2-21c).

**State at session-23 EOD:**
- Boot trace x86: `yo\nhi\nA\noxide 0.1.0-pre #1 SMP PREEMPT` deterministically.
- 524 hosted tests, 0 failed.
- spec-lint clean.
- Both arches build clean.
- dev-misc-smoke + procfs-smoke validate boot-time infra.
- arm boots through to elf-smoke + user task per P2-13e (no parity gap).

