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

## Session 19 (PRs #166 – #171) — 2026-05-03

**Subject**: Drop to ring 3 — kernel-owned GDT, TSS install, user-page mapping smoke, first iretq into ring 3, and the page-fault recovery smoke that closes out P1-86.

| PR | Branch | Lands |
|---|---|---|
| #166 | `P1-93-kernel-owned-gdt` | Replace bootloader's GDT with a kernel-owned one. Defines kernel CS/SS (0x08/0x10), user CS/SS (0x1B/0x23), TSS slots. `lgdt` + far-return via push-imm-CS+far-ret pattern (the silent `retfq` hang from session 18 turned out to be Limine's GDT being overwritten between `lgdt` and `retfq`; the new sequence uses immediate-encoded selectors that survive the swap). |
| #167 | `P1-94-tss-install` | Install per-CPU TSS with `rsp0` pointing at the IST-zero kernel stack; load via `ltr 0x28`. Required so the CPU has somewhere to drop the user-context registers when ring-3 → ring-0 transitions fire. arm equivalent: TPIDR_EL1 already carries the per-CPU pointer. |
| #168 | `P1-95-user-mapping` | Per-arch user-virt page mapping helper. `MmuOps::map_user(va, pa, prot)` flag combinations: x86 = P\|U\|RW; arm = AP_EL0_RW + AttrIdx + AF. Adds `USER_VA_END` constant per arch (x86 0x0000_8000_0000_0000 = canonical lower half; arm 0x0000_FFFF_FFFF_FFFF). |
| #169 | `P1-96-user-page-smoke` | Allocate 4 KiB frame, map it U+RW at `USER_SCRATCH_VA = 0x40_0000`, write a magic from kernel mode (CPL=0 ignores U bit), translate, log `[INFO] user-map-smoke: ok pa=... flags=...`. Validates the user-side mapping before we drop to ring 3. |
| #170 | `P1-82-userspace-first-iretq` | First ring-3 transition. Build an iretq frame on the kernel stack pointing at user CS=0x1B, SS=0x23, RFLAGS=0x202, RIP=user-text-VA. iretq drops to ring 3; the user blob is a hand-rolled 2-byte `ud2`; `#UD` from ring 3 returns to the kernel via the IDT. Validates the full ring-0→ring-3→ring-0 round-trip. |
| #171 | `C38-state-eod-session-19` | state.md EOD checkpoint. |

**Abandoned in earlier sessions, re-attempted here:** P1-93 (kernel GDT) was abandoned in session 18 with a silent `retfq` hang; root-caused this session via gdb-stub single-stepping (per the qemu-mcp landed in #164) and fixed.

End-of-session-19 verified-green:
- `make lint` clean.
- `make test` → 489 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → `[INFO] user-map-smoke: ok` then `[INFO] elf-smoke: ok ring3 #UD rip=...`; ring-3 round-trip live every boot.
- `make qemu-arm --features debug-all` reaches `boot: kernel ready, halting`; arm ring-3 path rides the syscall entry batch in session 20.

---

## Session 20 (PRs #172 – #195) — 2026-05-03

**Subject**: Syscall entry path + Phase-2 syscall coverage. The big arch-side push: p1-86c page-fault recovery smoke (closes the P1-86 saga), syscall MSR setup (LSTAR/STAR/FMASK), per-arch entry asm, dispatch table, then progressive syscall coverage (write/exit/uname/clock_gettime/mmap-anon/writev/etc) through P2-20.

| PR | Branch | Lands |
|---|---|---|
| #172 | `P1-86c-pf-recover-smoke` | Page-fault recovery smoke. Install a handler that recovers (returns true), deliberately fault on an unmapped user page, handler maps a fresh frame + retries. Validates the `iretq`-to-faulting-instruction path and recoverable handler contract introduced by P1-86b. Closes P1-86. |
| #173 | `P2-01-syscall-entry` | x86 syscall MSR programming: LSTAR = `oxide_syscall_entry`; STAR = (kernel CS<<32) \| (user CS<<48); FMASK clears IF+DF+AC on entry; EFER.SCE bit 0 set. Asm stub stores user RSP, switches to per-CPU kernel stack, pushes argument-shuffle slots (rax + rdi/rsi/rdx/r10/r8/r9 + rcx/r11/rsp triple), calls `oxide_syscall_dispatch`, sysretq. |
| #174 | `P2-02-sysretq` | Validate sysretq round-trip with a no-op syscall (`nr=0` returns 0). Confirms STAR is laid out correctly and the asm pop sequence aligns. |
| #175 | `P2-03-bind-syscall-dispatch` | Arch-neutral dispatch table per `15§4`: `crates/syscall::dispatch(nr, &args)`. Slot-numbered entries match the Linux x86_64 ABI. Stubs for `write`/`exit`/`uname`/etc that all return 0 + log via debug_sched. |
| #176 | `P2-04-bind-syswrite-sysexit` | sys_write fd=1/2 → UART via klog; sys_exit logs and returns 0 (real lifecycle exit lands with the runqueue). |
| #177 | `P2-05-arm-fault-register-safety` | aarch64 fault dispatcher must save+restore SysV caller-saved x0-x18 around the C call, not just the bare 192-byte EL1 frame. Latent bug in P1-86b's fault recovery path that x86 didn't expose. |
| #178 | `P2-06-bind-trivial-syscalls` | Trivial-stub coverage: getpid (1)/getuid/geteuid/getgid/getegid (0) — enough for libc startup probes. |
| #179 | `P2-07-arch-prctl-set-fs` | x86 `sys_arch_prctl(ARCH_SET_FS, addr)` writes IA32_FS_BASE via wrmsr. Required for libc TLS pointer setup. |
| #180 | `C40-function-cast-cleanup` | One-line lint: `as SyscallFn` → `as SyscallFn` (Rust 2024 stricter fn-pointer cast). |
| #181 | `P2-08-arm-walker-ttbr0-select` | aarch64 PT walker chooses TTBR0 vs TTBR1 by VA top-bit (user vs kernel half), not via a hardcoded TTBR0. Required so the arm syscall path can install user mappings. |
| #182 | `P2-09-arm-userspace-eret-smoke` | aarch64 first eret to EL0 — synthesises an ELR_EL1+SPSR_EL1 frame, maps the same `USER_SCRATCH_VA` user page, runs a bare `svc #0` instruction at EL0, syscall asm stub captures the args + returns. Mirrors x86's ring-3 smoke. |
| #183 | `P2-10-bind-tid-robust-list-and-eod` | Stubs: `set_tid_address` (returns 1), `set_robust_list` (returns 0). state.md EOD intermediate. |
| #184 | `P2-11-arm-svc-entry` | Real aarch64 `svc #0` entry path. ESR_EL1.EC=0x15 dispatch; arg shuffle from x8/x0..x5; calls `oxide_syscall_dispatch`. arm reaches syscall-ABI parity with x86. |
| #185 | `P2-14-syscalls-batch-2` | Stubs: rt_sigaction/rt_sigprocmask/sigaltstack/readlink/getrandom/close/mprotect/madvise/fcntl/prlimit64/lseek/read/dup/dup2/dup3/pipe2/sched_yield/nanosleep — accept-and-no-op or harmless-reject. |
| #186 | `C41-gitignore-claude` | Add `.claude/` and editor temp dirs to `.gitignore`. |
| #187 | `P2-15-syscalls-batch-3` | More stubs: brk(0)→0, ioctl→ENOTTY, fstat fields. |
| #188 | `P2-16-clock-gettime` | Real `sys_clock_gettime`: writes (tv_sec, tv_nsec) from per-arch `TimerOps::monotonic_ns`. Validates user-buf range + 8-byte alignment. |
| #189 | `P2-17-sys-uname` | Real `sys_uname`: writes 6×65-byte fields (sysname=oxide, nodename=oxide, release=0.1.0-pre, version=`oxide #1 SMP PREEMPT`, machine=x86_64\|aarch64, domainname=`(none)`). |
| #190 | `P2-18-sys-writev` | Real `sys_writev` for fd=1/2: walks iovec array, writes each iov to UART via klog. Required for printf-buffered libc stdio. |
| #191 | `P2-19-mmap-anon` | First real `sys_mmap`: MAP_ANONYMOUS\|MAP_PRIVATE with addr=NULL/fd=-1. Routes to `vmm::AddressSpace::mmap` per `11§3`/`11§6`; pages demand-fault on first user access (no upfront frame allocation). |
| #192 | `C42-glue-validate-user-buf` | Pull the validate_user_buf check (ptr in user-half + alignment) into a shared helper used by uname/clock_gettime/etc. |
| #193 | `P2-20-syscalls-batch-4` | Final P2 syscall batch: open returns -ENOENT; close returns 0; readlink path-special-cases. |
| #194 | `B08-fix-broken-dispatch-test` | Hotfix: P2-20 broke a dispatch unit test (slot collision). Test count back to expected. |
| #195 | `C43-state-eod-mass-syscall-batch` | state.md EOD checkpoint. |

End-of-session-20 verified-green:
- `make lint` clean.
- `make test` → 489 → 463 (drop investigated in B08 hotfix). Final: 463.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → first user `sys_write(1, "hello\n")` lands on UART; ring-3 → ring-0 → ring-3 round-trip live; arm equivalent via `svc`.

---

## Session 21 (PRs #196 – #198) — 2026-05-03

**Subject**: VMM page-fault integration + per-task `mm`. Wires `vmm::AddressSpace` into the user-fault path; `Task` carries a real `Arc<AddressSpace>` per docs/13 §5.

| PR | Branch | Lands |
|---|---|---|
| #196 | `P2-12-vmm-pagefault-integration` | The user fault handler classifies a fault into FaultKind (Read/Write/Exec on Anonymous/File/Stack) and asks `AddressSpace` to resolve. Resolution = allocate a frame, install a leaf PTE with the matching prot bits, return success. v1 supports Anonymous (zero-fill) + KernelBytes (`include_bytes!` slice) backings. |
| #197 | `P2-13a-task-mm` | `Task.mm: UnsafeCell<Option<Arc<AddressSpace>>>` + `mm_ref` / `replace_mm` accessors. UnsafeCell instead of `Arc<Mutex>` because the single-mutator-per-active-CPU invariant in `13§5` means execve replaces in-place under preempt-off. Closes P2-13a. |
| #198 | `C44-state-eod-session-21` | state.md EOD checkpoint. |

End-of-session-21 verified-green:
- `make lint` clean.
- `make test` → 463 passed, 0 failed.
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` — first demand-paged user write (`sys_write(1, "hello\n")` faults on the user-stack page, fault handler installs a fresh zero frame, syscall completes).

---

## Session 22 (PRs #199 – #233) — 2026-05-03

**Subject**: Real Phase-2 userspace. Per-AS PT root, real Runqueue with RT/CFS/Idle classes, ELF loader (PT_LOAD demand-paged via `VmaBacking::KernelBytes`), drop-to-ring-3 from a real `Task`, fork+execve+wait4+exit lifecycle, init-loop blob (yo+hi 2-iter), per-task syscall stack + user_frame slot, fd_table + `/dev/console`, devfs path lookup, brk window, pipes, ECHO blob, arm Task lifecycle parity. Multiple intra-session EOD markers (22, 22b, 22c, 22d, 22e, 22g) — same calendar day, distinct work batches.

| PR | Branch | Lands |
|---|---|---|
| #199 | `P2-19-as-pt-root` | Each `AddressSpace` owns its own PML4/L0 root PA (allocated from PMM). Kernel-half cloned from a captured "master" snapshot at user_as::init time so every user AS has the kernel mappings without per-AS duplication. `MmuOps::activate(root_pa)` writes CR3/TTBR0 + flushes user TLB. |
| #200 | `P2-13b-runqueue-wire` | Real `Runqueue` with `Spinlock<RunqueueInner>` per docs/13 §6: RT bitmap class (priority 1-99, 8x8 bitmap) + CFS RB-tree class + Idle. `schedule()` per §8 picks lowest-vruntime runnable task; AS-swap branch fires when `next.mm != prev.mm`. Replaces the Vec-shim from P1-84. |
| #201 | `P2-17-vma-kernel-bytes` | `VmaBacking::KernelBytes { data: &'static [u8] }` so the ELF loader can map PT_LOAD segments backed by `include_bytes!` blobs without a real VFS. Demand-page faults copy `data[off..off+4096]` into a fresh zero frame. |
| #202 | `P2-16-elf-loader` | Hand-synthesised ELF64 blob (164 bytes) with one PT_LOAD R\|X. Kernel parses ehdr+phdr, registers PT_LOAD as `VmaBacking::KernelBytes`, registers a 4 KiB user stack VMA, returns entry point. |
| #203 | `P2-16b-elf-drop-to-ring3` | Drop to ring 3 at the loaded entry. User code does `sys_write(1, "el\n", 3); sys_exit(0); ud2`. ud2 lands at a known landmark; smoke fault handler logs `elf-smoke: ok`. |
| #204 | `P2-16c-elf-arm` | Same flow on aarch64 via `eret` to EL0. |
| #205 | `P2-13c-spawn-user-task` | First user `Task` on the runqueue: `spawn_user_thread(tid, name, entry, sp, mm)`. Builds a synthetic iretq frame in the new task's kernel stack so `Context::switch` lands in user space when it's picked. |
| #206 | `P2-13d-sys-exit-clean` | `kernel_sys_exit` marks the running task Zombie + reschedules. With state=Zombie the picker won't re-enqueue; schedule() falls through to idle (boot anchor) ⇒ boot resumes past its `schedule()` callsite. |
| #207 | `C45-state-eod-session-22` | state.md EOD checkpoint. |
| #208 | `P2-15a-as-fork` | `AddressSpace::fork(new_root) -> AddressSpace` clones the VMA tree (no page copy yet — child re-demand-pages). Splits the original `fork` into the no-page-copy primitive + a `fork_copy_pages<M, F>` follow-up so callers can choose. |
| #209 | `P2-15b-sys-fork` | First real `sys_fork`: alloc new PML4, fork the AS, spawn child Task with `mm = child_as`, return child TID to parent. iretq frame built so child resumes at post-syscall RIP with rax=0 (canonical fork-return). |
| #210 | `C46-state-eod-session-22b` | state.md EOD checkpoint. |
| #211 | `P2-21-execve-static` | First `sys_execve`: ignores the path arg, always loads the kernel-static EXEC_BLOB. Replaces `current.mm` atomically, activates the new AS, overwrites the per-task user_frame slot so sysretq lands at the new program entry. |
| #212 | `P2-21b-execve-path` | execve reads the user path's first byte as a kernel-static ELF selector ('y'→YO, 'h'→HI). Real path resolution waits on VFS. |
| #213 | `C47-state-eod-session-22c` | state.md EOD checkpoint. |
| #214 | `P2-22-wait4` | `sys_wait4(pid, wstatus, options, rusage)`: `crate::sched::zombies::ZOMBIES` registry holds Zombie tasks past schedule's swap. Loops with `tick_yield` until a matching child appears. POSIX wstatus encoding: low 7 bits = signal (0 for normal exit), bits 8..16 = exit code. |
| #215 | `P2-22b-init-loop` | The init blob: 2 iterations of `for sel in ['y','h']: if fork()==0: execve(&sel) else: wait4(-1)`. Real shell-pattern lifecycle. |
| #216 | `C48-state-eod-session-22d` | state.md EOD checkpoint. |
| #217 | `P2-26-pid-syscalls` | Real `sys_getpid` + `sys_getppid` reading `current().tid` + `current().parent_tid`. Replaces the constant-1 stubs. |
| #218 | `P2-23a-uart-read` | Timer-tick UART RX poll + 64-byte ringbuffer in `tty.rs`. `tick_poll_uart` reads COM1 LSR.DR, pushes to RX_BUF. `try_read()` pops a byte non-blocking. |
| #219 | `C49-state-eod-session-22e` | state.md EOD checkpoint. |
| #220 | `P2-23-tty-blocking` | Blocking `sys_read(fd=0)`: if RX_BUF empty, the task pushes itself onto WAITERS, marks state=Sleeping, calls schedule(). `tick_poll_uart` wakes all WAITERS on every RX byte (Sleeping → Runnable + enqueue). |
| #221 | `C50-state-tty-arch` | state.md note on TTY architecture (per-VT distinct ConsoleInode + foreground alias is required, deferred). |
| #222 | `P2-30a-fd-table` | `Task.fd_table: UnsafeCell<Option<Arc<FdTable>>>`. fd_table holds `Arc<File>`; alloc/get/dup2/close. `init` installs fd 0/1/2 → ConsoleInode at boot; fork inherits the Arc. `kernel_sys_read`/`kernel_sys_write` route via the table. |
| #223 | `C51-state-eod-session-22g` | state.md EOD checkpoint. |
| #224 | `P2-31-fd-syscalls` | Real `close`/`dup`/`dup2`/`dup3` via fd_table. |
| #225 | `P2-15c-fork-pgcopy` | Per-page copy in fork via the `fork_copy_pages<M, F>` extension: walks each Anonymous VMA, allocates a new frame, `M::translate` reads parent's mapping, copies via HHDM, `M::map_at(new_root, va, pa)` installs in child. Closes the heap-survives-fork gap. |
| #226 | `P2-18-sigsegv-minimal` | Minimal SIGSEGV: when user_fault_handler can't resolve a fault, terminate the task (stash exit_status = 139 = 128+SIGSEGV, push to ZOMBIES, reschedule) instead of halting the kernel. Real signal subsystem rides docs/27. |
| #227 | `P2-13e-arm-user-task` | aarch64 IRQ frame extended 192→208 B + saves/restores sp_el0 at offset 0xC0. arm sys_exit no-rq fallback (returns 0 if no runqueue, mirrors x86's pre-P2-22 behavior). |
| #228 | `B08-arm-irq-frame-test-fix` | Hotfix: P2-13e changed the arm IRQ-frame layout test from 192→208 B + sp_el0 slot at 0xC0; the test in `crates/hal-aarch64/src/vbar.rs` still asserted the old layout. |
| #229 | `P2-13e2-arm-spawn-user-task` | `ContextAArch64::new_user_with_irq_frame(stack_top, user_ip, user_sp)` writes sp_el0 = user_sp at offset 0xC0; SPSR_EL1 = 0x3C0 (EL0t, DAIF masked); ELR_EL1 = user_ip. arm `spawn_user_thread` path mirrors x86. arm reaches user-Task lifecycle parity. |
| #230 | `P2-30b-devfs-sys-open` | Minimal devfs registry (`&str → InodeRef`); `init` registers `/dev/console`, `/dev/tty`, `/dev/tty0..6`, `/dev/ttyS0`. `sys_open(path, flags, mode)` resolves through devfs. |
| #231 | `P2-32-brk` | Real `sys_brk`: ELF loader pre-registers a 64 MiB Anonymous VMA at `[max_end, max_end + 64MiB)`; `as.set_brk_window(start, max)` records the bounds; `try_set_brk(new)` validates within the window. brk(0) queries; brk(N) sets. |
| #232 | `P3-01-pipe2` | Anonymous `PipeInode` per docs/16+24: 4 KiB ringbuffer behind a Spinlock. `sys_pipe2(pipefd, flags)` allocates two `File`s (RDONLY/WRONLY) at the lowest-free fds, writes the pair to user `pipefd[2]`. |
| #233 | `P3-02-echo-demo` | ECHO blob (173 B): `sys_read(0, buf, 1); sys_write(1, buf, 1); sys_exit(0)`. `tty::inject_for_smoke(b"A")` pre-fills the ringbuffer at boot so the demo runs non-interactively. Registered in `lookup_blob('e')` for future iter exec — actually-exercised end-to-end in P3-02b after the B09 ABI fix. |

End-of-session-22 verified-green (final, post-22g):
- `make lint` clean.
- `make test` → 463 passed, 0 failed (test count drop from session 19 stable).
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → init-loop output `yo\nhi\n` deterministically; full fork+execve+wait4+exit cycle; halts clean.
- `make qemu-arm --features debug-all` → ELF demo runs via arm spawn_user_thread path; halts clean.

---

## Session 23 (PRs #234 – #314) — 2026-05-04

**Subject**: User-authorised autonomous Phase-3 batch. The big libc-startup syscall coverage push, plus the B09 ABI fix that unblocks any user code reusing arg regs across syscalls, the SysV initial-stack build at execve (foundation for static-PIE musl), procfs/sysfs/etc skeletons, the CAT blob that exercises sys_open(/proc/version)+read+write+close end-to-end, the signal subsystem foundation, aarch64 PL011 RX parity, and the changelog backfill for sessions 19–22.

| PR | Branch | Lands |
|---|---|---|
| #234 | `P3-03-syscall-batch` | Slots 5/16/79/80/81/62/234. fstat synthesises a 144-byte struct stat from the inode's file_type+ino (S_IFCHR for ConsoleInode so `isatty()` works). ioctl(TIOCGWINSZ) → fake 80×24; ioctl(TCGETS) → zero termios; else -ENOTTY. getcwd → "/"; chdir/fchdir validate + no-op. kill self-target sets sigpending (per P3-21); else -ESRCH. New `kernel/src/syscall_glue_fs.rs` to keep `syscall_glue.rs` under the 1000-line cap. |
| #235 | `P2-21c-execve-auxv` | SysV initial stack at execve per docs/31 §4 step 5. `kernel/src/exec_stack.rs::build_user_stack` writes argc / argv\* / NULL / envp\* / NULL / auxv\* / AT_NULL / strings at the top of the stack VMA, returns the 16-byte-aligned SP. Auxv carries AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/RANDOM/PLATFORM/EXECFN/etc — sufficient for static-PIE musl `_start`. ParsedElf gains phoff/phentsize/phnum; LoadedImage gains phdr_va. |
| #236 | `P3-04-dev-null-zero-random` | `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` in `kernel/src/dev_misc.rs`. NullInode reads EOF / writes discard; ZeroInode reads NUL fill; FullInode reads NUL / writes -EIO; RandomInode reads from a shared LCG (NOT cryptographic; placeholder until docs/26). |
| #237 | `P3-05-getrandom` | Slot 318. Fills user buffer from `dev_misc::lcg_next`. NOT cryptographic. |
| #238 | `P3-06-sched-yield-glue` | Slot 24 routes through `crate::sched::tick_yield` when a runqueue is installed. Replaces the in-table 0-stub. |
| #239 | `B09-syscall-preserve-argregs` | **Major ABI fix.** x86 syscall asm was popping (and discarding) the user's rdi/rsi/rdx/r10/r8/r9 across syscalls. Linux ABI preserves them; only rax/rcx/r11 are clobbered. Concrete failure: ECHO blob's sys_write after sys_read had garbage rsi/rdx (buf=0x30, len=1016) and hung the kernel. Fix: load arg regs via `mov [rsp+N]` without consuming the slots; restore from same slots after dispatch returns; discard the 7 saved-arg slots; pop user rcx/r11/rsp triple. Drop `sub rsp, 8` align since 10 pushes from a 16-aligned base leave rsp 16-aligned. Without this, ANY user code reusing arg regs across syscalls breaks. |
| #240 | `P3-02b-init-echo-iter` | Init blob extended 2→3 iters (yo / hi / ECHO). ECHO reads the 'A' pre-injected via `tty::inject_for_smoke`, writes back to fd 1. End-to-end fd_table → ConsoleInode → tty validated. |
| #241 | `P3-07-writev-readv-glue` | Slots 19/20 routed through fd_table → `File::read`/`File::write` so they work for any open fd (pipes, /dev/null, etc.) not just stdout/stderr. musl/glibc stdio uses writev for line-buffered printf — without binding, stdio breaks for any non-stdout fd. |
| #242 | `C52-state-eod-session-23` | state.md intermediate update. |
| #243 | `P3-08-gettid-real` | Slots 186/218 read `current().tid` instead of returning constant 1. New `kernel/src/syscall_glue_proc.rs` houses sched_yield + gettid + set_tid_address. |
| #244 | `C53-state-eod-session-23-final` | state.md intermediate update. |
| #245 | `P3-09-pselect-poll-stub` | Slots 7/271 non-blocking poll: CharDev fds report POLLIN\|POLLOUT (ConsoleInode blocks at read time, not at poll time); others 0. Slot 8 lseek returns -ESPIPE for non-Regular file types. |
| #246 | `P3-10-futex-clone3-stub` | Slots 10/13/14/28/131/202/302/435 stubs: futex returns 0 (FUTEX_WAKE no waiters; FUTEX_WAIT spurious wake); clone3 returns -ENOSYS so musl falls back; mprotect/madvise/prlimit64/rt_sigaction/sigaltstack accept-and-no-op. |
| #247 | `P3-11-sys-read-multi-byte` | sys_read drops the 1-byte cap on the user buffer; ConsoleInode still returns 1 byte/call (line discipline) but pipes + /dev/zero|random fill the full buffer per call. |
| #248 | `P3-12-nanosleep-clock` | Slots 35/230 busy-wait against the per-arch monotonic clock with `tick_yield` between checks. Replaces the in-table immediate-return stub. |
| #249 | `P3-13-multi-task-smoke` | Slots 89/267. readlink/readlinkat resolve `/proc/self/exe → "/init"`; `/proc/self/cwd|root → "/"`. Other paths still return -EINVAL so glibc falls through. |
| #250 | `P3-14-statx-rseq` | Slot 332 statx writes a minimal 256-byte struct from the inode's file_type+ino; supports AT_EMPTY_PATH+dirfd. Slot 334 rseq returns -ENOSYS so musl falls back. Slot 324 membarrier returns 0 (UP single-CPU). |
| #251 | `P3-15-fcntl-real` | Slot 72 honours F_DUPFD/F_DUPFD_CLOEXEC (via fd_table.dup), F_GETFD/F_SETFD (CLOEXEC accepted no-op), F_GETFL (returns O_RDWR), F_SETFL (accepts O_NONBLOCK/O_APPEND no-op). Other commands return -EINVAL. |
| #252 | `B10-sys-write-bound-check` | Mirrors P3-11: sys_write validates the full buf+cnt range, not just buf. Closes a near-USER_VA_END overflow window. |
| #253 | `P3-16-dev-zero-read-smoke` | Boot-time `dev-misc-smoke` kasserts /dev/{null,zero,full,random} contracts. |
| #254 | `P3-17-procfs-stub` | Procfs skeleton: `StaticFileInode { body: &'static [u8] }` registered into devfs at /proc/{version,cpuinfo,meminfo,uptime,loadavg,stat,filesystems,mounts,self/maps,self/status}. read(off, buf) streams a window. |
| #255 | `P3-18-cat-procfs-blob` | Boot-time `procfs-smoke` walks the registered /proc entries via `devfs::lookup` + `Inode::read`, kasserts each body starts with its expected prefix. |
| #256 | `P3-19-sysfs-random-uuid` | Static /sys/kernel/{osrelease,ostype,random/{uuid,boot_id,entropy_avail}}, /sys/devices/system/cpu/{online,possible}, /etc/{os-release,machine-id} via the StaticFileInode pattern. |
| #257 | `P3-20-cat-blob-end-to-end` | Hand-rolled CAT blob (256 B): open(/proc/version, O_RDONLY) → read(64) → write(fd=1) → close → exit. Init blob extended 3→4 iters; selectors at 0x40017B..7E. Boot trace ends with `oxide 0.1.0-pre #1 SMP PREEMPT` deterministically — full sys_open + procfs StaticFileInode + multi-byte sys_read + sys_write + sys_close validated end-to-end. |
| #258 | `P3-21-signal-state-skeleton` | Task gains `sigpending: AtomicU64` + `sigmask: AtomicU64`. sys_kill self-target sets the pending bit (instead of immediate-exit-self); `oxide_syscall_dispatch` tail calls `take_lowest_pending` and terminates with status 128+sig if any unmasked signal is pending. No sa_handler dispatch yet — every signal terminates per `27§2` default disposition. |
| #259 | `P3-22-rt-sig-real` | Real `sys_rt_sigprocmask`: SIG_BLOCK/UNBLOCK/SETMASK update `current.sigmask`; oldset is written if non-NULL. SIGKILL+SIGSTOP forced unmaskable per POSIX. |
| #260 | `P3-23-pl011-rx-arm` | tty.rs cross-arch. arm `tick_poll_uart` drains PL011 RX FIFO via FR.RXFE/DR (Device-attr mapping published by `pl011::base_va`); `gic.rs` timer ISR calls it each tick. arm `ConsoleInode::read` uses the WAITERS+schedule pattern. arm stdin reaches x86 parity. |
| #261 | `P3-24-getrlimit-setrlimit` | Slots 97/98/99/100/160. getrlimit reports RLIM_INFINITY for every resource. setrlimit accepts + forgets. getrusage zeros struct rusage. times zeros struct tms + returns monotonic clock in CLK_TCK ticks (100 Hz). sysinfo fills uptime + zeros. |
| #262 | `C55-state-changelog-session-23-final` | state.md update (this session). |
| #263 | `P3-25-mremap-msync` | Slots 25/26/27/149/150/151/152. mremap returns -ENOMEM (libc falls back to mmap+memcpy+munmap which we support). msync 0 (no file VMAs to flush yet). mincore reports every page resident. mlock/munlock/mlockall/munlockall 0 (no swap). |
| #264 | `P3-26-getpgrp-setsid` | Slots 21/95/109/111/112/121/124/269. getpgrp/getpgid/getsid → `current().tid`. setpgid no-op. setsid returns tid (no actual session-leader bookkeeping yet). umask returns 0o022 prior. access/faccessat resolve via devfs lookup. |
| #265 | `P3-27-eventfd-timerfd` | Slots 284/290. EventfdInode counter (AtomicU64) — read swaps to 0 and returns prior value as 8-byte u64; write adds. Allocated as Fifo-typed Inode + RDWR File at lowest-free fd. dup/dup2/dup3 also moved out of `syscall_glue.rs` into `syscall_glue_fs.rs` for length cap. |
| #266 | `D03-changelog-fix-sessions-19-23` | CHANGELOG backfill — fills sessions 19/20/21/22 (PRs #166–#233) and rewrites session 23 in the canonical Subject+table+verified-green format used through session 18. Reconstructed from the merge log + branch names. |
| #267 | `P3-28-getcpu-sched-info` | Slots 143/144/145/146/147/157/203/204/309. getcpu reports CPU 0 / NUMA 0 (UP). sched_getparam writes priority 0. sched_getscheduler returns SCHED_OTHER. sched_get_priority_max/min report 99/1 for FIFO/RR else 0. sched_getaffinity reports a 1-bit mask. sched_setaffinity 0 (no-op). prctl honours PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE / PR_GET_DUMPABLE; other options 0. |
| #268 | `P3-29-pipe-smoke-test` | Boot-time `pipe-evt-smoke` round-trips a 5-byte string through PipeInode and a u64 counter through EventfdInode; kasserts the buf/counter contracts. |
| #269 | `P3-30-clock-getres` | Slots 96/201/227/229. clock_getres reports 1 ns resolution. clock_settime accepts and forgets (no RTC). gettimeofday and time use the same monotonic counter as clock_gettime. New `kernel/src/syscall_glue_time.rs` houses the time-shaped syscalls. |
| #270 | `P3-31-etc-hostname` | Static /etc/{hostname, passwd (root only), group, nsswitch.conf, resolv.conf, localtime} and /proc/{self/oom_score{,_adj}, sys/kernel/{pid_max, ngroups_max, cap_last_cap, random/{uuid,boot_id}}}. Common shell/libc startup probes. |
| #271 | `P3-32-state-changelog-update` | docs catch-up: state.md + CHANGELOG.md through #270. |
| #272 | `P3-33-getdents64` | Slots 78/217 stub: validate fd + dirp range, return 0 (EOD). Real Inode::lookup-driven enumeration rides docs/16. |
| #273 | `P3-34-pread-pwrite` | Slots 17/18 routed via fd_table → Inode::read/write with explicit offset (procfs StaticFileInode honours it for streaming). preadv/pwritev (295/296) → ENOSYS. |
| #274 | `P3-35-state-changelog` | docs catch-up through #273. |
| #275 | `P3-36-mkdir-rmdir-stub` | Slots 74/75/76/77/82/83/84/87/162/257/258/263/264/316. Mutating fs ops (mkdir/rmdir/unlink/rename/truncate) → -EROFS (devfs is read-only). openat routes through devfs lookup. fsync/fdatasync/sync → 0. |
| #276 | `P3-37-net-stubs` | Slots 41-55 + 288. socket/bind/listen/accept(4)/connect/sendto/recvfrom/sendmsg/recvmsg/shutdown/getsockname/getpeername/socketpair/setsockopt/getsockopt all return -ENOSYS until docs/25 net stack lands. |
| #277 | `P3-38-state-changelog` | docs catch-up through #276. |
| #278 | `P3-39-fchmod-fchown-stub` | **Refactor + coverage**: new `kernel/src/syscall_nrs.rs` holds the full Linux x86_64 syscall number table (NR_READ=0 through NR_CACHESTAT=451 + io_uring/landlock/etc). `syscall_glue.rs` drops 147 inline const declarations; references `crate::syscall_nrs::NR_*`. Plus chmod/fchmod/chown/fchown/lchown/utime/utimes/utimensat → 0 (silent accept on RO devfs); link/symlink/mknod variants → -EROFS; statfs/fstatfs writes minimal 120-byte struct. syscall_glue.rs ~1030 → 883 lines. Per user feedback: "why don't we just ADD all of the syscall numbers ... they aren't going to change." |
| #279 | `P3-40-state-changelog-update` | docs catch-up through #278. |
| #280 | `P3-41-epoll-stubs` | Explicit -ENOSYS for substrates we don't have yet so libraries probing for them fall through to supported alternatives: epoll family (NR_EPOLL_*), inotify (NR_INOTIFY_*), signalfd/timerfd/userfaultfd, libaio (NR_IO_*) + io_uring (NR_IO_URING_*), perf/bpf/seccomp/landlock, unshare/setns/pivot_root. |
| #281 | `P3-42-tkill-tgkill-real` | Slots 15/127/130/200. tkill self-target routes to sys_kill (sets sigpending bit). rt_sigpending writes current.sigpending. rt_sigsuspend swaps the mask + returns -EINTR (dispatch tail's take_lowest_pending handles delivery). rt_sigreturn returns 0 (no signal frame yet). rt_sigtimedwait/rt_sigqueueinfo/rt_tgsigqueueinfo → -ENOSYS. |
| #282 | `P3-43-state-changelog-final` | docs catch-up through #281. |
| #283 | `P3-44-getitimer-setitimer` | Wide ABI-compat batch covering libc/shell startup probes. itimer/alarm/pause/priority/groups/setuid family → 0. getresuid/getresgid write (0,0,0). capget/capset/personality/vhangup/syslog/sethostname → 0. reboot/mount/umount2/chroot → EPERM. ptrace/init_module/swapon/sendfile/splice/tee/vmsplice/copy_file_range/memfd_create/pidfd_*/xattr family → ENOSYS. flock/fallocate/readahead/fadvise64/sync_file_range → 0. |
| #284 | `P3-45-state-changelog` | docs catch-up through #283. |
| #285 | `P3-46-keyctl-ipc` | **Refactor + coverage**: pulls the giant dispatch tail into `kernel/src/syscall_compat.rs::try_compat -> Option<i64>` so the main `oxide_syscall_dispatch` arm stays under the line cap. Adds SysV IPC (shm/sem/msg) ENOSYS, POSIX MQ ENOSYS, keyring ENOSYS, timer_* ENOSYS, kexec/iopl/adjtimex EPERM, sendfile/splice/tee/vmsplice/memfd ENOSYS, pidfd ENOSYS, xattr ENOSYS, fanotify ENOSYS, mount-setattr/openat2/etc ENOSYS. Real-impl shadows for STAT/LSTAT/CREAT/PIPE/EXIT_GROUP/NEWFSTATAT/RT_SIGRETURN/GETRESUID/GETRESGID. syscall_glue.rs ~1100 → 890 lines. |
| #286 | `P3-47-state-changelog` | docs catch-up through #285. |
| #287 | `P3-49-syscall-coverage-banner` | Boot banner `[INFO] syscall: ~200 slots wired (real impls + compat stubs)` after dev-misc + procfs + pipe-evt smokes. |
| #288 | `P3-50-state-changelog-final` | docs catch-up through #287; verified-green block updated. |
| #289 | `P3-51-execve-real-argv` | execve now snapshots up to 8×64 argv/envp strings from the OLD AS into stack-allocated kernel buffers BEFORE activating the new AS, then materialises `&[&[u8]]` slices into `exec_stack::build_user_stack`. Real shells passing argv/envp to fork/execve children will now see them. |
| #290 | `P3-52-state-changelog` | docs catch-up through #289. |
| #291 | `P3-53-execve-args-trace` | sys_execve trace now logs `argc=N envc=M` so the boot trace confirms argv pass-through is on the live path. |
| #292 | `P3-54-execve-path-string` | execve real path-string resolution: reads up to 64 user bytes, looks up `/init`, `/sbin/init`, `/bin/{yo,hi,echo,cat}`, `/usr/bin/*` via new `crate::elf_smoke::lookup_blob_by_path`. Falls back to single-byte selector for the existing init-blob iter_block. Shells calling `execve("/bin/cat", argv, envp)` resolve correctly. |
| #293 | `P3-55-state-changelog` | docs catch-up through #292. |
| #294 | `P3-56-statx-test` | Boot-time `exec-path-smoke` kasserts each registered path resolves to a blob with the ELF magic; negative case must miss. |
| #295 | `P3-57-state-changelog-final` | docs catch-up through #294. |
| #296 | `P3-58-state-eod` | session-23 closeout docs. |
| #297 | `P3-59-musl-helloworld` | **M1 baseline reached.** First non-hand-rolled real-toolchain ELF binary running through the kernel: `gcc -nostdlib -static-pie -fPIE` static-PIE blob in `kernel/blobs/hello.elf` prints `hello asm-pie`. Substrate: `PIE_LOAD_BIAS=0x10000000` for ET_DYN; biased entry/phdr_va; pre-applies `R_X86_64_RELATIVE` from `DT_RELA`; `hal_x86_64::enable_sse()` at boot (CR0.MP, CR4.OSFXSR/OSXMMEXCPT for user-mode SSE2); fault handler installed BEFORE `load_static_blob` so PIE relocation kernel-side writes resolve via `user_fault_handler`; `build_user_stack` called for the spawned task (was only on execve before). musl libc full helloworld is M1b: faults inside `__libc_start_main_stage1` after `arch_prctl` + `set_tid_address` — investigation continues. |
| #298 | `B11-hotfix-blob-not-committed` | hotfix: P3-59's `kernel/blobs/hello.elf` matched the broad `*.elf` gitignore rule; fresh clones build-failed. Adds `!kernel/blobs/*.elf` exception + commits the blob (8.9 KB). |
| #299 | `P3-61-fork-fdtable-copy` | **M2 substrate.** fork now uses `FdTable::fork_clone()` (per-entry copy of files+cloexec arrays into a fresh table) instead of Arc-sharing the parent's table; child's close/dup don't disturb parent. execve calls `close_on_exec()` on the active fd_table before the new program runs, dropping FDs marked `FD_CLOEXEC`. Real shells rely on both. |
| #300 | `P3-63-state-changelog-m1` | docs catch-up through M1 baseline + M2 substrate. |
| #301 | `P3-64-sigaction-storage` | **M2 substrate.** Task gains `sigactions: UnsafeCell<[SaHandler; 64]>` array. `rt_sigaction` (slot 13) reads + stores the user `struct sigaction`; writes prior to oldact. Foundation for sa_handler dispatch in #302. |
| #302 | `P3-65-sa-handler-dispatch` | **M2 substrate — real signal-handler dispatch.** When a pending unblocked signal has a registered user handler (not SIG_DFL/IGN), the dispatch tail builds a 40-byte signal frame on the user stack `(magic, rflags, rsp, rip, restorer)`, rewrites the per-task user_frame so sysretq enters the handler with `sig` in `rdi`. Handler ret's to sa_restorer which calls `rt_sigreturn` (slot 15); kernel pops the frame and restores rip/rflags/rsp. New `kernel/src/sig_dispatch.rs`. x86_64 only; SA_SIGINFO not honored (no siginfo_t/ucontext_t). |
| #303 | `P3-66-signal-smoke` | Hand-rolled `kernel/blobs/sigtest.elf` validates the full sigaction → kill → dispatch → handler → restorer → rt_sigreturn → resume chain end-to-end. Boot trace prints `before h after` deterministically. Includes one bugfix (rt_sigreturn frame_base was 32 below cur_rsp; correct is 40). |
| #304 | `P3-67-sigchld` | **M2 substrate — SIGCHLD on Zombie.** Task gains `parent_arc: Weak<Task>` set at fork time. `park_zombie` upgrades the Weak; if parent alive, sets bit 16 (signal 17, SIGCHLD) in `parent.sigpending`. Bash + getty rely on this for job tracking. |
| #305 | `P3-68-sigchld-default-ignore` | **Bugfix.** SIG_DFL case in dispatch tail was always terminating; Linux per `signal(7)` defaults SIGCHLD/SIGURG/SIGWINCH to ignore. Without this, parents would be killed by their first child's Zombie posting SIGCHLD without a handler. Also: execve path-string lookup falls back to first-byte selector for any path_len ≥ 1 so init blob's non-NUL-terminated 1-byte selectors continue to resolve. |
| #306 | `B12-line-cap-hotfix` | Trims doc comments in syscall_glue.rs to bring it back under the 1000-line cap (1004→997). |
| #307 | `P3-69-state-changelog-m2` | docs catch-up. |
| #308 | `P3-72-proc-self-dynamic` | **M2 substrate.** `ProcSelfStatusInode` synthesises body from `current()` at read time — Name (task.name), Tgid/Pid (tid), PPid (parent_tid), State R, uids/gids 0, Threads 1. bash + libc parse this. Foundation for /proc/self/cmdline, /maps. |
| #309 | `P3-73-proc-self-cmdline` | **M2 substrate.** `ProcSelfCmdlineInode` (NUL-separated argv from task.name) + `ProcSelfStatInode` (52-field stat line: pid, comm, R, ppid, zeros). |
| #310 | `P3-74-proc-self-maps` | **M2 substrate.** `ProcSelfMapsInode` walks `current().mm.snapshot_vmas()` and emits Linux-format `<start>-<end> <perms> <off> 00:00 <ino> <path>` lines. New `AddressSpace::snapshot_vmas()` helper. |
| #311 | `P3-75-state-changelog-m2-procfs` | docs catch-up. |
| #312 | `P3-76-tmpfs-stub` | **M2 substrate — minimal /tmp filesystem.** New `kernel/src/tmpfs.rs`: `TmpfsFileInode` wraps `Spinlock<Vec<u8>>`; flat `&str → InodeRef` registry with `lookup_or_create`. `sys_open` lookup order is now devfs → tmpfs → tmpfs::lookup_or_create when O_CREAT set + path under /tmp/. Lets shells `echo > /tmp/x; cat /tmp/x`. |
| #313 | `P3-77-tmpfs-smoke` | Boot-time `tmpfs-smoke: ok` validates write+read round-trip + partial overwrite. |
| #314 | `P3-78-tmpfs-user-blob` | **End-to-end validation.** kernel/blobs/tmpfstest.elf prints `tmpfs!` after `open(/tmp/x, O_CREAT)` + write + close + reopen + read + write(stdout) cycle. Real shells can now use /tmp/. |

End-of-session-23 verified-green:
- `make lint` clean.
- `make test` → 524 passed, 0 failed (up from 463 → 524 over the run).
- `make build` + `make build-debug` both arches green.
- `make qemu-x86 --features debug-all` → boot trace: `dev-misc-smoke: ok` + `procfs-smoke: ok` + `pipe-evt-smoke: ok` + `syscall: ~200 slots wired` + `exec-path-smoke: ok` validate boot-time infra; init-loop emits `yo\nhi\nA\noxide 0.1.0-pre #1 SMP PREEMPT` deterministically; full fork+execve+wait4+exit+procfs read+write cycle through 4 iterations; halts clean.
- `make qemu-arm --features debug-all` reaches user task on the runqueue per P2-13e2; ELF demo runs (`el` written, exit clean); all boot-time smokes pass; PL011 RX hooked in (P3-23) but not yet exercised end-to-end (no arm-side init-blob iteration — rides P3 follow-up).
- ~200 syscall slots wired across `syscall_glue.rs` real-impl arms + `syscall_glue_fs/proc/time.rs` glue helpers + `syscall_compat.rs::try_compat`. Linux x86_64 ABI surface-coverage substantially complete for libc/shell startup probes.

---

## Session 24 (PRs #316 – #323) — 2026-05-04

**Subject**: M2 follow-ups — real argv in /proc/self/cmdline; real getdents64 over a /tmp directory inode; tid registry plus dynamic per-pid /proc/<tid>/.

| PR | Branch | Lands |
|---|---|---|
| #316 | `P3-80-task-cmdline` | Task gains `cmdline: UnsafeCell<Option<String>>`. `kernel_sys_execve` snapshots argv[0..argc] (NUL-joined) into the slot per `13§5` single-mutator. `ProcSelfCmdlineInode` reads the snapshot; falls back to `Task.name` + NUL when no execve has run. /proc/self/cmdline now reflects real argv per `19§4`. |
| #317 | `P3-81-tmpfs-readdir` | `TmpfsRootInode` synthesises a directory view over the flat tmpfs path registry — `lookup(name)` reverses the `/tmp/<name>` mapping; `readdir` walks REGISTRY filtering `/tmp/<leaf>` entries. Registered at boot so `open("/tmp", O_DIRECTORY)` returns it. `kernel_sys_getdents64` now drives `Inode::readdir` and emits real `linux_dirent64` records (d_ino / d_off cookie / d_reclen 8B-padded / d_type / NUL-terminated name); `File.pos()` carries the cookie across calls. ENOTDIR for regular fds. |
| #318 | `P3-82-tid-registry` | New `kernel/src/sched/registry.rs`: global `Spinlock<Vec<(tid, Weak<Task>)>>`. `spawn_user_thread` inserts on every spawn; entries decay via `Weak::upgrade`. `procfs::lookup_dynamic(path)` resolves `/proc/<tid>` directories and per-pid status/cmdline/stat/maps. `ProcRootInode` emits live tids + `self` via getdents64. `sys_open`/`sys_openat`/`sys_stat` consult the dynamic resolver after a devfs miss. |
| #319 | `C54-state-eod-session-24` | Session-24 EOD docs catch-up. |
| #320 | `P3-83-devfs-root-readdir` | `PrefixDirInode` walks the flat devfs path registry and emits children whose paths are `<prefix>/<single-segment>`. Registered for `/`, `/dev`, `/sys`, `/etc`, `/bin`, `/usr`, `/usr/bin`, `/proc/sys`. `open("/dev", O_DIRECTORY) + getdents64` enumerates the real char-dev set. |
| #321 | `P3-84-proc-self-fd` | `ProcSelfFdInode` (FileType::Directory) — readdir emits decimal fd names; lookup parses the name and returns the underlying File's inode. New `FdTable::live_fds()` helper. Bash + lsof + busybox `ls /proc/self/fd` rely on this. |
| #322 | `P3-85-readlink-real-exe` | `sys_readlink` and `sys_readlinkat` now resolve `/proc/<tid>/{exe,cwd,root}` and `/proc/self/{exe,cwd,root}`. `exe` returns argv[0] from the target task's cmdline snapshot (P3-80); fallback `/init`. cwd/root still report `/`. |
| #323 | `P3-86-close-range` | Linux 5.9+ slot 436. Walks `FdTable::live_fds()` and closes (or sets cloexec under `CLOSE_RANGE_CLOEXEC`) every fd in [first, last]. Removed from syscall_compat ENOSYS bucket. Modern shells use this to drop inherited fds before exec. |

End-of-session-24 verified-green:
- `make lint` clean.
- `make test` → 524 passed, 0 failed.
- `make build` both arches green.
- `make qemu-x86 --features debug-all` → boot trace through all elf-smoke iterations; halts clean.
