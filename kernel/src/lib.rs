// Kernel library. The actual binary is the per-arch boot crate
// (`crates/boot-x86_64`, `crates/boot-aarch64`) which provides the
// arch `_start` symbol, sets up a minimal env, then tail-calls
// `kernel_main`.
//
// This library is `#![no_std]`; it compiles on host so hosted unit
// tests can exercise everything that doesn't require asm.
//
// Phase 0 exit goal per `00§3`: hello-world boots both arches via
// QEMU, prints "init started" on UART, exits cleanly. The string is
// emitted here; the UART backend is wired by the per-arch boot
// crate.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// Compile-time check: the per-arch HAL `Context` type must fit in
// `Task.arch_ctx` per `13§5`. If a future arch grows past
// `::sched::ARCH_CTX_SIZE`, bump the constant in `crates/sched`
// rather than working around here.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const _: () = assert!(
    core::mem::size_of::<hal_x86_64::ContextX86_64>() <= ::sched::ARCH_CTX_SIZE,
    "ContextX86_64 exceeds ::sched::ARCH_CTX_SIZE — bump the const",
);
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const _: () = assert!(
    core::mem::size_of::<hal_aarch64::ContextAArch64>() <= ::sched::ARCH_CTX_SIZE,
    "ContextAArch64 exceeds ::sched::ARCH_CTX_SIZE — bump the const",
);

// Per-subsystem debug-trace gates per `04§3` (R05) + `04§4.0` (R06).
// `#[macro_use]` hoists the `debug_<sub>!` macros into all sibling
// modules so they can use them without per-call `use`.
#[macro_use]
mod debug_macros;

// Per `04§4.0` (R06): modules whose entire surface is diagnostic
// trace are gated at the module declaration so their klog call
// sites are absent from the binary unless the matching debug
// feature is on. Production-bring-up modules (lapic, gic, pmm_setup)
// keep their non-trace surface always-on; their klog call sites
// inside lib.rs are individually wrapped in `debug_<sub>!`.
#[cfg(feature = "debug-acpi")]
pub mod acpi;
#[cfg(target_arch = "aarch64")]
pub mod arm_timer;
#[cfg(target_arch = "aarch64")]
pub mod gic;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod canary;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod ksched;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod kthread;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod preempt_smoke;
#[cfg(target_os = "oxide-kernel")]
pub mod preempt;
/// Real per-CPU runqueue + `schedule()` per `13§6`/§8 (P2-13b).
/// Replaces the prior `kernel/src/ksched.rs` Vec-shim. Always-on
/// (not gated on `debug-sched`) so the runqueue is available to
/// production paths (preempt-on-IRQ-exit, future user-task switch).
#[cfg(target_os = "oxide-kernel")]
pub mod sched;

/// ELF loader glue per docs/31. Loads a `&'static [u8]` ELF into
/// an `AddressSpace` using `VmaBacking::KernelBytes` (P2-17).
#[cfg(target_os = "oxide-kernel")]
pub mod elf_load;

/// TTY input per docs/28. v1: timer-tick UART poll + ringbuffer
/// + WaitQueue-based blocking sys_read. x86_64 only.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod tty;

/// `/dev/console` char-device per docs/16 + docs/28. v1 stub
/// of the real /dev plumbing; full VFS + devfs ride P2-30.
#[cfg(target_os = "oxide-kernel")]
pub mod dev_console;

/// Minimal devfs registry per docs/16 + docs/19. Path → InodeRef
/// table for `/dev/console` + `/dev/tty*`. Resolved by `sys_open`.
#[cfg(target_os = "oxide-kernel")]
pub mod devfs;

/// Anonymous pipe per docs/16 + docs/24. PipeInode + sys_pipe2
/// glue for the canonical `cmd1 | cmd2` shell IPC pattern.
#[cfg(target_os = "oxide-kernel")]
pub mod dev_pipe;
#[cfg(target_os = "oxide-kernel")]
pub mod dev_misc;

/// Per-arch ELF execution smoke. Parses a hand-synthesised
/// ELF64 and drops to ring 3 / EL0 via the demand-page path.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod elf_smoke;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub mod elf_smoke_arm;
#[cfg(target_arch = "x86_64")]
pub mod lapic;
#[cfg(target_arch = "aarch64")]
pub mod pl011;
pub mod pmm_setup;

/// Kernel-wide heap allocator per `12§2`. Fixed-size BSS heap for v1;
/// replaced by PMM-backed slab routing once a binary stage exists.
/// Hosts the `BTreeMap` / `Vec` machinery used by `vmm::VmaTree` and
/// later subsystems.
///
/// Gated `cfg(target_os = "oxide-kernel")` so the declaration is
/// active only when building for the kernel targets in `targets/`.
/// Host builds (used by hosted tests in this and downstream crates)
/// keep `std`'s default allocator.
#[cfg(target_os = "oxide-kernel")]
#[global_allocator]
static GLOBAL_ALLOC: kalloc::KAlloc = kalloc::KAlloc::new();

/// Boot info passed by the arch boot stub.
///
/// Layout is bootloader-defined per `36`; the stub parses the
/// bootloader-specific blob (Limine info on x86_64, DTB/EDK2 on
/// aarch64) and hands a uniform view to the kernel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootInfo {
    /// Number of memory map entries.
    pub memmap_count: u32,
    /// Pointer to a `[BootMemRegion; memmap_count]`.
    pub memmap_ptr: *const BootMemRegion,
    /// Bootloader-provided initial entropy (RDRAND on x86; RNDR on
    /// arm; bootloader-collected jitter as fallback).
    pub seed: [u8; 32],
    /// Boot-time monotonic counter snapshot in nanoseconds.
    pub boot_ns: u64,
    /// Higher-half direct-map offset (Limine HHDM, `36§3`). For any
    /// physical address `pa` covered by HHDM, the kernel-VA mirror
    /// is `hhdm_offset + pa`. `0` means the bootloader did not
    /// populate the HHDM response (early-boot diagnostics, hosted
    /// tests, or stub paths).
    pub hhdm_offset: u64,
    /// Physical address of the ACPI RSDP table, or 0 if the
    /// bootloader did not surface one (no UEFI / no ACPI on this
    /// platform).
    pub rsdp_pa: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootMemRegion {
    pub base_pa: u64,
    pub len: u64,
    pub kind: BootMemKind,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootMemKind {
    Usable = 0,
    Reserved = 1,
    AcpiReclaim = 2,
    AcpiNvs = 3,
    BadMem = 4,
    BootloaderUsed = 5,
    KernelImage = 6,
    Initramfs = 7,
}

/// Kernel entry. Called by per-arch boot stub after low-level setup.
///
/// # SAFETY: caller has set up a valid kernel stack, mapped the kernel
/// image at the upper-half virtual address per the linker script, set
/// per-CPU base register, and disabled interrupts. `info` points to a
/// valid `BootInfo` whose `memmap_ptr` references valid memory for at
/// least `memmap_count` entries.
///
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    // Bring up the kernel heap before any subsystem that allocates.
    // SAFETY: kernel_main is called once per boot from a single CPU
    // with IRQs off; `STATIC_HEAP` is BSS-resident, exclusively owned
    // by `kalloc`, and not yet referenced by anything else.
    #[cfg(target_os = "oxide-kernel")]
    unsafe { GLOBAL_ALLOC.init_static() };

    debug_boot! { klog::kinfo!("init started"); }
    debug_boot! {
        if info.hhdm_offset != 0 {
            klog::kinfo!("hhdm: present");
        } else {
            klog::kinfo!("hhdm: absent");
        }
    }
    if info.rsdp_pa != 0 {
        debug_acpi! {
            klog::write_raw(b"[INFO]  rsdp: ");
            klog::write_hex_u64(info.rsdp_pa);
            klog::write_raw(b"\n");
            // SAFETY: `info.rsdp_pa` is the Limine-supplied kernel VA
            // for the RSDP (HHDM-mapped); the bootloader keeps the
            // backing memory alive past kernel handoff per `36§3`.
            unsafe { acpi::try_log_acpi(info.rsdp_pa, info.hhdm_offset); }
        }
    } else {
        debug_boot! { klog::kinfo!("rsdp: absent"); }
    }
    if info.memmap_count != 0 {
        debug_boot! { klog::kinfo!("memmap: present"); }
        debug_pmm! {
            // SAFETY: kernel_main fn-contract guarantees memmap_ptr is a
            // valid slice of length memmap_count for this call.
            let regions: &[BootMemRegion] = unsafe {
                core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
            };
            log_memmap(regions);
        }
    } else {
        debug_boot! { klog::kinfo!("memmap: absent"); }
    }

    // Bring up the physical memory manager.
    // SAFETY: kernel_main fn-contract; single-CPU, IRQs off, info
    // outlives the call.
    let pmm = unsafe { pmm_setup::init_from_boot_info(info) };
    debug_boot! {
        match &pmm {
            Ok(_)                                       => klog::kinfo!("pmm: ready"),
            Err(pmm_setup::SetupError::NoMemmap)        => klog::kinfo!("pmm: skip (no memmap)"),
            Err(pmm_setup::SetupError::NoHhdm)          => klog::kinfo!("pmm: skip (no hhdm)"),
            Err(pmm_setup::SetupError::NoUsableRegion)  => klog::kerror!("pmm: no usable region"),
            Err(pmm_setup::SetupError::NoSpaceForBitmaps) => klog::kerror!("pmm: pool too big"),
            Err(pmm_setup::SetupError::TooManyRegions)  => klog::kerror!("pmm: too many regions"),
            Err(pmm_setup::SetupError::PmmInit(_))      => klog::kerror!("pmm: Pmm::init refused"),
            Err(pmm_setup::SetupError::AlreadyInit)     => klog::kerror!("pmm: already init"),
        }
    }
    // Runtime smoke: alloc/free at order 0 to prove the buddy
    // machinery works after init. Removed once a real consumer
    // (slab) wires in.
    if let Ok(p) = pmm {
        debug_pmm! {
            match p.alloc(pmm::Order(0)) {
                Ok(pfn) => {
                    klog::kinfo!("pmm-smoke: alloc(0) ok");
                    // SAFETY: pfn was just returned by alloc(0); free is
                    // the matching counterpart and is single-threaded
                    // here per pre-init contract.
                    unsafe { p.free(pfn, pmm::Order(0)); }
                    klog::kinfo!("pmm-smoke: free(0) ok");
                }
                Err(_) => klog::kerror!("pmm-smoke: alloc(0) failed"),
            }
            // Memory summary: `pmm: <free_mib> MiB free, <alloc> page(s) reserved`.
            let free_pages = p.free_pages();
            let alloc_pages = p.allocated_pages();
            // 4 KiB pages -> MiB: pages * 4096 / (1024*1024) = pages / 256.
            let free_mib = free_pages / 256;
            klog::write_raw(b"[INFO]  pmm: ");
            klog::write_dec_u64(free_mib);
            klog::write_raw(b" MiB free, ");
            klog::write_dec_u64(alloc_pages);
            klog::write_raw(b" page(s) reserved\n");

            // PMM stress: alloc 64 order-0 pages, free in reverse, verify
            // free_pages count matches the baseline. Catches simple
            // bookkeeping bugs the single-page smoke can't.
            const STRESS_N: usize = 64;
            let baseline = p.free_pages();
            let mut buf: [hal::Pfn; STRESS_N] = [hal::Pfn(0); STRESS_N];
            let mut got = 0usize;
            while got < STRESS_N {
                match p.alloc(pmm::Order(0)) {
                    Ok(pfn) => { buf[got] = pfn; got += 1; }
                    Err(_)  => break,
                }
            }
            // SAFETY: every pfn in `buf[..got]` was returned by alloc(0)
            // above and not yet freed; reverse-order frees match the
            // alloc count exactly.
            unsafe {
                while got > 0 {
                    got -= 1;
                    p.free(buf[got], pmm::Order(0));
                }
            }
            let after = p.free_pages();
            if after == baseline {
                klog::kinfo!("pmm-stress: 64x alloc/free balanced");
            } else {
                klog::kerror!("pmm-stress: free_pages drift");
            }

            // Multi-order stress: one alloc/free per order 0..=10. Exercises
            // the split-and-merge paths the single-order stress can't.
            let baseline_mo = p.free_pages();
            let mut order_buf: [(hal::Pfn, u8); 11] = [(hal::Pfn(0), 0); 11];
            let mut got_mo = 0usize;
            for o in 0u8..=10 {
                match p.alloc(pmm::Order(o)) {
                    Ok(pfn) => { order_buf[got_mo] = (pfn, o); got_mo += 1; }
                    Err(_)  => break,
                }
            }
            // SAFETY: each pair in `order_buf[..got_mo]` came from a matching
            // `alloc(o)` above; we free with the same order, single-threaded.
            unsafe {
                while got_mo > 0 {
                    got_mo -= 1;
                    let (pfn, o) = order_buf[got_mo];
                    p.free(pfn, pmm::Order(o));
                }
            }
            if p.free_pages() == baseline_mo {
                klog::kinfo!("pmm-stress: orders 0..=10 balanced");
            } else {
                klog::kerror!("pmm-stress: multi-order drift");
            }
            // Re-emit the summary to make the round-trip visible in the trace.
            klog::write_raw(b"[INFO]  pmm: ");
            klog::write_dec_u64(p.free_pages() / 256);
            klog::write_raw(b" MiB free post-stress, ");
            klog::write_dec_u64(p.allocated_pages());
            klog::write_raw(b" page(s) reserved\n");
        }

        // Wire MmuOps for this arch: stash HHDM + bare-fn frame
        // allocator. After this point the trait surface is live.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: single-CPU pre-init; PMM initialised above; HHDM offset comes from BootInfo and matches the live tables; alloc_one_frame is a bare fn that wraps the just-initialised global PMM.
        unsafe {
            hal_x86_64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_x86_64::mmu_ops::set_frame_alloc(pmm_setup::alloc_one_frame);
        }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: single-CPU pre-init; PMM initialised above; HHDM offset comes from BootInfo and matches the live tables; alloc_one_frame is a bare fn that wraps the just-initialised global PMM.
        unsafe {
            hal_aarch64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_aarch64::mmu_ops::set_frame_alloc(pmm_setup::alloc_one_frame);
        }
        let _ = p;

        // Device bring-up: install Device-attr 4 KiB MMIO mappings
        // via the PMM-backed mapper, enable LAPIC/GIC/UART. The
        // bring-up is always-on; per-step diagnostic logs are gated
        // by per-subsystem `debug-vmm`/`debug-irq` features inside.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        device_map_smoke::smoke_device_map_x86(info.hhdm_offset);
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        device_map_smoke::smoke_device_map_arm(info.hhdm_offset);

        // MmuOps end-to-end smoke: map/write/translate/unmap a fresh
        // PMM frame at a scratch VA. Per-arch wrapper picks the
        // marker type implementing `MmuOps`.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: PMM + MmuOps state initialised above; SCRATCH_VA disjoint from existing kernel mappings; single-CPU pre-init.
        unsafe { mmuops_smoke::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: PMM + MmuOps state initialised above; SCRATCH_VA disjoint from existing kernel mappings; single-CPU pre-init.
        unsafe { mmuops_smoke::run::<hal_aarch64::mmu_ops::ArmMmu>(); }

        // User-page mapping smoke (P1-95 fix validation): map a 4 KiB
        // user VA with USER|EXEC|READ, verify translate round-trips
        // the USER+EXEC flags through real CR3 walk + interior U=1
        // propagation. CPL=3 access lands with P1-82.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: PMM + MmuOps state initialised above; USER_VA disjoint from kernel-half mappings; single-CPU pre-init.
        unsafe { user_map_smoke::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: PMM + MmuOps state initialised above; USER_VA disjoint from kernel-half mappings; single-CPU pre-init.
        unsafe { user_map_smoke::run::<hal_aarch64::mmu_ops::ArmMmu>(); }
    }


    // kalloc smoke: insert a VMA into a `vmm::VmaTree`, exercising
    // the global allocator's `BTreeMap` path.
    #[cfg(target_os = "oxide-kernel")]
    {
        let mut tree = vmm::VmaTree::new();
        // SAFETY: addresses are within the user-VA range (0x1000 < USER_VA_END).
        let start = hal::UserVirtAddr::new(0x1000).expect("test addr in user range");
        let end   = hal::UserVirtAddr::new(0x2000).expect("test addr in user range");
        let inserted = tree.insert(vmm::Vma::new(
            start, end,
            vmm::VmaProt::READ,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
            vmm::VmaBacking::Anonymous,
        )).is_ok();
        debug_boot! {
            if inserted {
                klog::kinfo!("kalloc-smoke: VmaTree insert ok");
            } else {
                klog::kerror!("kalloc-smoke: VmaTree insert failed");
            }
        }
    }

    debug_sched! {
        // SAFETY: kernel_main pre-init phase; allocator up; single-CPU,
        // IRQs masked (x86 CLI path, arm DAIF.I masked again post-soak).
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            kthread::smoke();
            kthread::smoke_yield();
            ksched::smoke_rr(4);
            #[cfg(target_arch = "x86_64")]
            preempt_smoke::smoke_preempt_x86(4, 1_000_000);
            #[cfg(target_arch = "aarch64")]
            preempt_smoke::smoke_preempt_arm(4, 50_000);
            // 64-task ctxsw register-canary per `14§8`. Bounded
            // version (CANARY_N × CANARY_ITERS); the 1h soak rides
            // background CI per `40§3`.
            #[cfg(target_arch = "x86_64")]
            canary::smoke_canary_x86(1_000_000);
            #[cfg(target_arch = "aarch64")]
            canary::smoke_canary_arm(50_000);
        }
    }

    // Recoverable page-fault smoke (P1-86c). Validates the fault
    // dispatcher's `bool` retry path on a real demand-paged write.
    // Runs at CPL=0 so it doesn't depend on the userspace smoke.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: PMM + MmuOps initialised; FAULT_VA in the smoke's
        // private kernel-half slot; single-CPU; IRQs masked.
        unsafe { pf_recover_smoke::run(); }
    }

    // Initialise the global user AddressSpace + demand-paging fault
    // hook per `11§3`/`11§5`. Must run before any userspace smoke so
    // mmap and #PF go through the real AS.
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: PMM up; HHDM offset known; single-CPU pre-init.
        unsafe { user_as::init(info.hhdm_offset); }
        // Register `/dev/console` + `/dev/tty*` in the v1 devfs
        // registry per docs/19. `sys_open(2)` resolves through here.
        devfs::init();
    }


    debug_boot! { klog::kinfo!("boot: kernel ready, halting"); }

    // ELF-loaded userspace via real Task on the runqueue (P2-13c).
    // Spawns the user task with mm=Arc<AddressSpace>, schedule()'s
    // into it via the IRQ-tail iretq path. Diverges at the ud2
    // landmark after sys_exit's sysretq.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: every prerequisite established above — kernel-owned
        // GDT (P1-93), TSS+ltr (P1-94), interior-U=1 walker (P1-95),
        // PMM + MmuOps + per-AS PT root (P2-19) + ELF loader (P2-16)
        // + runqueue (P2-13b) initialised; single-CPU; IRQs masked.
        unsafe { elf_smoke::run_as_task(info.hhdm_offset); }
    }

    // First ELF-loaded userspace per docs/31 (P2-16c) on aarch64.
    // Diverges via the deliberate brk landmark after sys_exit's
    // eret. Parallel to the x86_64 elf_smoke path; uses
    // `VmaBacking::KernelBytes` + demand-paging through the AS.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // SAFETY: PMM + MmuOps + VBAR_EL1 + per-AS PT root (P2-19) +
        // SVC dispatch all initialised; single-CPU; DAIF.I masked.
        unsafe { elf_smoke_arm::run(); }
    }

    halt_forever()
}

/// Map `BootMemKind` to a short ASCII tag for memmap dumps.
#[cfg(feature = "debug-pmm")]
fn kind_tag(k: BootMemKind) -> &'static [u8] {
    match k {
        BootMemKind::Usable         => b"USABLE",
        BootMemKind::Reserved       => b"RESV  ",
        BootMemKind::AcpiReclaim    => b"ACPI-R",
        BootMemKind::AcpiNvs        => b"ACPI-N",
        BootMemKind::BadMem         => b"BAD   ",
        BootMemKind::BootloaderUsed => b"BL-USE",
        BootMemKind::KernelImage    => b"KERNEL",
        BootMemKind::Initramfs      => b"INITRD",
    }
}

/// Emit one line per memmap region. Cheap O(N) at boot.
#[cfg(feature = "debug-pmm")]
fn log_memmap(regions: &[BootMemRegion]) {
    let mut usable_bytes: u64 = 0;
    let mut reserved_bytes: u64 = 0;
    let mut bootloader_bytes: u64 = 0;
    for r in regions {
        klog::write_raw(b"[INFO]    ");
        klog::write_raw(kind_tag(r.kind));
        klog::write_raw(b" base=");
        klog::write_hex_u64(r.base_pa);
        klog::write_raw(b" len=");
        klog::write_hex_u64(r.len);
        klog::write_raw(b"\n");
        match r.kind {
            BootMemKind::Usable         => usable_bytes     = usable_bytes.saturating_add(r.len),
            BootMemKind::BootloaderUsed => bootloader_bytes = bootloader_bytes.saturating_add(r.len),
            BootMemKind::Reserved
            | BootMemKind::AcpiNvs
            | BootMemKind::AcpiReclaim
            | BootMemKind::BadMem
            | BootMemKind::KernelImage
            | BootMemKind::Initramfs    => reserved_bytes   = reserved_bytes.saturating_add(r.len),
        }
    }
    klog::write_raw(b"[INFO]    memmap totals: ");
    klog::write_dec_u64(usable_bytes / (1024 * 1024));
    klog::write_raw(b" MiB usable, ");
    klog::write_dec_u64(bootloader_bytes / (1024 * 1024));
    klog::write_raw(b" MiB bootloader-reclaim, ");
    klog::write_dec_u64(reserved_bytes / (1024 * 1024));
    klog::write_raw(b" MiB reserved\n");
}

// Per-arch device-MMIO bring-up smokes live in `device_map_smoke.rs`
// (extracted to keep lib.rs under the 500-line soft cap).
#[cfg(target_os = "oxide-kernel")]
pub mod device_map_smoke;

// MmuOps end-to-end map/translate/unmap roundtrip smoke.
#[cfg(target_os = "oxide-kernel")]
pub mod mmuops_smoke;

// User-page mapping smoke validating the P1-95 interior-U=1 fix.
#[cfg(target_os = "oxide-kernel")]
pub mod user_map_smoke;

// Page-fault recovery smoke (P1-86c). x86_64-only for now.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod pf_recover_smoke;

// Syscall dispatch glue: kernel-side `oxide_syscall_dispatch` symbol
// both arches' asm stubs reference by name. Binds the asm path to
// `syscall::dispatch`. arch-specific interceptions live behind cfg
// gates inside the module.
#[cfg(target_os = "oxide-kernel")]
pub mod syscall_glue;

// P3-03 fs-shaped syscalls split out of `syscall_glue` to keep that
// file under the 1000-line cap per `08§7`.
#[cfg(target_os = "oxide-kernel")]
pub mod syscall_glue_fs;

// P3-08 process-shaped syscalls (sched_yield, gettid, set_tid_address).
#[cfg(target_os = "oxide-kernel")]
pub mod syscall_glue_proc;

// P2-21c initial user-stack builder per docs/31§4 step 5.
// SysV argc/argv/envp/auxv layout written at execve time.
#[cfg(target_os = "oxide-kernel")]
pub mod exec_stack;

// Global user `AddressSpace` per `11§3` + demand-paging fault hook
// per `11§5`. v1 single-task; per-task lifecycle lands with P2-13.
#[cfg(target_os = "oxide-kernel")]
pub mod user_as;

// First userspace `iretq` smoke (P1-82). x86_64-only.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod userspace_smoke;

// First userspace `eret` smoke (P2-09). aarch64 mirror, unblocked
// by the P2-08 walker TTBR0/TTBR1 selector fix.
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub mod userspace_smoke_arm;


/// Park the CPU forever. On the kernel target, uses the per-arch
/// halt instruction (`hlt` / `wfi`) so the host doesn't burn 100%
/// CPU cycling on a spin loop. Host fallback keeps `spin_loop` for
/// hosted unit-test compatibility.
///
/// # C: O(∞)
pub fn halt_forever() -> ! {
    loop {
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: `hlt` parks the core until next IRQ; legal at CPL=0.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: `wfi` parks the core until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
        #[cfg(not(target_os = "oxide-kernel"))]
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_layout_is_repr_c() {
        // Sanity check: BootInfo size is determinist on a 64-bit host.
        // u32 + ptr + [u8;32] + u64 + u64 with natural alignment.
        assert!(core::mem::size_of::<BootInfo>() >= 60);
    }

    #[test]
    fn boot_mem_kind_distinct() {
        assert_ne!(BootMemKind::Usable as u8, BootMemKind::BadMem as u8);
    }
}
