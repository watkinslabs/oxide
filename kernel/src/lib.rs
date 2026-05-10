// Kernel lib. Per-arch boot crates own _start; this lib hosts
// kernel_main. #![no_std]; compiles on host for unit tests.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// Anchor crates whose `#[no_mangle]` symbols the linker needs even
// without an explicit `use`. Per `52§8`.
#[cfg(target_os = "oxide-kernel")] extern crate ptrace;

// Compile-time check: per-arch Context must fit in Task.arch_ctx.
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

// Per-subsystem debug-trace gates per `04§3` R05 + R06.
#[macro_use]
mod debug_macros;

// Per `04§4.0` R06: trace-only modules are cfg-gated at decl.
// ACPI walker = `crates/firmware` (`33§R01`); ns inodes =
// `crates/nscg` (`26§R01`). Re-exports keep call sites stable.
pub use firmware::acpi;
#[cfg(target_os = "oxide-kernel")]
pub use nscg::proc_ns as dev_proc_ns;
pub mod smp;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod smp_x86;
#[cfg(target_arch = "aarch64")]
pub mod gic;
#[cfg(target_arch = "aarch64")]
pub mod its;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod canary;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod ksched;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub use ::sched::kthread;
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

/// ELF loader glue per docs/31. PT_LOADs → KernelBytes (P2-17).

/// TTY input per docs/28. timer-poll + ringbuffer + waitqueue.
#[cfg(target_os = "oxide-kernel")] pub mod tty;
/// `/dev/console` char-device per docs/16 + docs/28.
#[cfg(target_os = "oxide-kernel")] pub mod dev_console;
/// F158: /proc/meminfo body builder (split out of procfs.rs).

/// F158: /proc/<pid>/smaps detailed per-VMA memory stats.
#[cfg(target_os = "oxide-kernel")] pub mod procfs_smaps;
/// F158: /proc/<pid>/status body builder (Linux-conformant fields).
#[cfg(target_os = "oxide-kernel")] pub mod procfs_pid_status;

/// Minimal devfs registry per docs/16 + docs/19. Path → InodeRef
/// table for `/dev/console` + `/dev/tty*`. Resolved by `sys_open`.
#[cfg(target_os = "oxide-kernel")]
pub mod devfs;

/// Anonymous pipe per docs/16 + docs/24. PipeInode + sys_pipe2
/// glue for the canonical `cmd1 | cmd2` shell IPC pattern.
/// ext4 RO root fs: real driver from `crates/ext4` mounted at
/// boot from a kernel-embedded image. Linux's CONFIG_EXT4_FS=y
/// equivalent (built-in, not a module).
#[cfg(target_os = "oxide-kernel")]
pub mod dev_pty;
#[cfg(target_os = "oxide-kernel")]
pub mod dev_pidfd;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod dev_virtio_net;
pub mod dev_virtio_net_modern;
pub mod sysv_sem;
pub mod sysv_msg;
pub mod posix_mq;
pub mod io_uring;
// seccomp + bpf moved to `crates/security` per `27§R03`.
pub use security::seccomp;
#[cfg(target_os = "oxide-kernel")]
pub use security::bpf as dev_bpf;
pub mod dev_drm;
#[cfg(target_os = "oxide-kernel")]




#[cfg(target_os = "oxide-kernel")]
pub mod procfs;
#[cfg(target_os = "oxide-kernel")]
pub mod procfs_net;
#[cfg(target_os = "oxide-kernel")]
pub mod procfs_static;


/// Per-arch ELF execution smoke. Parses a hand-synthesised
/// ELF64 and drops to ring 3 / EL0 via the demand-page path.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod elf_smoke;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub mod elf_smoke_arm;
#[cfg(target_arch = "x86_64")]
pub mod lapic;

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

// Boot-stub → kernel handoff types now live in `crates/boot-info`
// per the `52§3` shared layer. Re-exported here so existing
// `crate::BootInfo` / `crate::BootMemRegion` / `crate::BootMemKind`
// call sites compile unchanged during the Stage B migration.
pub use boot_info::{BootInfo, BootMemKind, BootMemRegion};

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
    // Boot CPU's per-CPU page (B14): a 4 KiB BSS array whose first
    // 4 bytes are the cpu_id (0). Call set_percpu_base with its
    // address before any code path reads `gs:0` via `current_cpu`
    // — the per-CPU runqueue array (P4-10) and several other
    // helpers depend on this. The 16-byte alignment matches what
    // wrgsbase wants, and 4 KiB is the spec's per-CPU area size
    // per `06§4`. UnsafeCell + unsafe-impl-Sync wrapper avoids
    // `static mut` per `07§5`.
    #[cfg(target_os = "oxide-kernel")]
    {
        #[repr(align(16))]
        struct PerCpuBootPage(core::cell::UnsafeCell<[u8; 4096]>);
        // SAFETY: BSS-resident; sole writer is the boot CPU during its own bring-up here, before any other context can observe the cell.
        unsafe impl Sync for PerCpuBootPage {}
        static BOOT_PERCPU: PerCpuBootPage =
            PerCpuBootPage(core::cell::UnsafeCell::new([0u8; 4096]));

        let p = BOOT_PERCPU.0.get() as *mut u8;
        // SAFETY: BSS-resident page; this is the boot path's single writer; cpu_id=0 stamped at offset 0 matches `current_cpu`'s gs:0 (x86) / TPIDR_EL1 (arm) read.
        unsafe { core::ptr::write_volatile(p as *mut u32, 0u32); }
        // Enable CR4.FSGSBASE (bit 16) so wrgsbase is legal at CPL=0;
        // Limine leaves it off, but boot CPU is the single writer here.
        // SAFETY: kernel_main runs single-CPU pre-init; toggling CR4.FSGSBASE has no side effect beyond enabling rd/wrgsbase + rd/wrfsbase, which we use immediately below.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use hal::CpuOps;
            let mut cr4: u64;
            core::arch::asm!("mov {cr4}, cr4", cr4 = out(reg) cr4, options(nomem, nostack, preserves_flags));
            cr4 |= 1u64 << 16;
            core::arch::asm!("mov cr4, {cr4}", cr4 = in(reg) cr4, options(nomem, nostack, preserves_flags));
            // SAFETY: per fn contract — boot path; per-CPU page allocated above with cpu_id=0 at offset 0; called once before any current_cpu read.
            hal_x86_64::X86CpuOps::set_percpu_base(p);
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: same — boot path single writer; per-CPU page initialised with cpu_id=0 at offset 0; called before any TPIDR_EL1 read.
        unsafe { use hal::CpuOps; hal_aarch64::ArmCpuOps::set_percpu_base(p); }
    }

    // vfs hooks: flock release-on-close + inotify IN_MODIFY-on-write.
    #[cfg(target_os = "oxide-kernel")]
    { flock::install_drop_hook(); inotify::install_write_hook(); }
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
        }
        // Install the firmware → cpu_topology add-cpu hook, then
        // walk ACPI tables. Walk runs unconditionally so SMP gets
        // populated without `debug-acpi`; the alog_* helpers inside
        // firmware::acpi gate the trace lines.
        firmware::set_add_cpu_hook(cpu::add_cpu);
        // SAFETY: `info.rsdp_pa` is the Limine-supplied kernel VA
        // for the RSDP (HHDM-mapped); the bootloader keeps the
        // backing memory alive past kernel handoff per `36§3`.
        unsafe { firmware::try_log_acpi(info.rsdp_pa, info.hhdm_offset); }
        // SMP bring-up scaffolding: capture the boot CPU id from
        // the first cpu_topology entry. ACPI 6.5 §5.2.12.2 lists
        // the boot CPU first in MADT, so cpu_topology[0] is the
        // boot CPU's APIC id / MPIDR. Avoids reading `gs:0` here —
        // GS_BASE is set up later by per-CPU init, and an early
        // `current_cpu()` would null-deref the boot CPU's missing
        // per-CPU page (B14).
        if let Some((id, _flags)) = cpu::get(0) {
            // SAFETY: kernel_main runs single-CPU pre-init per fn contract; sole writer for BOOT_CPU_ID before any AP observes it.
            unsafe { crate::smp::set_boot_cpu_id(id); }
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
    if pmm.is_ok() { pmm_setup::init_page_meta(pmm_setup::pfn_max_from_boot_info(info)); }
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

    // user AS + demand-paging fault hook per 11§3/11§5; must run
    // before any userspace smoke so mmap and #PF go through the real AS.
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: PMM up; HHDM offset known; single-CPU pre-init.
        unsafe { user_as::init(info.hhdm_offset); }
        devfs::init(); procfs::init();
        crate::dev_drm::register();
        tmpfs::init(); dev_tracefs::init(); drv_virtio_input::devfs::init();
        fbdev::devfs::init(); dev_pty::init();
        // boot smokes:
        ::devfs::misc::smoke_test();
        procfs::smoke_test();
        pipe::smoke_test();
        tmpfs::smoke_test();
        dev_pty::smoke_test();
        // P3-49 syscall coverage banner. Kept in sync by hand —
        // bumped whenever a new arm or compat-table entry lands.
        debug_boot! { klog::write_raw(b"[INFO]  syscall: ~200 slots wired (real impls + compat stubs)\n"); }
        // P3-56 path-string lookup smoke for the execve resolver.
        #[cfg(target_arch = "x86_64")]
        elf_smoke::lookup_smoke();
    }


    // SMP bring-up per `13§11`. With -smp 1 (default) the per-arch
    // path is a no-op. With -smp N>=2 the boot CPU starts each AP:
    //   x86_64: Limine SMP request — store our entry into each
    //           SmpInfoX86::goto_address so the parked AP jumps in.
    //   aarch64: PSCI CPU_ON for each enumerate_aps() entry.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: kernel_main post-init; Limine SMP response in info is bootloader-owned; boot CPU is sole writer for goto_address slots.
        let started = unsafe { crate::smp_x86::bring_up_aps_x86(info) };
        debug_boot! {
            klog::write_raw(b"[INFO]  smp: cpus=");
            klog::write_dec_u64(info.smp_count);
            klog::write_raw(b" aps_started=");
            klog::write_dec_u64(started as u64);
            klog::write_raw(b"\n");
        }
        // Cross-CPU IPI smoke per `13§9`. Wait for every AP to
        // come online (smp::online_count() reaches smp_count) so
        // their LAPICs are enabled + IRQs unmasked, then send a
        // resched IPI to each non-BSP and confirm the handler
        // ran via RESCHED_IPI_COUNT.
        if started > 0 {
            // Wait up to ~100ms for APs to flip online.
            let target = info.smp_count as u32;
            let mut spins = 0u32;
            while crate::smp::online_count() < target && spins < 1_000_000 {
                core::hint::spin_loop();
                spins += 1;
            }
            // SAFETY: BSP holds boot context; LAPIC enabled; cpu_topology populated by ACPI walk.
            unsafe {
                let n = cpu::count() as usize;
                let bsp = crate::smp::boot_cpu_id();
                for i in 0..n {
                    if let Some((id, _)) = cpu::get(i) {
                        if id != bsp {
                            let _ = crate::lapic::send_resched_ipi(id);
                        }
                    }
                }
            }
            // Brief settle for IPIs to deliver + handlers to run.
            for _ in 0..1_000_000u32 { core::hint::spin_loop(); }
            debug_boot! {
                use core::sync::atomic::Ordering;
                klog::write_raw(b"[INFO]  smp: ipi_smoke: online=");
                klog::write_dec_u64(crate::smp::online_count() as u64);
                klog::write_raw(b" resched_ipis_received=");
                klog::write_dec_u64(crate::lapic::RESCHED_IPI_COUNT.load(Ordering::Relaxed));
                klog::write_raw(b"\n");
            }
            // Migration smoke per `13§11`: spawn a few CFS kthreads
            // on BSP so its runqueue has surplus, then balance_once
            // should migrate at least one to an idle AP.
            extern "C" fn smp_smoke_thread(_arg: usize) -> ! {
                loop {
                    // SAFETY: idle-equivalent loop in kthread context; pause is a hint, hlt parks until next IRQ.
                    unsafe {
                        core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
                        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
                    }
                }
            }
            // SAFETY: BSP at boot post-init; allocator up; runqueue idempotent install brings up BSP slot; spawn enqueues into BSP's slot; smp_smoke_thread loops in pause/hlt forever, no shared state; balance_once is reentrant under per-rq locks.
            let migrated = unsafe {
                crate::sched::install_default_runqueue();
                let _ = crate::sched::spawn_kernel_thread(0xB1A0_0001, "smpb1", smp_smoke_thread, 0);
                let _ = crate::sched::spawn_kernel_thread(0xB1A0_0002, "smpb2", smp_smoke_thread, 0);
                let _ = crate::sched::spawn_kernel_thread(0xB1A0_0003, "smpb3", smp_smoke_thread, 0);
                let m1 = crate::sched::balance::balance_once();
                let m2 = crate::sched::balance::balance_once();
                let m3 = crate::sched::balance::balance_once();
                m1 + m2 + m3
            };
            debug_boot! {
                klog::write_raw(b"[INFO]  smp: balance_once: migrated_total=");
                klog::write_dec_u64(migrated as u64);
                klog::write_raw(b"\n");
            }
        }
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // SAFETY: kernel_main post-init; PSCI conduit on QEMU virt is SMC #0; cpu_topology populated by ACPI; boot CPU is sole writer.
        let started = unsafe { hal_aarch64::smp::bring_up_aps_arm() };
        debug_boot! {
            klog::write_raw(b"[INFO]  smp: aps_started=");
            klog::write_dec_u64(started as u64);
            klog::write_raw(b"\n");
        }
    }

    // SAFETY: kernel_main runs single-CPU pre-init; power::init reports ready (no static state).
    let _ = unsafe { power::init() };
    // SAFETY: kernel_main runs single-CPU pre-init; firmware::init reports ready (real ACPI walk happened earlier).
    let _ = unsafe { firmware::init() };
    // Install the cross-crate `current task` accessor so downstream
    // workspace crates (security, nscg) can ask without importing
    // kernel-internal sched module.
    #[cfg(target_os = "oxide-kernel")]
    ::sched::set_current_hook(|| crate::sched::current());
    // SAFETY: kernel_main runs single-CPU pre-init; nscg::init reports ready (per-task ns slots set up by sched).
    let _ = unsafe { nscg::init() };
    // SAFETY: kernel_main runs single-CPU pre-init; security::init reports ready (per-task seccomp slot is None until prctl/seccomp installs).
    let _ = unsafe { security::init() };
    // SAFETY: kernel_main runs single-CPU pre-init; drv::init reports ready; per-driver register() happens during PCI enumeration.
    let _ = unsafe { drv::init() };
    // Register virtio-gpu wire driver. The matching probe runs from
    // pci_boot::virtio_probe_arch when the device id is found.
    drv_virtio_gpu::register();
    drv_virtio_input::register();
    // SAFETY: kernel_main runs single-CPU pre-init; vt::init allocates VT 1 + sets ACTIVE_VT.
    let _ = unsafe { vt::init() };
    debug_boot! { klog::kinfo!("boot: kernel ready, halting"); }

    // ELF-loaded userspace via real Task on the runqueue (P2-13c).
    // Spawns the user task with mm=Arc<AddressSpace>, schedule()'s
    // into it via the IRQ-tail iretq path. Diverges at the ud2
    // landmark after sys_exit's sysretq.
    // Mount the embedded ext4 root fs (P6-07). Linux's
    // CONFIG_EXT4_FS=y equivalent: real driver from crates/ext4
    // built into the kernel binary. No-op if already mounted.
    // SAFETY: post-PMM/allocator init; no other CPU has yet observed MOUNT_PTR.
    #[cfg(target_os = "oxide-kernel")]
    unsafe {
        ext4::rootfs::init();
        net::sock::init();
        modules::registry::init_exports();
    }
    #[cfg(target_os = "oxide-kernel")]
    {
        debug_boot! {
            klog::write_raw(b"[INFO]  ext4: mounted=");
            klog::write_dec_u64(ext4::rootfs::mounted() as u64);
            klog::write_raw(b"\n");
            for path in [&b"/hello.txt"[..], &b"/etc/issue"[..]] {
                if let Some(bytes) = ext4::rootfs::read_file(path) {
                    klog::write_raw(b"[INFO]  ext4 ");
                    klog::write_raw(path);
                    klog::write_raw(b" = ");
                    klog::write_raw(&bytes);
                    if !bytes.ends_with(b"\n") { klog::write_raw(b"\n"); }
                }
            }
            // P7b-01 RW smoke: overwrite the start of /hello.txt,
            // read it back, verify the write hit the disk through
            // ext4's extent walker + the writable ImageDisk backing.
            if ext4::rootfs::write_file(b"/hello.txt", b"WRITTEN-BY-OXIDE\n").is_some() {
                if let Some(bytes) = ext4::rootfs::read_file(b"/hello.txt") {
                    klog::write_raw(b"[INFO]  ext4 RW smoke /hello.txt = ");
                    klog::write_raw(&bytes);
                    if !bytes.ends_with(b"\n") { klog::write_raw(b"\n"); }
                }
            }
            // Read /bin/sh twice to prove the page cache: first
            // call is all misses; second is all hits.
            if let Some(bytes) = ext4::rootfs::read_file(b"/bin/sh") {
                klog::write_raw(b"[INFO]  ext4 /bin/sh size=");
                klog::write_dec_u64(bytes.len() as u64);
                let (h1, m1) = ext4::rootfs::cache_stats();
                klog::write_raw(b" cache after pass1: hits=");
                klog::write_dec_u64(h1);
                klog::write_raw(b" misses=");
                klog::write_dec_u64(m1);
                klog::write_raw(b"\n");
                let _ = ext4::rootfs::read_file(b"/bin/sh");
                let (h2, m2) = ext4::rootfs::cache_stats();
                klog::write_raw(b"[INFO]  ext4 /bin/sh cache after pass2: hits=");
                klog::write_dec_u64(h2);
                klog::write_raw(b" misses=");
                klog::write_dec_u64(m2);
                klog::write_raw(b"\n");
            }
            // P8 boot smoke: loopback UDP send-then-recv +
            // ICMP echo round-trip via the in-kernel net stack.
            {
                let s = net::sock::stack();
                let _ = s.bind_udp(net::Ipv4Addr::LOOPBACK, 7777);
                let _ = s.send_udp_to(
                    net::Ipv4Addr::LOOPBACK, 5555,
                    net::Ipv4Addr::LOOPBACK, 7777,
                    b"oxide-boot-smoke",
                );
                net::sock::drain_loopback();
                if let Some((_, _, payload)) = s.recv_udp(7777) {
                    klog::write_raw(b"[INFO]  net udp lo round-trip: ");
                    klog::write_raw(&payload);
                    klog::write_raw(b"\n");
                }
            }
        }
    }

    // PCI bus enumeration — both arches via `pci::enumerate`; per-arch
    // `ConfigSpaceReader` differs (x86 CF8/CFC, aarch64 ECAM MMIO).
    #[cfg(target_os = "oxide-kernel")]
    { crate::pci_boot::enumerate_and_log(); }

    // virtio-net legacy driver detect + init. No-op if no device.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        crate::dev_virtio_net::init_legacy();
    }

    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // F50: install per-arch user-trap hook BEFORE any user task
        // runs so PTRACE_SINGLESTEP #DB delivers SIGTRAP instead of
        // halting the kernel via the default fault path.
        // SAFETY: pre-init single-CPU; ptrace_singlestep::install is idempotent and only swaps a 'static fn pointer.
        unsafe { ptrace::install(); }
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
pub mod syscalls;
#[cfg(target_os = "oxide-kernel")] pub mod dev_tracefs;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscall"))] pub mod syscall_trace;

// aarch64 → x86 syscall-nr translation per docs/15§3. Active only
// on arm; x86 builds compile this away via a cfg gate at the call
// site in `syscalls::oxide_syscall_dispatch`.
pub mod syscall_arm_abi;

// P3-03 fs-shaped syscalls split out of `syscalls` to keep that
// file under the 1000-line cap per `08§7`.
#[cfg(target_os = "oxide-kernel")]
pub mod sched_stop;
#[cfg(target_os = "oxide-kernel")]
pub mod hostname;

// P3-08 process-shaped syscalls (sched_yield, gettid, set_tid_address).
#[cfg(target_os = "oxide-kernel")]

// Linux x86_64 syscall number table per `15§5`. One canonical
// place — `syscalls` references `syscall_nrs::NR_*`.

// P3-46 compat-stub dispatch table — pulls the broad
// accept-and-no-op + ENOSYS + EPERM tail out of `syscalls`.
#[cfg(target_os = "oxide-kernel")]
pub mod syscall_compat;

// P3-30 time-shaped syscalls (clock_gettime + family).

// P3a futex — process-private FUTEX_WAIT/WAKE per docs/24.
pub mod futex;

// P3-65 signal dispatch (build user-stack frame + jump to sa_handler).
// Arch-portable since F16 — x86 + aarch64 paths share the wire frame
// shape; only the saved-state register set differs.
#[cfg(target_os = "oxide-kernel")]
pub mod sig_dispatch;

// PCI bus enumeration boot helper (per-arch ConfigSpaceReader
// dispatch). Split out of lib.rs to keep that file under cap.
#[cfg(target_os = "oxide-kernel")]
pub mod pci_boot;

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
    // SAFETY: park-only operation; the per-arch hlt/wfi requires CPL=0/EL1 which the kernel always holds.
    unsafe { power::halt() }
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
