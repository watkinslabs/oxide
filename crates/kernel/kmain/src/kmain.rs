#![cfg(target_os = "oxide-kernel")]  // kernel-entry crate; oxide-kernel-only (wires hal/sched/tty live state)
// Kernel lib. Per-arch boot crates own _start; this lib hosts
// kernel_main. #![no_std]; oxide-kernel-only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// Anchor crates whose `#[no_mangle]` symbols the linker needs even
// without an explicit `use`. Per `52§8`.
#[cfg(target_os = "oxide-kernel")] extern crate fs;
#[cfg(target_os = "oxide-kernel")] extern crate arch_irq;

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
extern crate kmacros;

// Per `04§4.0` R06: trace-only modules are cfg-gated at decl.
// ACPI walker = `crates/firmware` (`33§R01`); ns inodes =
// `crates/nscg` (`26§R01`). Re-exports keep call sites stable.
pub use firmware::acpi;
#[cfg(target_os = "oxide-kernel")]
pub use nscg::proc_ns as dev_proc_ns;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub use ::sched::kthread;
#[cfg(target_os = "oxide-kernel")] pub use devfs;
#[cfg(target_os = "oxide-kernel")] pub use security::seccomp;
#[cfg(target_os = "oxide-kernel")] pub use security::bpf as dev_bpf;

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

/// Publish a boot-discovered platform device through the driver model.
/// Repeated boot wiring may reuse an identical model identity, but a conflicting
/// platform object is a kernel model error and must not be hidden.
/// # C: O(N_devices)
fn platform_device_or_panic(addr: &'static str) -> alloc::sync::Arc<drv::Device> {
    let candidate = alloc::sync::Arc::new(drv::Device::new(
        "platform",
        alloc::string::String::from(addr),
        0,
        0,
        0,
    ));
    match drv::try_device_add(alloc::sync::Arc::clone(&candidate)) {
        Ok(dev) => dev,
        Err(drv::Error::Busy) => {
            if let Some(existing) = drv::devices().into_iter().find(|d| {
                d.bus == "platform"
                    && d.addr == addr
                    && d.parent_bus.is_none()
                    && d.parent_addr.is_none()
                    && d.vendor_id == 0
                    && d.device_id == 0
                    && d.class == 0
                    && d.devname.is_none()
                    && d.resources.is_empty()
            }) {
                existing
            } else {
                panic!("conflicting platform device registration: {}", addr);
            }
        }
        Err(e) => panic!("platform device registration failed for {}: {:?}", addr, e),
    }
}

/// Kernel entry. Called by per-arch boot stub after low-level setup.
/// # SAFETY: caller set up a valid kernel stack, mapped the kernel image
/// upper-half per the linker script, set the per-CPU base, disabled IRQs;
/// `info` is a valid `BootInfo` with `memmap_count` entries at `memmap_ptr`.
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
            // B3.3: now that gs points at the BSP per-CPU area, seed its
            // syscall-kstack slot (gs:[8]). install_syscall_msrs ran in early
            // boot before gs was set, so it could not. Per-task tops overwrite
            // this on the first switch-to-user.
            // SAFETY: gs base just set to this CPU's per-CPU area.
            hal_x86_64::init_percpu_syscall_kstack(hal_x86_64::boot_syscall_kstack_top());
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: same — boot path single writer; per-CPU page initialised with cpu_id=0 at offset 0; called before any TPIDR_EL1 read.
        unsafe { use hal::CpuOps; hal_aarch64::ArmCpuOps::set_percpu_base(p); }
    }

    // vfs hooks: flock release-on-close + inotify IN_MODIFY-on-write
    // + pipe reader/writer close tracking (must register before any
    // pipe File can be dropped).
    #[cfg(target_os = "oxide-kernel")] fs::init();
    // Bring up the kernel heap before any subsystem that allocates.
    // SAFETY: kernel_main is called once per boot from a single CPU
    // with IRQs off; `STATIC_HEAP` is BSS-resident, exclusively owned
    // by `kalloc`, and not yet referenced by anything else.
    #[cfg(target_os = "oxide-kernel")]
    unsafe { GLOBAL_ALLOC.init_static() };

    #[cfg(target_os = "oxide-kernel")]
    klog::set_clock_fn(syscalls::vvar::monotonic_now_ns);

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
            unsafe { cpu::smp::set_boot_cpu_id(id); }
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
            pmm::boot::log_memmap(regions);
        }
    } else {
        debug_boot! { klog::kinfo!("memmap: absent"); }
    }

    // Bring up the physical memory manager.
    // SAFETY: kernel_main fn-contract; single-CPU, IRQs off, info
    // outlives the call.
    let pmm = unsafe { pmm::setup::init_from_boot_info(info) };
    // F428: reserve the x86 AP trampoline page (TRAMP_PA) from the PMM
    // BEFORE the first allocation, so `bring_up_aps_x86`'s blob copy can't
    // clobber a handed-out page. Must precede the grow hook + page_meta.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    if pmm.is_ok() {
        arch_irq::smp_x86::reserve_trampoline_page();
    }
    // F247 (T16): wire the kalloc grow hook FIRST, so allocations that
    // overflow the static heap route through PMM-allocated pages (HHDM).
    #[cfg(target_os = "oxide-kernel")]
    if pmm.is_ok() {
        GLOBAL_ALLOC.set_grow_hook(pmm::boot::kalloc_grow);
    }
    // PageMeta slab (≈0.59% of RAM) allocates AFTER the grow hook so it
    // can pull from PMM rather than exhausting the fixed static heap at
    // large RAM (gap-analysis M2: 64 MiB static heap caps this ~11 GiB).
    if pmm.is_ok() { pmm::setup::init_page_meta(pmm::setup::pfn_max_from_boot_info(info)); }
    debug_boot! {
        match &pmm {
            Ok(_)                                       => klog::kinfo!("pmm: ready"),
            Err(pmm::setup::SetupError::NoMemmap)        => klog::kinfo!("pmm: skip (no memmap)"),
            Err(pmm::setup::SetupError::NoHhdm)          => klog::kinfo!("pmm: skip (no hhdm)"),
            Err(pmm::setup::SetupError::NoUsableRegion)  => klog::kerror!("pmm: no usable region"),
            Err(pmm::setup::SetupError::NoSpaceForBitmaps) => klog::kerror!("pmm: pool too big"),
            Err(pmm::setup::SetupError::TooManyRegions)  => klog::kerror!("pmm: too many regions"),
            Err(pmm::setup::SetupError::PmmInit(_))      => klog::kerror!("pmm: Pmm::init refused"),
            Err(pmm::setup::SetupError::AlreadyInit)     => klog::kerror!("pmm: already init"),
        }
    }
    // Runtime smoke: alloc/free at order 0 to prove the buddy
    // machinery works after init. Removed once a real consumer
    // (slab) wires in.
    if let Ok(p) = pmm {
        debug_pmm! { smoke::pmm::run(p); }
        // In-guest full-RAM memtest (opt-in): drains all free pages, sweeps
        // moving-inversions over the real HHDM mapping, frees, conserves.
        #[cfg(feature = "debug-memtest")]
        smoke::memtest::run(p);

        // Wire MmuOps for this arch: stash HHDM + bare-fn frame
        // allocator. After this point the trait surface is live.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: single-CPU pre-init; PMM initialised above; HHDM offset comes from BootInfo and matches the live tables; alloc_raw_frame is a bare fn that wraps the just-initialised global PMM.
        unsafe {
            hal_x86_64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_x86_64::mmu_ops::set_frame_alloc(pmm::setup::alloc_raw_frame);
        }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: single-CPU pre-init; PMM initialised above; HHDM offset comes from BootInfo and matches the live tables; alloc_raw_frame is a bare fn that wraps the just-initialised global PMM.
        unsafe {
            hal_aarch64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_aarch64::mmu_ops::set_frame_alloc(pmm::setup::alloc_raw_frame);
        }
        let _ = p;

        // SMP-IST hardening (Stage 1): now the allocator is live, give the
        // BSP its per-CPU IST exception stacks (#DF/NMI/#DB/#MC) and point
        // the shared IDT gates at them. boot-x86_64 installed the TSS/IDT
        // with RSP0-only + ist=0; populate the BSP's TSS IST slots FIRST,
        // then patch the gates (else a fault would vector to a zero top).
        // Each AP does its own setup_ist_stacks in ap_main_x86 before `sti`;
        // the gates are shared so they're patched once here. A #DF/NMI on a
        // CPU mid kernel-stack-switch now lands on a known-good stack instead
        // of escalating to a triple fault (the late-boot -smp 2 flake).
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: single-CPU pre-init, IRQs masked; allocator live; BSP is
        // cpu 0; setup_ist_stacks(0) populates this CPU's TSS IST slots
        // before install_ist_gates patches the (shared) IDT gate indices.
        unsafe {
            hal_x86_64::setup_ist_stacks(0);
            hal_x86_64::install_ist_gates();
        }

        // Device bring-up: install Device-attr 4 KiB MMIO mappings
        // via the PMM-backed mapper, enable LAPIC/GIC/UART. The
        // bring-up is always-on; per-step diagnostic logs are gated
        // by per-subsystem `debug-vmm`/`debug-irq` features inside.
        // Map + enable LAPIC/HPET (x86) or GIC (arm) unconditionally:
        // the LAPIC-enable path inside owns LAPIC_BASE_VA, without which
        // `timer_periodic` (called from spawn-init below) silently no-
        // ops, no timer IRQs fire, and any CPU-bound user task hangs
        // forever (B14: login prompt wedge — getty spun in user mode
        // between stdio writevs because the scheduler never preempted).
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        smoke::device_map::smoke_device_map_x86(info.hhdm_offset);
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        smoke::device_map::smoke_device_map_arm(info.hhdm_offset);

        // MmuOps end-to-end smoke: map/write/translate/unmap a fresh
        // PMM frame at a scratch VA. Per-arch wrapper picks the
        // marker type implementing `MmuOps`.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64", feature = "debug-vmm"))]
        // SAFETY: PMM + MmuOps state initialised above; SCRATCH_VA disjoint from existing kernel mappings; single-CPU pre-init.
        unsafe { smoke::mmuops::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64", feature = "debug-vmm"))]
        // SAFETY: PMM + MmuOps state initialised above; SCRATCH_VA disjoint from existing kernel mappings; single-CPU pre-init.
        unsafe { smoke::mmuops::run::<hal_aarch64::mmu_ops::ArmMmu>(); }

        // User-page mapping smoke (P1-95 fix validation): map a 4 KiB
        // user VA with USER|EXEC|READ, verify translate round-trips
        // the USER+EXEC flags through real CR3 walk + interior U=1
        // propagation. CPL=3 access lands with P1-82.
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64", feature = "debug-vmm"))]
        // SAFETY: PMM + MmuOps state initialised above; USER_VA disjoint from kernel-half mappings; single-CPU pre-init.
        unsafe { smoke::user_map::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64", feature = "debug-vmm"))]
        // SAFETY: PMM + MmuOps state initialised above; USER_VA disjoint from kernel-half mappings; single-CPU pre-init.
        unsafe { smoke::user_map::run::<hal_aarch64::mmu_ops::ArmMmu>(); }
    }


    // kalloc smoke: insert a VMA into a `vmm::VmaTree`, exercising
    // the global allocator's `BTreeMap` path.
    #[cfg(target_os = "oxide-kernel")]
    {
        debug_boot! {
            let mut tree = vmm::VmaTree::new();
            // SAFETY: addresses within user-VA range (0x1000 < USER_VA_END).
            let start = hal::UserVirtAddr::new(0x1000).expect("test addr");
            let end   = hal::UserVirtAddr::new(0x2000).expect("test addr");
            let inserted = tree.insert(vmm::Vma::new(start, end, vmm::VmaProt::READ,
                vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS, vmm::VmaBacking::Anonymous)).is_ok();
            if inserted { klog::kinfo!("kalloc-smoke: VmaTree insert ok"); }
            else { klog::kerror!("kalloc-smoke: VmaTree insert failed"); }
        }
    }

    debug_sched! {
        // SAFETY: kernel_main pre-init phase; allocator up; single-CPU,
        // IRQs masked (x86 CLI path, arm DAIF.I masked again post-soak).
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            kthread::smoke();
            kthread::smoke_yield();
            smoke::ksched::smoke_rr(4);
            #[cfg(target_arch = "x86_64")]
            smoke::preempt::smoke_preempt_x86(4, 1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::preempt::smoke_preempt_arm(4, 50_000);
            // 64-task ctxsw register-canary per `14§8`. Bounded
            // version (CANARY_N × CANARY_ITERS); the 1h soak rides
            // background CI per `40§3`.
            #[cfg(target_arch = "x86_64")]
            smoke::canary::smoke_canary_x86(1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::canary::smoke_canary_arm(50_000);
        }
    }

    // Recoverable page-fault smoke (P1-86c). Validates the fault
    // dispatcher's `bool` retry path on a real demand-paged write.
    // Runs at CPL=0 so it doesn't depend on the userspace smoke.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64", feature = "debug-vmm"))]
    {
        // SAFETY: PMM + MmuOps initialised; FAULT_VA in the smoke's
        // private kernel-half slot; single-CPU; IRQs masked.
        unsafe { smoke::pf_recover::run(); }
    }

    // user AS + demand-paging fault hook per 11§3/11§5; must run
    // before any userspace smoke so mmap and #PF go through the real AS.
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: PMM up; HHDM offset known; single-CPU pre-init.
        unsafe { pmm::user_as::init(info.hhdm_offset); }
        // SAFETY: PMM up; HHDM offset just published; one-shot.
        unsafe { syscalls::vvar::init(); }
        procfs::hooks::set_boot_unix_secs_hook(syscalls::time::boot_unix_seconds);
        procfs::hooks::set_hostname_hooks(syscalls::hostname::snapshot_current, syscalls::hostname::set_current);
        procfs::hooks::set_cmdline_hook(crate::boot_cmdline::get);
        // debug-zerotrap: give the [ZEROTRAP] logger a current-tid getter.
        hal::zerotrap::set_tid_hook(zerotrap_tid);
        ::devfs::set_current_hooks(sched::live::current_mount_ns, sched::live::current_chroot_root);
        // device-model Stage C: wire the devtmpfs side of `drv::try_device_add`
        // BEFORE the built-in /dev registrants run below (console/mem/drm/fbdev
        // self-register via fallible model publication now, D27). The /sys side
        // (set_sysfs_hook) stays wired just before PCI enumeration — these early
        // pseudo-devices carry a non-pci/non-virtio bus that the /sys synthesis
        // ignores, so the devtmpfs hook is the only one they need at this phase.
        drv::set_devtmpfs_hook(devfs::add_device_node);
        drv::set_devtmpfs_del_hook(devfs::del_device_node);
        // Publish cmdline before /dev/console registers so the node follows
        // the preferred console from its first open.
        // SAFETY: boot-only single-writer, pre-userspace; install_arch_default is idempotent (no-op if the slot is set) and cannot race a procfs reader here.
        unsafe { crate::boot_cmdline::install_arch_default(); }
        console::register_devnodes(); ::devfs::boot::populate_defaults(); procfs::init();
        fs::tmpfs::init(); tracefs::init(); drv_virtio_input::devfs::init();
        drv_virtio_input::procfs::init();
        fbdev::devfs::init(); devpts::init();
        // boot smokes (debug-boot gated):
        debug_boot! {
            ::devfs::misc::smoke_test();
            procfs::smoke_test();
            fs::pipe::smoke_test();
            fs::tmpfs::smoke_test();
            devpts::smoke_test();
        }
        // P3-49 syscall coverage banner. Kept in sync by hand —
        // bumped whenever a new arm or compat-table entry lands.
        debug_boot! { klog::write_raw(b"[INFO]  syscall: ~200 slots wired (real impls + compat stubs)\n"); }
    }


    // Install BSP timer work: scheduler load sampling and display drains.
    // UART, PS/2, and virtio input delivery are owned by their drivers' IRQs.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    arch_irq::set_tick_poll_hook(tick_poll_combined);
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    arch_irq::set_tick_poll_hook(tick_poll_combined);
    // Cross-CPU backtrace poke (NMI on x86): lets the hard-lockup detector
    // + sysrq `<NUL>b` make a wedged CPU dump its own RIP/regs.
    #[cfg(target_os = "oxide-kernel")]
    arch_irq::install_diag_nmi_hook();
    // Feed the softirq restart gate its scheduler/time inputs (Linux
    // __do_softirq: need_resched + jiffies + wakeup_softirqd) so a
    // self-re-raising bottom half (virtio-net RX flood) can't livelock a CPU.
    #[cfg(target_os = "oxide-kernel")]
    arch_irq::install_softirq_hooks();

    // Wire the UART RX sink (tty line discipline), then register the
    // serial platform device and bind the active UART driver. The driver's
    // probe detects the UART (ACPI SPCR, else legacy 8250 scratch-probe
    // on x86) and only then installs the serial klog sink + RX IRQ. A
    // machine with no serial leaves platform/serial0 unbound.
    // Install the serial tty (`/dev/ttyS0`) on the new tty stack. The
    // framebuffer console (`/dev/console` by default on x86 QEMU) uses the
    // VT tty stack; serial remains a separate login/debug line. printk stays
    // separate (klog → UART sink below + fbcon aux sink); a tty write goes
    // through its owning TtyStruct, not into the kmsg ring.
    console::static_console::install();
    // The keyboard belongs to the VIDEO console: deliver keystrokes to the
    // FOREGROUND VT's tty (Linux `kbd_keycode` → fg console), NOT the serial
    // line. `kbd_input` routes to `vt_tty(foreground())`; serial RX has its
    // own path (`drv_serial` → ttyS0). This is what makes framebuffer login
    // type into the VT shown on screen.
    tty::live::set_kbd_sink(console::kbd_input);
    // Serial sysrq: snoop a magic console sequence (`<NUL> t` = task
    // dump) for on-demand liveness diagnostics, before bytes reach the
    // tty. Pairs with the per-tick liveness watchdog (`05`, `27`).
    drv_serial::set_rx_prefilter(sched::diag::sysrq_rx);
    drv_serial::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
    {
        let uart_drv = drv_serial::uart_driver();
        let dev = platform_device_or_panic("serial0");
        drv::register_driver(uart_drv);
        if dev.bound() == Some(drv::Driver::name(uart_drv)) {
            klog::set_byte_sink(drv_serial::emit);
        }
    }

    // Real i8042 PS/2 keyboard (x86 only — no i8042 on the arm boards).
    // Register the platform device + driver; driver-core attachment runs
    // Driver::probe, which brings up the controller and resets/identifies the
    // keyboard. Decoded scancodes feed the SAME input pipeline as virtio-input
    // (drv_virtio_input::drain::handle_key_event). The i8042 driver owns IRQ1
    // setup/teardown in probe/remove. A serial-only box with no PS/2 leaves
    // platform/i8042 unbound.
    #[cfg(target_arch = "x86_64")]
    {
        let ps2_drv = drv_ps2_keyboard::driver();
        drv_ps2_keyboard::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
        platform_device_or_panic("i8042");
        drv::register_driver(ps2_drv);
    }

    // SMP bring-up per `13§11`. With -smp 1 (default) the per-arch
    // path is a no-op. With -smp N>=2 the boot CPU starts each AP:
    //   x86_64: Limine SMP request — store our entry into each
    //           SmpInfoX86::goto_address so the parked AP jumps in.
    //   aarch64: PSCI CPU_ON for each enumerate_aps() entry.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: kernel_main post-init; Limine SMP response in info is bootloader-owned; boot CPU is sole writer for goto_address slots.
        let started = unsafe { arch_irq::smp_x86::bring_up_aps_x86(info) };
        debug_boot! {
            klog::write_raw(b"[INFO]  smp: cpus=");
            klog::write_dec_u64(info.smp_count);
            klog::write_raw(b" aps_started=");
            klog::write_dec_u64(started as u64);
            klog::write_raw(b"\n");
        }
        // Production scheduler hooks — installed UNCONDITIONALLY (not
        // gated on AP count): the periodic load balancer (`13§11`) sends
        // resched IPIs cross-CPU, and coredumps need the writer hook even
        // single-CPU. These were previously buried in the `started > 0`
        // migration smoke, so SMP=1 boots silently lacked them.
        // SAFETY: BSP post-init; install_default_runqueue is idempotent; the hooks swap 'static fn pointers.
        unsafe {
            sched::live::install_default_runqueue();
            sched::live::set_send_resched_ipi_hook(arch_irq::lapic::send_resched_ipi);
            pmm::user_as::set_coredump_hook(fs::coredump::write_for_current);
            // SMP TLB coherence (`20§5`): install the x86 cross-CPU TLB
            // shootdown so PTE downgrades/removals (fork COW W-strip,
            // mprotect, munmap, COW split) flush every OTHER online CPU's
            // stale translation — x86 has no hardware TLB broadcast. The
            // IDT 0x42 vector + every AP's online bit are live by here.
            arch_irq::tlb::install();
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
            while cpu::smp::online_count() < target && spins < 1_000_000 {
                core::hint::spin_loop();
                spins += 1;
            }
            // SAFETY: BSP holds boot context; LAPIC enabled; cpu_topology populated by ACPI walk.
            unsafe {
                let n = cpu::count() as usize;
                let bsp = cpu::smp::boot_cpu_id();
                for i in 0..n {
                    if let Some((id, _)) = cpu::get(i) {
                        if id != bsp {
                            let _ = arch_irq::lapic::send_resched_ipi(i as u32);
                        }
                    }
                }
            }
            // Brief settle for IPIs to deliver + handlers to run.
            for _ in 0..1_000_000u32 { core::hint::spin_loop(); }
            debug_boot! {
                use core::sync::atomic::Ordering;
                klog::write_raw(b"[INFO]  smp: ipi_smoke: online=");
                klog::write_dec_u64(cpu::smp::online_count() as u64);
                klog::write_raw(b" resched_ipis_received=");
                klog::write_dec_u64(arch_irq::lapic::RESCHED_IPI_COUNT.load(Ordering::Relaxed));
                klog::write_raw(b"\n");
            }
            // NOTE: the old boot-time migration smoke spawned permanent
            // `loop { hlt }` kthreads here to exercise balance_once. They
            // never exited, so once real scheduling started (run_as_task)
            // the picker switched into one and boot wedged — invisible
            // while the gate ran -smp 1 (this whole block was skipped).
            // Removed: balance_once now runs in production from the kthread
            // tick (F325), so no boot smoke is needed.
        }
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // Install the AP-init hook (per-AP GIC + runqueue, runs on the AP)
        // + the arm resched-IPI sender (GIC SGI) BEFORE bringing APs up.
        arch_irq::smp_arm::install_hooks();
        // EFI/GRUB path has no DTB /cpus → feed the ACPI-MADT GICC MPIDRs
        // (from the ACPI walk) into the PSCI params (no-op on the -kernel/DTB
        // path, which already has its MPIDR list).
        arch_irq::smp_arm::publish_madt_mpidrs();
        // PSCI SMP (Limine-free): boot-aarch64 published the self-boot page
        // tables + DTB `/cpus` MPIDRs via `set_psci_ap_params`. For each
        // non-BSP MPIDR we `CPU_ON` the AP into the MMU-off trampoline
        // `oxide_ap_entry_arm_psci`, which installs the kernel page tables
        // and reaches `ap_main`. No-op (SMP=1) when only the BSP is present.
        // SAFETY: kernel_main post-heap-init on the boot CPU; the self-boot
        // page tables named in the published params are live for boot.
        let started = unsafe { hal_aarch64::smp::bring_up_aps_psci() };
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
    ::sched::set_current_hook(|| sched::live::current());
    // SAFETY: kernel_main runs single-CPU pre-init; nscg::init reports ready (per-task ns slots set up by sched).
    let _ = unsafe { nscg::init() };
    // cgroup v2 (`26§4`): install the signal-delivery hook so
    // `cgroup.kill` can SIGKILL members, then mount the unified
    // hierarchy at /sys/fs/cgroup so the mount point exists for
    // userspace from boot. A later `mount -t cgroup2` is idempotent.
    sched::cgroup::install();
    cgroup::set_notify_hook(fs::inotify::fire_modify_path); // cgroup.events → inotify
    // cgroup2 mount moved BELOW (after the `/sys` register + root-dentry
    // provider install): the mount engine takes the walked mountpoint dentry,
    // so `/sys/fs/cgroup` must be resolvable first.
    // Permanent, `debug-cgroup`-gated boot self-test (`26§8`,
    // `docs/41`): exercise the cgroup v2 VFS path end-to-end via the
    // real mount-table lookup + inode read/write the userspace shell
    // uses, klogging PASS/FAIL. Deterministic early-boot validation
    // that doesn't depend on flaky userspace serial capture. Zero
    // codegen when the feature is off, like every other debug gate.
    debug_cgroup! { cgroup::selftest::run(); }
    // SAFETY: kernel_main runs single-CPU pre-init; security::init reports ready (per-task seccomp slot is None until prctl/seccomp installs).
    let _ = unsafe { security::init() };
    // SAFETY: kernel_main runs single-CPU pre-init; drv::init reports ready; per-driver register() happens during PCI enumeration.
    let _ = unsafe { drv::init() };
    power::set_driver_shutdown_hook(drv::shutdown_all);
    // drivers-plan D1a: wire the drv model's sysfs-publish hooks BEFORE
    // PCI enumeration so each `drv::try_device_add` during enumeration publishes
    // its `/sys/bus/<bus>/devices/<addr>` entry as it lands.
    drv::set_sysfs_hook(crate::sysfs::bus::publish_device_cb);
    drv::set_sysfs_remove_hook(crate::sysfs::bus::remove_device_cb);
    drv::set_driver_hook(crate::sysfs::bus::publish_driver_cb);
    drv::set_bind_hook(crate::sysfs::bus::bind_device_cb);
    // device-model Stage B: the devtmpfs side of `drv::try_device_add` is wired
    // EARLY (just after `devfs::set_current_hooks`, above) so the built-in
    // /dev registrants that now self-register via fallible model publication
    // (console/mem/drm/fbdev, Stage C) mint their nodes at boot. The
    // /sys-publish hooks here still precede PCI enumeration so each bus device's `/sys/bus/<bus>/
    // devices/<addr>` entry lands as it is enumerated.
    // Hardware bus drivers bind through the drv model during enumeration;
    // the old flat BDF probe registry path has been removed.
    // SAFETY: kernel_main runs single-CPU pre-init; vt::init allocates VT 1 + sets ACTIVE_VT.
    let _ = unsafe { vt::init() };
    // VT_PROCESS switch handshake (console-plan #6c): the vt layer signals a
    // VT's controlling owner (relsig on switch-away, acqsig on switch-to) via
    // this hook — keeps the vt crate free of a sched dependency.
    vt::set_signal_hook(|pid, signo| {
        if signo == 0 || signo > 64 { return; }
        if let Some(t) = sched::live::registry::lookup_by_vpid(pid) {
            t.sigpending.fetch_or(1u64 << (signo - 1), core::sync::atomic::Ordering::Release);
        }
    });
    // Owner-liveness hook (console-plan #6c): a VT_PROCESS owner is alive iff
    // the live task with this vpid still carries the recorded internal tid —
    // vpid is reusable, tid (monotonic NEXT_TID) is not. A dead owner must not
    // wedge VT switching, so the handshake switches immediately when this is
    // false.
    vt::set_owner_alive_hook(|vpid, tid| {
        sched::live::registry::lookup_by_vpid(vpid).map(|t| t.tid == tid).unwrap_or(false)
    });
    // Switch-completion hook (console-plan #6a): wake tasks blocked in
    // VT_WAITACTIVE once a (possibly deferred) switch lands.
    vt::set_switch_hook(|_n| syscalls::ioctl::vt_switch_wake());
    debug_boot! { klog::kinfo!("boot: kernel ready, halting"); }

    // ELF-loaded userspace via real Task on the runqueue (P2-13c).
    // Spawns the user task with mm=Arc<AddressSpace>, schedule()'s
    // into it via the IRQ-tail iretq path. Diverges at the ud2
    // landmark after sys_exit's sysretq.
    // PCI bus enumeration FIRST — both arches via `pci::enumerate`;
    // per-arch `ConfigSpaceReader` differs (x86 CF8/CFC, aarch64 ECAM
    // MMIO). This brings up virtio-blk (drv-virtio-blk registers each
    // device into `block::registry`, tagged with its GET_ID serial), so
    // the ext4 root mount below can bind the real `oxide-root` disk. The
    // root mount used to run ~100 lines before enumeration and consumed
    // a 256 MiB embedded blob; now the disk comes from virtio-blk.
    // Register loopback BEFORE PCI enumeration so `lo` claims ifindex 1 — the
    // Linux invariant. Enumeration registers eth0 (→ ifindex 2) and seeds the
    // netlink addr table, which needs `lo` already present to put 127.0.0.1 on
    // lo (not eth0). Idempotent (the later net::sock::init() is then a no-op).
    // SAFETY: post-allocator-up; no other CPU has run AF_INET syscalls yet.
    #[cfg(target_os = "oxide-kernel")]
    unsafe { net::sock::init(); }
    #[cfg(target_os = "oxide-kernel")]
    { crate::pci_boot::enumerate_and_log(); }

    // PCI enumeration spliced the device-MMIO BARs (virtio-gpu/net/blk
    // notify + cfg regions, 0xffff_fd00…) into the ACTIVE boot-AS root —
    // NOT into the kernel master PML4, which APs already booted on
    // (smp_x86 loads `kernel_master()` as the AP CR3). So an AP in kernel
    // context (e.g. the fbcon GPU-flush softirq on an idle AP) would #PF NP
    // on a BAR. Re-sync the master's kernel-half PML4 entries from the
    // active root in place — the APs share that master frame and never
    // cached the BAR VAs, so they pick up the entries on first walk.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: boot path; APs spin in their park loop; master frame is the one
    // they CR3 to; copying kernel-half entries (shared L3s) into it.
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }

    // Mount the ext4 root fs from the virtio-blk disk (serial
    // `oxide-root`). Linux's CONFIG_EXT4_FS=y equivalent: real driver
    // from crates/ext4 built into the kernel, backed by a real disk.
    // No-op if already mounted.
    // SAFETY: post-PMM/allocator init; PCI enumeration above registered
    // the virtio-blk devices; no other CPU has yet observed ROOT.
    #[cfg(target_os = "oxide-kernel")]
    unsafe {
        let root_dev = block::registry::by_serial("oxide-root")
            .or_else(block::registry::first_device)
            .expect("root disk (virtio-blk serial=oxide-root) not found");
        ext4::rootfs::init_from_dev(root_dev)
            .expect("ext4 root mount (oxide-root) failed to open");
        net::sock::init();
        // F150: install the iface-primary-IP hook so socket_sendto can
        // pick the right outbound src IP for routed (non-loopback) dst.
        net::sock::set_iface_primary_ip_hook(crate::syscalls::siocgif::iface_primary_ip_hook);
        net::iface_addr::set_addr_change_hook(crate::syscalls::siocgif::ipv4_addr_change_hook);
        modules::registry::init_exports();
        // Install the VFS walk hooks + mount-ns provider + dentry resolver
        // FIRST, so each `register` below wires its dentry-identity mount
        // crossing (`docs/16§3`) at mount time. (Was after the mounts, which
        // left boot mounts un-wired for dentry crossing.)
        crate::syscalls::mount::install_vfs_hooks();
        // Register every FS backend with the unified mount table per docs/16.
        // The mount engine takes the WALKED mountpoint dentry (Linux
        // `mnt_set_mountpoint`), NOT a path string — `boot_register*` below do
        // the single namei walk (`vfs::resolve_path_dentry`) each handler does
        // and hand the dentry in. Order matters: each mountpoint's underlay
        // must already be resolvable (`/` first; `/dev/shm` underlay dir is
        // pre-created in devfs::boot). `/` has no mountpoint dentry → `None`.
        let _ = vfs::mount::register(None, alloc::sync::Arc::new(ext4::rootfs::Ext4RootfsFs));
        boot_register("/dev",  alloc::sync::Arc::new(::devfs::DevfsFs));
        boot_register("/proc", alloc::sync::Arc::new(procfs::fs_impl::ProcfsFs));
        boot_register("/sys",  alloc::sync::Arc::new(crate::sysfs::SysfsFs));
        // cgroup2 at /sys/fs/cgroup — now that `/sys` is mounted and the root
        // provider is installed, its mountpoint dentry resolves (was an early
        // pre-provider mount repaired by the now-deleted `rewire_all_crossings`).
        cgroup::mount_root();
        // tmpfs boot mounts carry their per-mount root inode (Linux
        // `sb->s_root`) so the path walk crosses into them and resolves
        // per-component via `TmpfsRootInode::lookup` — no whole-path
        // `FileSystem::lookup` fallback. Same shape `mount_fstype` uses for
        // userspace `mount -t tmpfs`.
        // Each tmpfs mount is its own instance owning its own `TmpfsDir` tree
        // under its SuperBlock (per-instance `s_dev`, no shared registry).
        let tmp = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/tmp"));
        let tmp_root = tmp.root_inode();
        boot_register_bind("/tmp", tmp, tmp_root);
        // POSIX shm + systemd /run live on tmpfs. The walk crosses into them
        // by dentry identity, so paths resolve through the tmpfs root inode.
        // Without this `shm_open(3)` (which musl routes to `/dev/shm/<name>`)
        // hits DevfsFs and ENOENTs.
        let shm = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/dev/shm"));
        let shm_root = shm.root_inode();
        boot_register_bind("/dev/shm", shm, shm_root);
        let run = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/run"));
        let run_root = run.root_inode();
        boot_register_bind("/run", run, run_root);
        // /home from its own virtio-blk disk (serial `oxide-home`), as a
        // self-contained `Ext4Mount` (own device/cache/orphan set, never
        // aliasing the root). Graceful: a missing home disk leaves /home
        // resolving through the root fs rather than panicking, since it's
        // not required for login.
        if let Some(home_dev) = block::registry::by_serial("oxide-home") {
            if let Ok(home_fs) = ext4::rootfs::Ext4Mount::open(home_dev) {
                boot_register("/home", home_fs);
            }
        }
        // cgroup v2 self-test runs here — after /proc + /sys/fs/cgroup
        // are in the mount table so `/proc/self/cgroup` resolves.
        debug_cgroup! { cgroup::selftest::run(); }
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
            // ext4's extent walker + the virtio-blk write path.
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
            // F96: install netfilter NFNL handler. The netlink
            // crate can't depend on netfilter (circular), so the
            // kernel side wires the fn pointer at boot.
            netlink::install_netfilter_handler(netfilter::handle);
            // F104: nftables packet-path enforcement. Bridge the
            // netfilter eval() into net::stack via a fn pointer so
            // the net crate stays independent of netfilter.
            net::stack::install_nf_hook(|h, p, fam| netfilter::eval(h, p, fam).as_u32());
            // SO_ATTACH_BPF socket filters: run the eBPF program over each
            // inbound datagram; r0 != 0 accepts, 0 drops.
            net::stack::install_bpf_filter_runner(
                |insns, pkt| security::bpf_interp::run(insns, pkt).map_or(false, |r| r != 0));
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

    // (PCI enumeration moved earlier — before the ext4 root mount —
    // so virtio-blk is up to back the root disk.)

    // Load the rootfs-resident keyboard layout. Linux pattern:
    // /etc/keymap is the active map; /usr/share/keymaps/*.kmap is
    // the library. Falls through silently if the file is missing —
    // virtio-input drops EV_KEY events on the floor until a map is
    // loaded, which is the right failure mode (no garbage input).
    #[cfg(target_os = "oxide-kernel")]
    if let Some(blob) = ext4::rootfs::read_file(b"/etc/keymap") {
        match drv_virtio_input::keymap::load_text(&blob) {
            Ok(name) => { debug_boot! {
                klog::write_raw(b"[INFO]  keymap loaded: ");
                klog::write_raw(name.as_bytes());
                klog::write_raw(b"\n");
            } }
            Err(_) => { debug_boot! {
                klog::write_raw(b"[WARN]  /etc/keymap: parse error\n");
            } }
        }
    }

    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        debug_boot! { klog::write_raw(b"[INFO]  init: handoff begin\n"); }
        // F50: install per-arch user-trap hook BEFORE any user task
        // runs so PTRACE_SINGLESTEP #DB delivers SIGTRAP instead of
        // halting the kernel via the default fault path.
        // SAFETY: pre-init single-CPU; ptrace_singlestep::install is idempotent and only swaps a 'static fn pointer.
        unsafe { fs::ptrace::install(); }
        // DIAG (debug-mount): chain the libc-lock-page single-step write-trap
        // #DB hook AFTER ptrace's so it delegates to ptrace when idle.
        #[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
        pmm::user_as::install_lock_step_hook();
        // SAFETY: every prerequisite established above — kernel-owned
        // GDT (P1-93), TSS+ltr (P1-94), interior-U=1 walker (P1-95),
        // PMM + MmuOps + per-AS PT root (P2-19) + ELF loader (P2-16)
        // + runqueue (P2-13b) initialised; single-CPU; IRQs masked.
        unsafe { smoke::elf::run_as_task(info.hhdm_offset); }
    }

    // First ELF-loaded userspace per docs/31 (P2-16c) on aarch64.
    // Diverges via the deliberate brk landmark after sys_exit's
    // eret. Parallel to the x86_64 elf_smoke path; uses
    // `VmaBacking::KernelBytes` + demand-paging through the AS.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // SAFETY: PMM + MmuOps + VBAR_EL1 + per-AS PT root (P2-19) +
        // SVC dispatch all initialised; single-CPU; DAIF.I masked.
        unsafe { smoke::elf_arm::run(); }
    }

    #[cfg(target_os = "oxide-kernel")] sched::live::spawn_timer_driver();
    // ksoftirqd: process-context softirq drainer the restart gate defers to
    // (Linux wakeup_softirqd target). Installs the softirq wakeup hook.
    #[cfg(target_os = "oxide-kernel")] sched::live::spawn_ksoftirqd();
    sched::halt_forever()
}



// Subsystem crates re-exported so `crate::*` call sites resolve.
#[cfg(target_os = "oxide-kernel")] pub use syscalls;
#[cfg(target_os = "oxide-kernel")] pub use procfs;
#[cfg(target_os = "oxide-kernel")] pub use sysfs;
#[cfg(target_os = "oxide-kernel")] pub use cmdline as boot_cmdline;
#[cfg(target_os = "oxide-kernel")] pub use pci_boot;

/// Cooperative-yield hook for fbdev's FBIO_WAITFORVSYNC wait loop: voluntarily
/// Boot mount registration: do the single namei walk to the mountpoint
/// dentry (the mount engine takes the WALKED dentry, Linux
/// `mnt_set_mountpoint` — never a path string) and register only if it
/// resolves. A missing underlay is SKIPPED rather than passed as `None`,
/// which the engine reads as the namespace root. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register(path: &str, fs: alloc::sync::Arc<dyn vfs::fs::FileSystem>) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        let _ = vfs::mount::register(Some(d), fs);
    }
}

/// Boot bind-mount registration (per-mount root inode), same walk-then-attach
/// contract as `boot_register`. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register_bind(path: &str, fs: alloc::sync::Arc<dyn vfs::fs::FileSystem>, root: vfs::InodeRef) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        let _ = vfs::mount::register_bind(Some(d), fs, root);
    }
}

/// Combined timer-tick hook: run BSP timer device work and drain any pending
/// fbcon writes onto the GPU display.
/// # SAFETY: timer-ISR context per the hook contract.
/// # C: O(1) typical; O(xres*yres) on dirty fbcon repaint.
#[cfg(target_os = "oxide-kernel")]
unsafe fn tick_poll_combined(_from_user: bool) {
    // NOTE: /proc/stat per-CPU cputime accounting (cpustat::account) moved to
    // the timer ISR (arch_irq lapic/gic) so it runs on EVERY CPU — this hook
    // is BSP-only (device polling), which left APs' cpuN buckets at zero.
    // Load average (1/5/15 min EWMA, resampled ~every 5s — self-gated on the
    // monotonic clock, so the per-tick cost is one compare).
    {
        use hal::TimerOps;
        #[cfg(target_arch = "x86_64")]
        let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        sched::loadavg::tick(now);
    }
    fbcon::kernel::tick_drain();
    // D6: advance the pseudo-vblank counter at the tick rate — the honest
    // virtual-GPU vsync cadence that FBIO_WAITFORVSYNC blocks on and
    // FBIOGET_VBLANK reports as the running frame count.
    fbdev::vblank_tick();
    // B14: subreap orphan/abandoned zombies. Without this, sshd-
    // session children whose parent doesn't wait4 within 5s pile
    // up in ZOMBIES at ~340 KB each (Task struct + 16KB kernel
    // stack), causing TCG ARM smoke to bog down past ~14 sessions.
    sched::live::zombies::reap_orphans();
    // F169/B20: wake tasks past wakeup_deadline_ns (SO_*TIMEO) or
    // alarm_ns (alarm/itimer). Dead since F152 retired the rx kthread.
    let now_ns = syscalls::vvar::monotonic_now_ns();
    sched::live::tick_wake_expired(now_ns);
    // Liveness watchdog (`05`): fire a one-shot soft-lockup banner +
    // task dump if a Runnable task monopolises the CPU with no
    // reschedule past the stall threshold. Silent on a healthy boot.
    sched::diag::watchdog_tick(now_ns);
    // Refresh the vDSO vvar page with the live monotonic clock so
    // userspace __vdso_clock_gettime returns current time without
    // a syscall. Cheap (one TimerOps read + 4 atomic stores).
    syscalls::vvar::publish();
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


/// debug-zerotrap tid getter (fn-pointer, no capture). # C: O(1)
fn zerotrap_tid() -> u32 { sched::live::current().map(|c| c.tid).unwrap_or(0) }
