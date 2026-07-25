use crate::{BootInfo, BootMemRegion, GLOBAL_ALLOC, zerotrap_tid};
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
use crate::kthread;

/// Early boot bring-up before runtime device and filesystem init.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init(info: &BootInfo) {
    init_boot_percpu();

    fs::init();
    // SAFETY: kernel_main is called once per boot from a single CPU
    // with IRQs off; `STATIC_HEAP` is BSS-resident, exclusively owned
    // by `kalloc`, and not yet referenced by anything else.
    unsafe { GLOBAL_ALLOC.init_static() };
    // Boot performs kernel-owned allocation before any task can run. This scope
    // ends before scheduler/userspace handoff; syscall/task boundaries install
    // and restore their own contexts later.
    let _boot_alloc = GLOBAL_ALLOC.enter_context(kalloc::AllocationContext::memcg(cgroup::kernel_context_memcg()));
    klog::set_clock_fn(syscalls::vvar::monotonic_now_ns);

    log_boot_info(info);
    init_pmm_and_arch(info);
    kalloc_smoke();
    debug_sched_smokes();
    debug_pf_smoke();

    // SAFETY: PMM up; HHDM offset known; single-CPU pre-init.
    unsafe { pmm::user_as::init(info.hhdm_offset); }
    // SAFETY: PMM up; HHDM offset just published; one-shot.
    unsafe { syscalls::vvar::init(); }
    procfs::hooks::set_boot_unix_secs_hook(syscalls::time::boot_unix_seconds);
    procfs::hooks::set_hostname_hooks(syscalls::hostname::snapshot_current, syscalls::hostname::set_current);
    procfs::hooks::set_domainname_hooks(syscalls::hostname::domain_snapshot_current, syscalls::hostname::domain_set_current);
    procfs::hooks::set_cmdline_hook(crate::boot_cmdline::get);
    fs::coredump::register_core_hooks();
    hal::zerotrap::set_tid_hook(zerotrap_tid);
    ::devfs::set_current_hooks(sched::live::current_mount_ns, sched::live::current_chroot_root);
    drv::set_devtmpfs_hook(devfs::add_device_node);
    drv::set_devtmpfs_del_hook(devfs::del_device_node);
    // SAFETY: boot-only single-writer, pre-userspace; install_arch_default is idempotent (no-op if the slot is set) and cannot race a procfs reader here.
    unsafe { crate::boot_cmdline::install_arch_default(); }
    console::register_devnodes(); ::devfs::boot::populate_defaults(); procfs::init();
    syscalls::init_wall_clock_from_rtc();
    fs::tmpfs::init(); fs::fuse::register(); tracefs::init(); drv_virtio_input::devfs::init();
    drv_virtio_input::procfs::init();
    fbdev::devfs::init(); devpts::init();
    debug_boot_smokes();
}

#[cfg(target_os = "oxide-kernel")]
fn init_boot_percpu() {
    #[repr(align(16))]
    struct PerCpuBootPage(core::cell::UnsafeCell<[u8; 4096]>);
    // SAFETY: BSS-resident; sole writer is the boot CPU during its own bring-up here, before any other context can observe the cell.
    unsafe impl Sync for PerCpuBootPage {}
    static BOOT_PERCPU: PerCpuBootPage =
        PerCpuBootPage(core::cell::UnsafeCell::new([0u8; 4096]));

    let p = BOOT_PERCPU.0.get() as *mut u8;
    // SAFETY: BSS-resident page; this is the boot path's single writer; cpu_id=0 stamped at offset 0 matches `current_cpu`'s gs:0 (x86) / TPIDR_EL1 (arm) read.
    unsafe { core::ptr::write_volatile(p as *mut u32, 0u32); }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use hal::CpuOps;
        let mut cr4: u64;
        core::arch::asm!("mov {cr4}, cr4", cr4 = out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1u64 << 16;
        core::arch::asm!("mov cr4, {cr4}", cr4 = in(reg) cr4, options(nomem, nostack, preserves_flags));
        hal_x86_64::X86CpuOps::set_percpu_base(p);
        hal_x86_64::init_percpu_syscall_kstack(hal_x86_64::boot_syscall_kstack_top());
    }
    #[cfg(target_arch = "aarch64")]
    unsafe { use hal::CpuOps; hal_aarch64::ArmCpuOps::set_percpu_base(p); }
}

#[cfg(target_os = "oxide-kernel")]
fn log_boot_info(info: &BootInfo) {
    // Boot CPU identity is part of the handoff, not an ACPI side effect. DT-only
    // arm boots have no RSDP; leaving BOOT_CPU_ID unset makes every timer IRQ
    // fail the BSP gate, so deadline, watchdog, and device tick work never run.
    // SAFETY: single boot CPU before AP bring-up; this is the sole writer.
    unsafe { cpu::smp::set_boot_cpu_id(info.bsp_lapic_id); }
    debug_boot! { klog::kinfo!("init started"); }
    debug_boot! {
        if info.hhdm_offset != 0 { klog::kinfo!("hhdm: present"); }
        else { klog::kinfo!("hhdm: absent"); }
    }
    if info.rsdp_pa != 0 {
        debug_acpi! {
            klog::write_raw(b"[INFO]  rsdp: ");
            klog::write_hex_u64(info.rsdp_pa);
            klog::write_raw(b"\n");
        }
        firmware::set_add_cpu_hook(cpu::add_cpu);
        // SAFETY: `info.rsdp_pa` is the Limine-supplied kernel VA
        // for the RSDP (HHDM-mapped); the bootloader keeps the
        // backing memory alive past kernel handoff per `36§3`.
        unsafe { firmware::try_log_acpi(info.rsdp_pa, info.hhdm_offset); }
    } else {
        debug_boot! { klog::kinfo!("rsdp: absent"); }
    }
    // SMBIOS/DMI decode (independent of ACPI/RSDP): populate /sys/class/dmi/id/*
    // so systemd-detect-virt identifies the QEMU/KVM VM via `sys_vendor`/
    // `product_name`. Without it detect_vm() returns NONE.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the legacy BIOS ROM area [0xF0000,0x100000) is HHDM-mapped readable
    // per the boot handoff; init_x86 bounds every read to that window and to the
    // SMBIOS structure-table length declared in the anchor.
    unsafe { firmware::smbios::init_x86(info.hhdm_offset); }
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
}

#[cfg(target_os = "oxide-kernel")]
fn init_pmm_and_arch(info: &BootInfo) {
    // SAFETY: kernel_main fn-contract; single-CPU, IRQs off, info
    // outlives the call.
    let pmm = unsafe { pmm::setup::init_from_boot_info(info) };
    #[cfg(feature = "debug-zram-lifecycle")]
    if pmm.is_ok() { klog::write_raw(b"[KALLOC] pmm-ready\n"); }
    #[cfg(feature = "debug-zram-lifecycle")]
    if pmm.is_err() { klog::write_raw(b"[KALLOC] pmm-unavailable\n"); }
    #[cfg(target_arch = "x86_64")]
    if pmm.is_ok() { arch_irq::smp_x86::reserve_trampoline_page(); }
    if pmm.is_ok() {
        // `init_from_boot_info` has already reserved and published the PMM's
        // canonical struct-page array directly from the boot map. Only now
        // may a heap-growth allocation receive PMM frames.
        GLOBAL_ALLOC.set_grow_hook(pmm::boot::kalloc_grow);
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        kalloc::set_corruption_probe_hook(pmm::boot::corruption_probe);
        // B1347: name the running context at an EARLY-detected free-list
        // corruption (periodic_validate_diag), to separate the stale-pointer
        // WRITER's syscall/IRQ context from the later zram-disksize stumble.
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        kalloc::set_current_ctx_hook(kalloc_current_ctx);
        // B1347: surface the hard-IRQ arrival counter+vector to kalloc so a
        // detection can tell whether an IRQ fired in the write window (hard IRQs
        // don't set preempt_count's hardirq bits, so ctx.in_irq can't see them).
        #[cfg(all(target_arch = "x86_64", any(feature = "debug-heappoison", feature = "debug-dealloc-diag")))]
        kalloc::set_irq_info_hook(kalloc_irq_info);
        // Kalloc corruption hunt: wire kalloc's just-freed-block hook to the
        // x86_64 DR0/DR1 watchpoint arming bridge so a stray write to a freed
        // HoleHdr #DB-traps and hal-x86_64 prints the writer rip ([HWWP]).
        #[cfg(all(target_arch = "x86_64", feature = "debug-hw-watchpoint"))]
        kalloc::set_watchpoint_hook(pmm::boot::watchpoint_arm);
        #[cfg(all(target_arch = "x86_64", feature = "debug-hw-watchpoint"))]
        kalloc::set_watchpoint_disarm_hook(pmm::boot::watchpoint_disarm);
        #[cfg(feature = "debug-zram-lifecycle")]
        klog::write_raw(b"[KALLOC] growth-hook-installed\n");
    }
    if pmm.is_ok() { GLOBAL_ALLOC.install_global(); }
    // Make the heap IRQ-atomic: IRQ-context allocators exist (the timer-ISR
    // deferred wake pushes to a per-CPU Vec that can realloc), so alloc/dealloc
    // must disable IRQs across the whole op — else the plain hole-list Spinlock
    // deadlocks (ISR spins on the mainline-held lock) or re-enters in the grow
    // window. Installed after IRQs are set up; safe (IRQs are still off now).
    if pmm.is_ok() {
        use hal::CpuOps;
        use sync::IrqGate;
        #[cfg(target_arch = "x86_64")]
        GLOBAL_ALLOC.set_context_cpu_hook(|| hal_x86_64::X86CpuOps::current_cpu() as u16);
        #[cfg(target_arch = "x86_64")]
        GLOBAL_ALLOC.set_irq_gate(
            || unsafe { hal_x86_64::X86IrqGate::save_disable() },
            |f| unsafe { hal_x86_64::X86IrqGate::restore(f) },
        );
        #[cfg(target_arch = "aarch64")]
        GLOBAL_ALLOC.set_context_cpu_hook(|| hal_aarch64::ArmCpuOps::current_cpu() as u16);
        #[cfg(target_arch = "aarch64")]
        GLOBAL_ALLOC.set_irq_gate(
            || unsafe { hal_aarch64::ArmIrqGate::save_disable() },
            |f| unsafe { hal_aarch64::ArmIrqGate::restore(f) },
        );
        GLOBAL_ALLOC.require_context_for_growth();
    }
    if pmm.is_ok() {
        pmm::install_memcg_pressure_policy();
        // PMM is the sole physical zspage owner. zram device publication is
        // later than early PMM setup, so it cannot fall back to heap storage.
        pmm::kassert!(drv_zram::install_page_provider(drv_zram::PageProvider::new_movable(
            pmm::setup::alloc_object_frame, pmm::setup::release_object_frame,
            pmm::setup::frame_ptr, pmm::setup::try_lock_page, pmm::setup::unlock_page,
            pmm::movable::register, pmm::movable::unregister, pmm::setup::alloc_movable_object_frame,
            pmm::setup::release_movable_object_frame,
        )).is_ok(), "zram PMM page-provider installation");
        pmm::kassert!(pmm::shrinker::register_shrinker(pmm::shrinker::Shrinker {
            count_objects: drv_zram::reclaimable_pages,
            scan_objects: drv_zram::reclaim_pages,
        }).is_ok(), "zram shrinker registration");
    }
    debug_boot! {
        match &pmm {
            Ok(_)                                       => klog::kinfo!("pmm: ready"),
            Err(pmm::setup::SetupError::NoMemmap)        => klog::kinfo!("pmm: skip (no memmap)"),
            Err(pmm::setup::SetupError::NoHhdm)          => klog::kinfo!("pmm: skip (no hhdm)"),
            Err(pmm::setup::SetupError::NoUsableRegion)  => klog::kerror!("pmm: no usable region"),
            Err(pmm::setup::SetupError::NoSpaceForBitmaps) => klog::kerror!("pmm: pool too big"),
            Err(pmm::setup::SetupError::NoSpaceForPageMeta) => klog::kerror!("pmm: struct-page pool too big"),
            Err(pmm::setup::SetupError::TooManyRegions)  => klog::kerror!("pmm: too many regions"),
            Err(pmm::setup::SetupError::PmmInit(_))      => klog::kerror!("pmm: Pmm::init refused"),
            Err(pmm::setup::SetupError::AlreadyInit)     => klog::kerror!("pmm: already init"),
        }
    }
    if let Ok(p) = pmm {
        debug_pmm! { smoke::pmm::run(p); }
        #[cfg(feature = "debug-memtest")]
        smoke::memtest::run(p);
        #[cfg(target_arch = "x86_64")]
        unsafe {
            hal_x86_64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_x86_64::mmu_ops::set_frame_alloc(pmm::setup::alloc_page_table_frame);
            hal_x86_64::setup_ist_stacks(0);
            hal_x86_64::install_ist_gates();
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            hal_aarch64::mmu_ops::set_hhdm_offset(info.hhdm_offset);
            hal_aarch64::mmu_ops::set_frame_alloc(pmm::setup::alloc_page_table_frame);
        }
        // C213: arm the electric-fence guard arena. Must follow set_hhdm_offset
        // + set_frame_alloc (MmuOps::map needs both) and the heap being global;
        // still early — before the heavy allocation burst + first user fork, so
        // early small objects get fenced and the arena's kernel-half PT entries
        // land in the master every later AS copies. No-op unless debug-efence.
        efence::init();
        // C213: arm guard-paged kernel stacks (Linux CONFIG_VMAP_STACK) before
        // ANY task spawn. sched can't depend on pmm (pmm depends on sched), so
        // it takes the physical frames via this hook; page mapping uses the HAL
        // MmuOps sched already has. An overflow now #PFs on the guard page
        // instead of silently scribbling the adjacent heap block.
        ::sched::kstack::init(pmm::setup::alloc_raw_frame, |pa| unsafe { pmm::setup::free_one_frame(pa) });
        // debug-armctx: arm the aarch64 register-corruption post-mortem (fatal-
        // fault dump of kstack-slot ownership + arch_ctx + the switch ring).
        #[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
        ::sched::live::schedule::ctxprobe::install();
        // F699: arm the BSP's per-CPU IRQ stack (guard-paged, leaked) so the
        // IRQ handler + do_softirq re-entry relocate off the interrupted task
        // kstack once IRQs run in kernel context — the overflow fix. The
        // guard-paged allocator is live (just inited); gs/TPIDR were set in
        // init_boot_percpu; IRQs are still masked this early. `None` (frame
        // exhaustion) leaves the slot 0 ⇒ dispatcher stays on the interrupted
        // stack (pre-fix behavior, no crash).
        match ::sched::kstack::alloc_leaked_top() {
            Some(top) => {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: BSP gs base set in init_boot_percpu; `top` outlives the kernel.
                unsafe { hal_x86_64::init_percpu_hardirq_stack(top); }
                #[cfg(target_arch = "aarch64")]
                hal_aarch64::set_irq_stack_top(top);
            }
            None => klog::write_raw(b"[IRQSTK] BSP hardirq stack alloc failed; on task stack\n"),
        }
        #[cfg(target_arch = "x86_64")]
        smoke::device_map::smoke_device_map_x86(info.hhdm_offset);
        #[cfg(target_arch = "aarch64")]
        smoke::device_map::smoke_device_map_arm(info.hhdm_offset);
        #[cfg(all(target_arch = "x86_64", feature = "debug-vmm"))]
        unsafe { smoke::mmuops::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_arch = "aarch64", feature = "debug-vmm"))]
        unsafe { smoke::mmuops::run::<hal_aarch64::mmu_ops::ArmMmu>(); }
        #[cfg(all(target_arch = "x86_64", feature = "debug-vmm"))]
        unsafe { smoke::user_map::run::<hal_x86_64::mmu_ops::X86Mmu>(); }
        #[cfg(all(target_arch = "aarch64", feature = "debug-vmm"))]
        unsafe { smoke::user_map::run::<hal_aarch64::mmu_ops::ArmMmu>(); }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn kalloc_smoke() {
    debug_boot! {
        let mut tree = vmm::VmaTree::new();
        let start = hal::UserVirtAddr::new(0x1000).expect("test addr");
        let end   = hal::UserVirtAddr::new(0x2000).expect("test addr");
        let inserted = tree.insert(vmm::Vma::new(start, end, vmm::VmaProt::READ,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS, vmm::VmaBacking::Anonymous)).is_ok();
        if inserted { klog::kinfo!("kalloc-smoke: VmaTree insert ok"); }
        else { klog::kerror!("kalloc-smoke: VmaTree insert failed"); }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn debug_sched_smokes() {
    debug_sched! {
        unsafe {
            kthread::smoke();
            kthread::smoke_yield();
            smoke::ksched::smoke_rr(4);
            #[cfg(target_arch = "x86_64")]
            smoke::preempt::smoke_preempt_x86(4, 1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::preempt::smoke_preempt_arm(4, 50_000);
            #[cfg(target_arch = "x86_64")]
            smoke::canary::smoke_canary_x86(1_000_000);
            #[cfg(target_arch = "aarch64")]
            smoke::canary::smoke_canary_arm(50_000);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn debug_pf_smoke() {
    #[cfg(all(target_arch = "x86_64", feature = "debug-vmm"))]
    unsafe { smoke::pf_recover::run(); }
}

/// B1347: pack the running task's context for kalloc's diag-validate capture:
/// bits[63:40]=`preempt_count`(24), [39:20]=`last_syscall_nr`(20), [19:0]=`tid`(20);
/// `u64::MAX` when no task is current (very-early boot / idle loop). # C: O(1)
#[cfg(all(target_os = "oxide-kernel", any(feature = "debug-heappoison", feature = "debug-dealloc-diag")))]
fn kalloc_current_ctx() -> u64 {
    match sched::current() {
        Some(t) => {
            let tid = (t.tid as u64) & 0xF_FFFF;
            let sc = ((t.last_syscall_nr.load(core::sync::atomic::Ordering::Relaxed) as u64) & 0xF_FFFF) << 20;
            let pc = ((sched::preempt::preempt_count() as u64) & 0xFF_FFFF) << 40;
            pc | sc | tid
        }
        None => u64::MAX,
    }
}

/// B1347: pack the hard-IRQ arrival counter + last vector `(IRQ_SEQ << 8) | vec`
/// from the arch IRQ dispatcher, for kalloc's corruption detector. # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", any(feature = "debug-heappoison", feature = "debug-dealloc-diag")))]
fn kalloc_irq_info() -> u64 {
    use core::sync::atomic::Ordering;
    (arch_irq::lapic::IRQ_SEQ.load(Ordering::Acquire) << 8)
        | (arch_irq::lapic::IRQ_LAST_VEC.load(Ordering::Acquire) & 0xff)
}

#[cfg(target_os = "oxide-kernel")]
fn debug_boot_smokes() {
    debug_boot! {
        ::devfs::misc::smoke_test();
        procfs::smoke_test();
        fs::pipe::smoke_test();
        fs::tmpfs::smoke_test();
        devpts::smoke_test();
    }
    debug_boot! { klog::write_raw(b"[INFO]  syscall: ~200 slots wired (real impls + compat stubs)\n"); }
}
