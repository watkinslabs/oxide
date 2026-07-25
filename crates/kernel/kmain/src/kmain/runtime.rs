use crate::{BootInfo, tick_poll_combined};

/// Runtime hook, console, device, and SMP bring-up.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init(info: &BootInfo) {
    arch_irq::set_tick_poll_hook(tick_poll_combined);
    arch_irq::install_timer_deadline_hook();
    arch_irq::install_diag_nmi_hook();
    arch_irq::install_softirq_hooks();

    console::static_console::install();
    tty::live::set_kbd_sink(console::kbd_input);
    // VT owns the canonical foreground console; sysfs only exposes it.
    sysfs::tty::set_active_vt_hook(vt::active);
    drv_serial::set_rx_prefilter(sched::diag::sysrq_rx);
    drv_serial::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
    install_drv_sysfs_hooks();
    init_serial_console();
    init_ps2_keyboard(info);
    init_smp(info);
    init_runtime_subsystems();
    init_vt_and_drv_hooks();
    // Wire the control-event notifier BEFORE any netdev registers. Linux
    // installs the rtnetlink notifier chain before device registration; here
    // `init_network_and_pci` probes virtio-net and emits eth0's boot-time
    // RTM_NEWLINK. Installing the notifier afterward (the old rootfs-phase
    // install) dropped that event on the floor (control_event.rs notifier=None).
    net::control_event::set_notifier(netlink::mcast::notify_control_event);
    init_network_and_pci();
    // NB: the AP master page-table gets each device's MMIO mapping propagated
    // eagerly inside `mmio_map::map_pages` (resync per splice), so APs can't #PF
    // on a virtio notify/config VA mid-enumeration — no post-enum resync needed.
}

#[cfg(target_os = "oxide-kernel")]
const PLATFORM_BUS: &str = "platform";
#[cfg(target_os = "oxide-kernel")]
const SERIAL_PLATFORM_ADDR: &str = "serial0";
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const I8042_PLATFORM_ADDR: &str = "i8042";
#[cfg(target_os = "oxide-kernel")]
const BOOT_PLATFORM_VENDOR_ID: u16 = 0;
#[cfg(target_os = "oxide-kernel")]
const BOOT_PLATFORM_DEVICE_ID: u16 = 0;
#[cfg(target_os = "oxide-kernel")]
const BOOT_PLATFORM_CLASS: u32 = 0;

#[cfg(target_os = "oxide-kernel")]
fn init_serial_console() {
    let uart_drv = drv_serial::uart_driver();
    let dev = platform_device_or_panic(SERIAL_PLATFORM_ADDR);
    drv::register_driver(uart_drv);
    // Register the serial printk console only if a `console=ttyS*/ttyAMA*` token
    // asked for it (Linux `register_console` per `console=`), not unconditionally.
    // The serial /dev/ttyS0 tty is installed regardless; this gates only klog
    // fan-out. No `console=` at all → default true (keep the sink).
    if dev.bound() == Some(drv::Driver::name(uart_drv)) && crate::boot_cmdline::console_classes().0 {
        klog::set_byte_sink(drv_serial::emit);
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn init_ps2_keyboard(info: &BootInfo) {
    let ps2_drv = drv_ps2_keyboard::driver();
    drv_ps2_keyboard::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
    platform_device_or_panic(I8042_PLATFORM_ADDR);
    drv::register_driver(ps2_drv);
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn init_ps2_keyboard(_info: &BootInfo) {}

#[cfg(target_os = "oxide-kernel")]
fn init_smp(info: &BootInfo) {
    #[cfg(target_arch = "x86_64")]
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
        unsafe {
            sched::live::install_default_runqueue();
            sched::live::set_send_resched_ipi_hook(arch_irq::lapic::send_resched_ipi);
            pmm::user_as::set_coredump_hook(fs::coredump::write_for_current);
            arch_irq::tlb::install();
        }
        if started > 0 { smp_ipi_smoke(info); }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: BSP boot path is the sole writer before scheduler workers
        // are spawned; APs install their own runqueues in the AP init hook.
        unsafe { sched::live::install_default_runqueue(); }
        arch_irq::smp_arm::install_hooks();
        arch_irq::smp_arm::publish_madt_mpidrs();
        hal_aarch64::smp::set_percpu_alloc_hook(pmm::setup::alloc_percpu_page);
        let started = unsafe { hal_aarch64::smp::bring_up_aps_psci() };
        debug_boot! {
            klog::write_raw(b"[INFO]  smp: aps_started=");
            klog::write_dec_u64(started as u64);
            klog::write_raw(b"\n");
        }
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn smp_ipi_smoke(info: &BootInfo) {
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
    for _ in 0..1_000_000u32 { core::hint::spin_loop(); }
    debug_boot! {
        use core::sync::atomic::Ordering;
        klog::write_raw(b"[INFO]  smp: ipi_smoke: online=");
        klog::write_dec_u64(cpu::smp::online_count() as u64);
        klog::write_raw(b" resched_ipis_received=");
        klog::write_dec_u64(arch_irq::lapic::RESCHED_IPI_COUNT.load(Ordering::Relaxed));
        klog::write_raw(b"\n");
    }
}

#[cfg(target_os = "oxide-kernel")]
fn init_runtime_subsystems() {
    let _ = unsafe { power::init() };
    let _ = unsafe { firmware::init() };
    ::sched::set_current_hook(|| sched::live::current());
    // RCU CPU-topology hooks. WITHOUT these, `sync::rcu` runs its documented
    // effectively-UP defaults — `online()` returns 1 (boot CPU only) and
    // `cur_cpu()` returns 0 for EVERY caller. On an SMP boot that is a
    // use-after-free generator: an AP's `note_qs()` (one per context switch,
    // via `oxide_finish_task_switch`) bumps CPU 0's quiescent counter, so a
    // grace period completes as soon as EITHER cpu passes a QS — while the
    // other cpu may still be inside an RCU read-side critical section holding
    // raw dentry/inode pointers. `call_rcu` then frees them under it.
    //
    // That is the aarch64 SMP=2 boot fault: it dies ~11s guest with wild
    // pointers (a branch into a kernel heap page, a near-null deref) and a
    // healthy stack. Bisected by experiment — an AP that is online and taking
    // interrupts but has NO runqueue (so it never schedules, so it never calls
    // `note_qs`) boots to basic.target clean; giving that same AP a runqueue
    // reintroduces the fault even with task migration disabled.
    sync::set_cpu_hooks(
        || {
            use hal::CpuOps;
            #[cfg(target_arch = "x86_64")]
            { (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
            #[cfg(target_arch = "aarch64")]
            { (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
        },
        cpu::smp::online_mask,
    );
    let _ = kalloc::replace_global_context(kalloc::AllocationContext::memcg(cgroup::kernel_context_memcg()));
    ::sched::set_allocation_context_hook(|task, kernel| {
        let memcg = if kernel { cgroup::kernel_context_memcg() }
        else { cgroup::cgroup_of(task.tid as u64) };
        let _ = kalloc::replace_global_context(kalloc::AllocationContext::memcg(memcg));
    });
    // Robust-futex exit walk lives in `ipc`; wire it into the sched exit hook so
    // the crash/fatal-fault exit paths (zombies, SIGSEGV terminate) recover a
    // dying thread's held robust mutexes. Body: ipc::live::futex::exit_robust_list.
    sched::live::set_robust_exit_hook(ipc::live::futex::exit_robust_list);
    let _ = unsafe { nscg::init() };
    sched::cgroup::install();
    cgroup::set_notify_hook(fs::inotify::fire_modify);
    debug_cgroup! { cgroup::selftest::run(); }
    let _ = unsafe { security::init() };
    let _ = unsafe { drv::init() };
    power::set_driver_shutdown_hook(drv::shutdown_all);
}

#[cfg(target_os = "oxide-kernel")]
fn init_vt_and_drv_hooks() {
    let _ = unsafe { vt::init() };
    vt::set_signal_hook(|pid, signo| {
        if let Some(t) = sched::live::registry::lookup_by_vpid(pid) {
            if let Some(bit) = sched::bit_for(signo as u32) {
                t.sigpending.fetch_or(bit, core::sync::atomic::Ordering::Release);
            }
        }
    });
    vt::set_owner_alive_hook(|vpid, tid| {
        sched::live::registry::lookup_by_vpid(vpid).map(|t| t.tid == tid).unwrap_or(false)
    });
    vt::set_switch_hook(|_n| {
        syscalls::ioctl::vt_switch_wake();
        sysfs::tty::notify_active_vt();
    });
    debug_boot! { klog::kinfo!("boot: kernel ready, halting"); }
}

#[cfg(target_os = "oxide-kernel")]
fn install_drv_sysfs_hooks() {
    drv::set_sysfs_hook(crate::sysfs::bus::publish_device_cb);
    drv::set_sysfs_remove_hook(crate::sysfs::bus::remove_device_cb);
    drv::set_driver_hook(crate::sysfs::bus::publish_driver_cb);
    drv::set_bind_hook(crate::sysfs::bus::bind_device_cb);
}

#[cfg(target_os = "oxide-kernel")]
fn init_network_and_pci() {
    unsafe { net::sock::init(); }
    crate::pci_boot::enumerate_and_log();
}

/// Publish a boot-discovered platform device through the driver model.
/// Repeated boot wiring may reuse an identical model identity, but a conflicting
/// platform object is a kernel model error and must not be hidden.
/// # C: O(N_devices)
#[cfg(target_os = "oxide-kernel")]
fn platform_device_or_panic(addr: &'static str) -> alloc::sync::Arc<drv::Device> {
    let candidate = alloc::sync::Arc::new(drv::Device::new(
        PLATFORM_BUS,
        alloc::string::String::from(addr),
        BOOT_PLATFORM_VENDOR_ID,
        BOOT_PLATFORM_DEVICE_ID,
        BOOT_PLATFORM_CLASS,
    ));
    match drv::try_device_add(alloc::sync::Arc::clone(&candidate)) {
        Ok(dev) => dev,
        Err(drv::Error::Busy) => {
            if let Some(existing) = drv::find_matching_device_identity(&candidate) {
                existing
            } else {
                panic_platform_device_conflict(addr);
            }
        }
        Err(_) => panic_platform_device_failure(addr),
    }
}

#[cfg(target_os = "oxide-kernel")]
fn panic_platform_device_conflict(addr: &'static str) -> ! {
    klog::write_raw(b"[ERR] platform device conflict: ");
    klog::write_raw(addr.as_bytes());
    klog::write_raw(b"\n");
    panic!("conflicting platform device registration");
}

#[cfg(target_os = "oxide-kernel")]
fn panic_platform_device_failure(addr: &'static str) -> ! {
    klog::write_raw(b"[ERR] platform device add failed: ");
    klog::write_raw(addr.as_bytes());
    klog::write_raw(b"\n");
    panic!("platform device registration failed");
}
