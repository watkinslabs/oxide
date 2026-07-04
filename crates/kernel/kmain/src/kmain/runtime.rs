use crate::{BootInfo, tick_poll_combined};

/// Runtime hook, console, device, and SMP bring-up.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init(info: &BootInfo) {
    arch_irq::set_tick_poll_hook(tick_poll_combined);
    arch_irq::install_diag_nmi_hook();
    arch_irq::install_softirq_hooks();

    console::static_console::install();
    tty::live::set_kbd_sink(console::kbd_input);
    drv_serial::set_rx_prefilter(sched::diag::sysrq_rx);
    drv_serial::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
    init_serial_console();
    init_ps2_keyboard(info);
    init_smp(info);
    init_runtime_subsystems();
    init_vt_and_drv_hooks();
    init_network_and_pci();
}

#[cfg(target_os = "oxide-kernel")]
fn init_serial_console() {
    let uart_drv = drv_serial::uart_driver();
    let dev = platform_device_or_panic("serial0");
    drv::register_driver(uart_drv);
    if dev.bound() == Some(drv::Driver::name(uart_drv)) {
        klog::set_byte_sink(drv_serial::emit);
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn init_ps2_keyboard(info: &BootInfo) {
    let ps2_drv = drv_ps2_keyboard::driver();
    drv_ps2_keyboard::configure_probe(info.bsp_lapic_id as u8, smoke::device_map::KERNEL_DEVICE_BASE);
    platform_device_or_panic("i8042");
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
        arch_irq::smp_arm::install_hooks();
        arch_irq::smp_arm::publish_madt_mpidrs();
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
    let _ = unsafe { nscg::init() };
    sched::cgroup::install();
    cgroup::set_notify_hook(fs::inotify::fire_modify_path);
    debug_cgroup! { cgroup::selftest::run(); }
    let _ = unsafe { security::init() };
    let _ = unsafe { drv::init() };
    power::set_driver_shutdown_hook(drv::shutdown_all);
}

#[cfg(target_os = "oxide-kernel")]
fn init_vt_and_drv_hooks() {
    drv::set_sysfs_hook(crate::sysfs::bus::publish_device_cb);
    drv::set_sysfs_remove_hook(crate::sysfs::bus::remove_device_cb);
    drv::set_driver_hook(crate::sysfs::bus::publish_driver_cb);
    drv::set_bind_hook(crate::sysfs::bus::bind_device_cb);
    let _ = unsafe { vt::init() };
    vt::set_signal_hook(|pid, signo| {
        if signo == 0 || signo > 64 { return; }
        if let Some(t) = sched::live::registry::lookup_by_vpid(pid) {
            t.sigpending.fetch_or(1u64 << (signo - 1), core::sync::atomic::Ordering::Release);
        }
    });
    vt::set_owner_alive_hook(|vpid, tid| {
        sched::live::registry::lookup_by_vpid(vpid).map(|t| t.tid == tid).unwrap_or(false)
    });
    vt::set_switch_hook(|_n| syscalls::ioctl::vt_switch_wake());
    debug_boot! { klog::kinfo!("boot: kernel ready, halting"); }
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
