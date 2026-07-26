use crate::BootInfo;

/// Kernel entry. Called by per-arch boot stub after low-level setup.
/// # SAFETY: caller set up a valid kernel stack, mapped the kernel image
/// upper-half per the linker script, set the per-CPU base, disabled IRQs;
/// `info` is a valid `BootInfo` with `memmap_count` entries at `memmap_ptr`.
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    unsafe { super::early::init(info); }
    unsafe { super::runtime::init(info); }
    if sched::live::spawn_timer_driver().is_err() {
        klog::kerror!("fatal: timer driver spawn failed");
        sched::halt_forever();
    }
    if sched::live::spawn_ksoftirqd().is_err() {
        klog::kerror!("fatal: ksoftirqd spawn failed");
        sched::halt_forever();
    }
    if pmm::spawn_kswapd().is_err() {
        klog::kerror!("fatal: kswapd spawn failed");
        sched::halt_forever();
    }
    let netns_reaper = net::net_ns::spawn_namespace_reaper();
    if netns_reaper.is_err() {
        klog::kerror!("fatal: netns reaper spawn failed");
        sched::halt_forever();
    }
    // Bridge STP runs as a softirq (`net::stack::stp_softirq`); the timer tick
    // only raises the slot. Install before the tick can raise it — though an
    // unraised slot with no handler is inert, so ordering is not load-bearing.
    net::stp_softirq_init();
    unsafe { super::rootfs::init(info); }
    sched::halt_forever()
}
