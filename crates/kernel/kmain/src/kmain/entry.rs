use crate::BootInfo;

/// Kernel entry. Called by per-arch boot stub after low-level setup.
/// # SAFETY: caller set up a valid kernel stack, mapped the kernel image
/// upper-half per the linker script, set the per-CPU base, disabled IRQs;
/// `info` is a valid `BootInfo` with `memmap_count` entries at `memmap_ptr`.
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    // SAFETY: `kernel_main`'s own boot-entry contract (valid kernel stack and
    // per-CPU base, IRQs off, single CPU, `info` a valid BootInfo) is exactly
    // what these two phases require, and it is forwarded unchanged.
    unsafe { super::early::init(info); }
    // SAFETY: forwarded boot-entry contract; `early::init` has additionally run,
    // which is `runtime::init`'s ordering precondition.
    unsafe { super::runtime::init(info); }
    if sched::live::spawn_timer_driver().is_err() {
        klog::kerror!("fatal: timer driver spawn failed");
        sched::halt_forever();
    }
    if sched::live::spawn_ksoftirqd().is_err() {
        klog::kerror!("fatal: ksoftirqd spawn failed");
        sched::halt_forever();
    }
    // kworkers: the process-context home for deferred work that may SLEEP
    // (`sched::live::workqueue`). Spawned alongside ksoftirqd — both are pinned
    // per-CPU kthreads and both need the runqueues installed first.
    if sched::live::workqueue::spawn_kworkers().is_err() {
        klog::kerror!("fatal: kworker spawn failed");
        sched::halt_forever();
    }
    // The kernel -> userspace helper runs its exec on a worker thread, so its
    // backend is installed once the workers exist. The gate stays CLOSED here:
    // no helper may run until userspace is up, which is what `enable` below
    // marks. `docs/53`.
    if umh::spawn::init().is_err() {
        klog::kerror!("fatal: khelper spawn failed");
        sched::halt_forever();
    }
    // Periodic lazytime sweep: bounds how long a `lazytime` mount may hold a
    // timestamp in memory. Needs the workqueue, so it arms right after it.
    fs::sync::start_dirtytime_writeback();
    if pmm::spawn_kswapd().is_err() {
        klog::kerror!("fatal: kswapd spawn failed");
        sched::halt_forever();
    }
    let netns_reaper = net::net_ns::spawn_namespace_reaper();
    if netns_reaper.is_err() {
        klog::kerror!("fatal: netns reaper spawn failed");
        sched::halt_forever();
    }
    // B1409: process-context home for the RTNL-taking half of a socket's
    // final release when the last `Arc<InetSocket>` drop lands in softirq
    // (AF_PACKET fan-out racing a `close()`). Same site as the other
    // dedicated reapers above — needs the runqueue installed first.
    if net::sock_rtnl_defer::spawn_sock_rtnl_reaper().is_err() {
        klog::kerror!("fatal: sock rtnl reaper spawn failed");
        sched::halt_forever();
    }
    // Bridge STP runs as a softirq (`net::stack::stp_softirq`); the timer tick
    // only raises the slot. Install before the tick can raise it — though an
    // unraised slot with no handler is inert, so ordering is not load-bearing.
    // Tasklet drain (Linux TASKLET_SOFTIRQ) — dynamic softirq-context callbacks.
    sched::live::tasklet::init_softirq();
    net::stp_softirq_init();
    // SAFETY: forwarded boot-entry contract; the runqueue, workqueues and
    // kthreads that `rootfs::init` mounts and execs through all exist by now.
    unsafe { super::rootfs::init(info); }
    sched::halt_forever()
}
