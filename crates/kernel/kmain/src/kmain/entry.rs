use crate::BootInfo;

/// Run one boot init step under the `initcall_debug` tracer. The step
/// announces itself BEFORE it runs, so a step that never returns has already
/// named itself — which is the difference between a diagnosable hang and a
/// silent one. With the parameter absent this is exactly the call it wraps.
/// The three boot PHASES call `klog::initcall::{start, finish}` directly
/// rather than through this wrapper: a closure around a call that already runs
/// near the kernel stack ceiling gets outlined into its own symbol, which both
/// adds a frame to the deepest path in the kernel and renames the path the
/// stack-depth gate tracks. Everything shallower uses the wrapper.
/// # C: cost of `f`
#[cfg(target_os = "oxide-kernel")]
#[inline(always)]
pub(super) fn step<T>(name: &'static str, f: impl FnOnce() -> T) -> T { klog::initcall::run(name, f) }

/// Kernel entry. Called by per-arch boot stub after low-level setup.
/// # SAFETY: caller set up a valid kernel stack, mapped the kernel image
/// upper-half per the linker script, set the per-CPU base, disabled IRQs;
/// `info` is a valid `BootInfo` with `memmap_count` entries at `memmap_ptr`.
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    klog::initcall::level("early");
    let t = klog::initcall::start("early::init");
    // SAFETY: `kernel_main`'s own boot-entry contract (valid kernel stack and
    // per-CPU base, IRQs off, single CPU, `info` a valid BootInfo) is exactly
    // what these two phases require, and it is forwarded unchanged.
    unsafe { super::early::init(info); }
    klog::initcall::finish("early::init", t, 0);
    klog::initcall::level("runtime");
    let t = klog::initcall::start("runtime::init");
    // SAFETY: forwarded boot-entry contract; `early::init` has additionally run,
    // which is `runtime::init`'s ordering precondition.
    unsafe { super::runtime::init(info); }
    klog::initcall::finish("runtime::init", t, 0);
    klog::initcall::level("kthreads");
    if step("spawn_timer_driver", sched::live::spawn_timer_driver).is_err() {
        klog::kerror!("fatal: timer driver spawn failed");
        sched::halt_forever();
    }
    if step("spawn_ksoftirqd", || sched::live::spawn_ksoftirqd()).is_err() {
        klog::kerror!("fatal: ksoftirqd spawn failed");
        sched::halt_forever();
    }
    // kworkers: the process-context home for deferred work that may SLEEP
    // (`sched::live::workqueue`). Spawned alongside ksoftirqd — both are pinned
    // per-CPU kthreads and both need the runqueues installed first.
    if step("spawn_kworkers", || sched::live::workqueue::spawn_kworkers()).is_err() {
        klog::kerror!("fatal: kworker spawn failed");
        sched::halt_forever();
    }
    // The kernel -> userspace helper runs its exec on a worker thread, so its
    // backend is installed once the workers exist. The gate stays CLOSED here:
    // no helper may run until userspace is up, which is what `enable` below
    // marks. `docs/53`.
    if step("umh::spawn::init", || umh::spawn::init()).is_err() {
        klog::kerror!("fatal: khelper spawn failed");
        sched::halt_forever();
    }
    // Periodic lazytime sweep: bounds how long a `lazytime` mount may hold a
    // timestamp in memory. Needs the workqueue, so it arms right after it.
    step("fs::sync::start_dirtytime_writeback", fs::sync::start_dirtytime_writeback);
    if step("spawn_kswapd", || pmm::spawn_kswapd()).is_err() {
        klog::kerror!("fatal: kswapd spawn failed");
        sched::halt_forever();
    }
    let netns_reaper = step("net::net_ns::spawn_namespace_reaper", net::net_ns::spawn_namespace_reaper);
    if netns_reaper.is_err() {
        klog::kerror!("fatal: netns reaper spawn failed");
        sched::halt_forever();
    }
    // B1409: process-context home for the RTNL-taking half of a socket's
    // final release when the last `Arc<InetSocket>` drop lands in softirq
    // (AF_PACKET fan-out racing a `close()`). Same site as the other
    // dedicated reapers above — needs the runqueue installed first.
    if step("net::sock_rtnl_defer::spawn_sock_rtnl_reaper", || net::sock_rtnl_defer::spawn_sock_rtnl_reaper()).is_err() {
        klog::kerror!("fatal: sock rtnl reaper spawn failed");
        sched::halt_forever();
    }
    // Bridge STP runs as a softirq (`net::stack::stp_softirq`); the timer tick
    // only raises the slot. Install before the tick can raise it — though an
    // unraised slot with no handler is inert, so ordering is not load-bearing.
    // Tasklet drain (Linux TASKLET_SOFTIRQ) — dynamic softirq-context callbacks.
    step("sched::live::tasklet::init_softirq", sched::live::tasklet::init_softirq);
    step("net::stp_softirq_init", net::stp_softirq_init);
    klog::initcall::level("rootfs");
    let t = klog::initcall::start("rootfs::init");
    // SAFETY: forwarded boot-entry contract; the runqueue, workqueues and
    // kthreads that `rootfs::init` mounts and execs through all exist by now.
    unsafe { super::rootfs::init(info); }
    klog::initcall::finish("rootfs::init", t, 0);
    sched::halt_forever()
}
