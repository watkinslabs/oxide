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
    // SAFETY: `kernel_main`'s own boot-entry contract (valid kernel stack and
    // per-CPU base, IRQs off, single CPU, `info` a valid BootInfo) is exactly
    // what these two phases require, and it is forwarded unchanged.
    unsafe { super::early::init(info); }
    klog::initcall::level("runtime");
    // Keep runtime's strict phases as separate call frames. The PCI/AML phase
    // can recurse deeply, so it must not retain the setup or SMP/display
    // phase frame beneath it.
    super::runtime::init_prefix(info);
    super::runtime::init_network_and_pci();
    super::runtime::init_suffix(info);
    // Runtime emits stage-level `step` timing itself. Do not retain an outer
    // timestamp under the deepest firmware/PCI initialization call chain.
    spawn_kthreads();
    klog::initcall::level("rootfs");
    let t = klog::initcall::start("rootfs::init");
    // SAFETY: forwarded boot-entry contract; the runqueue, workqueues and
    // kthreads that `rootfs::init` mounts and execs through all exist by now.
    unsafe { super::rootfs::init(info); }
    klog::initcall::finish("rootfs::init", t, 0);
    sched::halt_forever()
}

/// kthread phase of `kernel_main`: every pinned per-CPU kernel thread and the
/// deferred-work backends that need one.
///
/// Its own frame (Linux `noinline_for_stack`). The phase is sequential — each
/// spawn's locals are dead before the next runs and all of them are dead
/// before the rootfs mount and the userspace handoff — but inlined into
/// `kernel_main` the whole pile is reserved in one prologue and stays live
/// underneath the deepest chain in the kernel.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
/// The terminal thermal action: the hardware is past the temperature at which
/// it is damaged, so the machine goes down rather than continuing to run.
/// # C: O(1)
fn thermal_critical(_zone: &str, _temp_mc: i32) {
    klog::kerror!("thermal: critical temperature reached, powering off");
    // SAFETY: `power::power_off` is the platform's irreversible S5 transition,
    // which is exactly what a critical trip calls for; nothing needs unwinding
    // because the machine does not continue past it.
    unsafe { power::power_off() }
}

fn spawn_kthreads() {
    klog::initcall::level("kthreads");
    // Idle: the architecture halt is what the hardware offers before any
    // firmware description has been read, and registering it is what makes the
    // residency accounting under `/sys/devices/system/cpu/cpu*/cpuidle` real.
    // A platform provider that finds a deeper ladder replaces this table.
    step("cpuidle::generic::init", || { cpuidle::idle::generic::init(cpu::MAX_CPUS); });
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
    // Thermal: a zone read evaluates firmware and a cooling-device change
    // writes it, so the sweep runs on the workqueue and arms here alongside
    // the other periodic work. The terminal action is installed here because
    // powering the machine down belongs to the power subsystem, not to the
    // device class that decides when it is warranted.
    thermal::set_critical_hook(thermal_critical);
    step("thermal::poll::start", thermal::poll::start);
    // Frequency scaling resamples the demand signal on the tick.
    step("sched::cpufreq_hook::start", sched::cpufreq_hook::start);
    // The two reclaim kthreads. kswapd reclaims under pressure; the OOM reaper
    // drains a chosen victim's own private memory on its behalf and marks the
    // mm skippable when it cannot, which is what lets selection move past a
    // victim wedged in an uninterruptible sleep. Leaf teardown stays on PMM's
    // side of the boundary, installed here as the sole zapper, exactly as the
    // badness observer keeps physical accounting there.
    //
    // One failure report for both: the initcall trace already names whichever
    // step failed, and `04§4.0` is frozen on a default build emitting no log
    // bytes, so a second unconditional message buys nothing.
    sched::oom::install_oom_zapper(pmm::user_as::evict_foreign_pages_in_range);
    // kflushd, the third of the periodic reclaim threads: it puts dirty page
    // cache on the medium once the machine passes its background dirty
    // threshold, and ages out anything dirty long enough (`17§4.3`). Without
    // it a dirty page waits for an `fsync` that a writer may never issue, and
    // reclaim meets pages it is not allowed to drop.
    // `hung_task_timeout_secs=` / `hung_task_panic` install BEFORE the
    // detector starts, so its first scan already runs under the boot line's
    // policy rather than one window of the build default.
    {
        let line = crate::boot_cmdline::get();
        if let Some(secs) = cmdline::hung_task::timeout_secs(line) {
            sched::hung_task::set_timeout_secs(secs);
        }
        sched::hung_task::set_panic_on_hung(cmdline::hung_task::panic_on_hung(line));
    }
    let reclaim_failed = step("spawn_kswapd", || pmm::spawn_kswapd()).is_err()
        || step("block::pagecache::spawn_daemons", block::pagecache::spawn_daemons).is_err()
        || step("sched::oom::spawn_oom_reaper", || sched::oom::spawn_oom_reaper()).is_err()
        // The hung-task detector: a task stuck in an uninterruptible sleep past
        // the window names ITSELF in the log, instead of a wedge being visible
        // only to whoever happens to be at the console with a sysrq key.
        || step("sched::live::spawn_khungtaskd", || sched::live::spawn_khungtaskd()).is_err();
    if reclaim_failed {
        klog::kerror!("fatal: reclaim kthread spawn failed");
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
}
