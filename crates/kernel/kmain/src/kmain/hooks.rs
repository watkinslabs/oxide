/// Combined timer-tick hook: run BSP timer device work and drain any pending
/// fbcon writes onto the GPU display.
/// # SAFETY: timer-ISR context per the hook contract.
/// # C: O(1) typical; O(xres*yres) on dirty fbcon repaint.
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn tick_poll_combined(_from_user: bool) {
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
        // PSI (`/proc/pressure/*`) sampling moved to the ktimers kthread (B1344):
        // its `SYS` spinlock is taken plain by process-context readers
        // (systemd-oomd polling /proc/pressure/*), so charging it from the hard
        // IRQ can self-deadlock the CPU when the tick preempts a reader (`06§3.1`).
    }
    fbcon::kernel::tick_drain();
    // D6: advance the pseudo-vblank counter at the tick rate — the honest
    // virtual-GPU vsync cadence that FBIO_WAITFORVSYNC blocks on and
    // FBIOGET_VBLANK reports as the running frame count.
    fbdev::vblank_tick();
    // B1344: `reap_orphans` (B14 zombie subreap) and `tick_wake_expired`
    // (F169/B20 SO_*TIMEO + alarm/itimer deadline walker) moved OFF this
    // hard-IRQ tick into the ktimers process-context kthread
    // (`sched::register_timers`). Both take REG/ZOMBIES/child_sigq plain
    // (non-irqsave) locks — and `reap_orphans`→`wake_wait4_parent` even takes
    // the runqueue `rq.inner` lock — that process context (fork/exit/wait4/
    // procfs/cgroup::tick) also holds with IRQs enabled. Running them in the
    // timer ISR self-deadlocks the CPU whenever the tick preempts a holder of
    // one of those locks (a hard-IRQ handler must never spin on a plain lock a
    // process-context holder owns; `06§3.1`). They already self-throttle to the
    // 100 ms ktimers cadence, so wakeup latency is unchanged.
    let now_ns = syscalls::vvar::monotonic_now_ns();
    net::global_stack().bridge_stp_tick(now_ns);
    // Liveness watchdog (`05`): fire a one-shot soft-lockup banner +
    // task dump if a Runnable task monopolises the CPU with no
    // reschedule past the stall threshold. Silent on a healthy boot.
    sched::diag::watchdog_tick(now_ns);
    // Refresh the vDSO vvar page with the live monotonic clock so
    // userspace __vdso_clock_gettime returns current time without
    // a syscall. Cheap (one TimerOps read + 4 atomic stores).
    syscalls::vvar::publish();
}

/// debug-zerotrap tid getter (fn-pointer, no capture). # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn zerotrap_tid() -> u32 { sched::live::current().map(|c| c.tid).unwrap_or(0) }
