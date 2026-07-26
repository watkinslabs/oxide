//! Per-CPU CPU-time accounting for `/proc/stat` (htop/btop %CPU). Each timer
//! tick buckets into user/system/idle by the interrupted task's class, on the
//! CPU the tick fired on — so `/proc/stat` emits a real `cpuN` line per online
//! CPU (Linux `kernel/sched/cputime.c` per-CPU `kcpustat`). htop computes %CPU
//! from deltas between reads, so raw tick counts suffice — the unit cancels in
//! the ratio (no USER_HZ conversion needed).
//!
//! user-vs-system is approximated by task class (a running user task → user, a
//! kthread → system); a precise split would inspect the timer-IRQ frame's
//! privilege level (arch-specific) — deferred until it matters.

use core::sync::atomic::{AtomicU64, Ordering};

const N: usize = cpu::MAX_CPUS;

static USER: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static SYS:  [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static IDLE: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

/// Per-CPU monotonic-ns timestamp of the previous timer tick. The
/// inter-tick wall delta is charged to the interrupted task's user- or
/// kernel-mode CPU-time bucket (tick-sampled per-task accounting, Linux
/// CONFIG_TICK_CPU_ACCOUNTING). 0 = no baseline yet (first tick on CPU).
static LAST_TICK_NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

/// Ceiling on a single tick's per-task charge. The LAPIC/CNTV periodic
/// timer here is NOT a fixed 100 Hz (x86 LAPIC bus freq is unmeasured;
/// arm CNTV ticks ~62.5 Hz at `timer_periodic(1_000_000)`), so utime is
/// derived from the real inter-tick monotonic delta rather than a fixed
/// jiffy. A larger gap (first tick, long IRQ-off window, VM pause) is
/// capped so accounting can't spike. 100 ms >> any real tick period.
pub const MAX_TICK_CHARGE_NS: u64 = 100_000_000;

/// What the timer tick interrupted.
pub enum TickKind { User, System, Idle }

/// The CPU this code is running on (per-CPU base via gs/TPIDR). 0 off-target.
/// # C: O(1)
#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(N - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(N - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Charge one timer tick to the running context's bucket on the CPU the tick
/// fired on. Called from each CPU's timer-ISR tick hook.
/// # C: O(1)
pub fn account(kind: TickKind) {
    let c = this_cpu();
    match kind {
        TickKind::User   => USER[c].fetch_add(1, Ordering::Relaxed),
        TickKind::System => SYS[c].fetch_add(1, Ordering::Relaxed),
        TickKind::Idle   => IDLE[c].fetch_add(1, Ordering::Relaxed),
    };
}

/// Live monotonic clock in ns. Host builds (unit tests) return 0, so the
/// per-task charge below is a no-op off-target.
/// # C: O(1)
#[inline]
fn now_ns() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Charge the wall-time elapsed since the previous timer tick on THIS CPU
/// to the interrupted task's user- or kernel-mode CPU-time bucket. Called
/// from each arch timer ISR alongside `account`. Tick-sampled: the whole
/// inter-tick delta is attributed to whichever mode the timer interrupted
/// (`from_user`), matching Linux CONFIG_TICK_CPU_ACCOUNTING. Reads the
/// real monotonic delta so utime/stime stay wall-consistent on any timer
/// frequency (the periodic tick is not a fixed 100 Hz here).
///
/// Hard-IRQ safe, but not "atomics only" as this previously claimed: it also
/// charges the thread group and services process CPU-clock timers, the latter
/// behind a NON-BLOCKING `try_lock` that bails rather than spinning. What makes
/// it safe is that nothing here can block — F703 removed the `registry::lookup`
/// that used to take `REG`, a lock process context holds with IRQs enabled
/// (`06§3.1`, `skizm.md` 3.1 #1). Keep it that way: any lock added on this path
/// must be a try-lock or irqsave.
/// # C: O(1)
/// # Ctx: IRQ
pub fn charge_current_tick(from_user: bool) {
    let c = this_cpu();
    let now = now_ns();
    let prev = LAST_TICK_NS[c].swap(now, Ordering::Relaxed);
    if prev == 0 || now <= prev { return; }
    let delta = (now - prev).min(MAX_TICK_CHARGE_NS);
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = crate::live::current() {
        if from_user { t.utime_ns.fetch_add(delta, Ordering::Relaxed); }
        else         { t.stime_ns.fetch_add(delta, Ordering::Relaxed); }
        t.thread_group.charge_cpu(from_user, delta);
        crate::timers::account_cpu_tick(t);
    }
    let _ = (delta, from_user);
}

/// `(user, system, idle)` accumulated ticks for CPU `cpu` — `/proc/stat`'s
/// `cpuN` line. # C: O(1)
pub fn snapshot_cpu(cpu: usize) -> (u64, u64, u64) {
    if cpu >= N { return (0, 0, 0); }
    (USER[cpu].load(Ordering::Relaxed),
     SYS[cpu].load(Ordering::Relaxed),
     IDLE[cpu].load(Ordering::Relaxed))
}

/// Aggregate `(user, system, idle)` summed over all CPUs — `/proc/stat`'s
/// `cpu` (no-suffix) line. # C: O(MAX_CPUS)
pub fn snapshot() -> (u64, u64, u64) {
    let (mut u, mut s, mut i) = (0u64, 0u64, 0u64);
    for c in 0..N {
        u += USER[c].load(Ordering::Relaxed);
        s += SYS[c].load(Ordering::Relaxed);
        i += IDLE[c].load(Ordering::Relaxed);
    }
    (u, s, i)
}
