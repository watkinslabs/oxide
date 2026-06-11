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
