// Live half of the CPU-time rlimits — Linux's `check_process_timers` /
// `check_thread_timers` special cases, run from the same periodic walk that
// services `alarm(2)` and the CPU-time itimers.
//
// The ladder itself (hard kills, soft nags once per second by raising
// `rlim_cur`) is `crate::rlimit::cputime`, unit-tested there. This file only
// samples live state, applies the decision and reports the signal mask back to
// the walker, which owns the enqueue.

use crate::rlimit::cputime::{check_cpu, check_rttime, CpuLimitAction};
use crate::rlimit::rlim;
use crate::signum::Signum;
use crate::Task;

/// Nanoseconds per microsecond — `RLIMIT_RTTIME` is denominated in µs while
/// the run-time accumulator is nanoseconds.
const NS_PER_US: u64 = 1_000;

/// Mask of signals `RLIMIT_CPU` and `RLIMIT_RTTIME` raised for `t`, with the
/// soft-limit bump already stored back into the thread group's table.
///
/// `RLIMIT_CPU` is process-wide (Linux samples `sig->cputimer`, this kernel's
/// `ThreadGroup::cpu_sample`) and `RLIMIT_RTTIME` is per-thread, so the two
/// read different clocks even though they share the ladder. Both signals are
/// process-directed (`PIDTYPE_TGID`), which is what the caller's enqueue does.
/// # C: O(1); # Lk: TaskList (thread group rlimit table, momentary)
pub fn check_cpu_rlimits(t: &Task) -> u64 {
    cpu_limit(t) | rttime_limit(t)
}

/// `RLIMIT_CPU`: the thread group's total user+system time against a limit in
/// SECONDS. Linux's soft-limit bump (`rlim_cur = soft + 1`) is what turns a
/// per-tick check into one `SIGXCPU` per second.
/// # C: O(1); # Lk: TaskList (momentary)
fn cpu_limit(t: &Task) -> u64 {
    let (soft, hard) = t.rlimit(rlim::CPU);
    if soft == crate::rlimit::INFINITY { return 0; }
    let (user, system) = t.thread_group.cpu_sample();
    match check_cpu(user.saturating_add(system), soft, hard) {
        CpuLimitAction::None => 0,
        CpuLimitAction::Kill => Signum::Sigkill.bit(),
        CpuLimitAction::Xcpu { next_soft } => {
            t.set_rlimit(rlim::CPU, (next_soft, hard));
            Signum::Sigxcpu.bit()
        }
    }
}

/// `RLIMIT_RTTIME`: how long THIS thread has run under a real-time policy,
/// against a limit in microseconds. Linux counts whole ticks
/// (`p->rt.timeout * (USEC_PER_SEC / HZ)`); this kernel's tick period is not
/// fixed, so the accumulator carries the charged nanoseconds directly and the
/// conversion is exact instead of tick-quantised.
/// # C: O(1); # Lk: TaskList (momentary)
fn rttime_limit(t: &Task) -> u64 {
    let (soft, hard) = t.rlimit(rlim::RTTIME);
    if soft == crate::rlimit::INFINITY { return 0; }
    let rttime_us = t.rt_timeout_ns.load(core::sync::atomic::Ordering::Acquire) / NS_PER_US;
    match check_rttime(rttime_us, soft, hard) {
        CpuLimitAction::None => 0,
        CpuLimitAction::Kill => Signum::Sigkill.bit(),
        CpuLimitAction::Xcpu { next_soft } => {
            t.set_rlimit(rlim::RTTIME, (next_soft, hard));
            Signum::Sigxcpu.bit()
        }
    }
}
