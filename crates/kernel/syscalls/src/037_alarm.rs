// 037 alarm — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.

use syscall::SyscallArgs;

const NSEC_PER_SEC:  u64 = 1_000_000_000;
const HALF_SEC_NSEC: u64 = NSEC_PER_SEC / 2;

#[inline]
fn monotonic_ns() -> u64 {
    #[cfg(test)]
    {
        TEST_NOW_NS.load(core::sync::atomic::Ordering::Acquire)
    }
    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        use hal::TimerOps;
        hal_x86_64::X86TimerOps::monotonic_ns().0
    }
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        use hal::TimerOps;
        hal_aarch64::ArmTimerOps::monotonic_ns().0
    }
}

#[cfg(test)]
static TEST_NOW_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub fn set_test_now_ns(ns: u64) {
    TEST_NOW_NS.store(ns, core::sync::atomic::Ordering::Release);
}

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

fn alarm_return_seconds(rem_ns: u64) -> u64 {
    let mut secs = rem_ns / NSEC_PER_SEC;
    let nsec = rem_ns % NSEC_PER_SEC;
    if (secs == 0 && nsec != 0) || nsec >= HALF_SEC_NSEC {
        secs = secs.saturating_add(1);
    }
    secs
}

/// `sys_alarm(seconds)` — slot 37. Sets a per-task SIGALRM
/// deadline at monotonic_ns + seconds*1e9. Returns the seconds
/// remaining on the previous alarm, or 0 if none.
/// # C: O(1)
pub fn sys_alarm(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let secs = args.a0 as u32 as u64;
    let now = monotonic_ns();
    let cur = match current_task() { Some(c) => c, None => return 0 };
    let prev = cur.alarm_ns.load(Ordering::Acquire);
    let prev_remaining = if prev > now { alarm_return_seconds(prev - now) } else { 0 };
    let new = if secs == 0 { 0 } else { now.saturating_add(secs.saturating_mul(NSEC_PER_SEC)) };
    cur.alarm_interval_ns.store(0, Ordering::Release);
    cur.alarm_ns.store(new, Ordering::Release);
    prev_remaining as i64
}
