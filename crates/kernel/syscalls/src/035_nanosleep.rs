// 035 nanosleep — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.

use syscall::SyscallArgs;

#[cfg(not(test))]
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

#[cfg(target_os = "oxide-kernel")]
static NANOSLEEP_WAIT: sched::live::WaitList = sched::live::WaitList::new();

#[cfg(test)]
fn validate_user_buf(ptr: u64, _len: u64, _align: u64) -> Result<(), i64> {
    if ptr >= 4096 { Ok(()) } else { Err(-(syscall::Errno::Efault.as_i32() as i64)) }
}

#[cfg(test)]
fn validate_user_buf_writable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    validate_user_buf(ptr, len, align)
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SleepWake {
    None,
    Complete,
    Stop(u32),
}

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

#[inline]
fn ignored_or_noop(sig: u32, handler: u64) -> bool {
    if handler == SIG_IGN { return true; }
    if handler != SIG_DFL { return false; }
    matches!(sched::signum::default_action(sig),
        sched::signum::DefaultAction::Ign | sched::signum::DefaultAction::Cont)
}

#[inline]
fn default_stop(sig: u32, handler: u64) -> bool {
    handler == SIG_DFL && sched::signum::default_action(sig) == sched::signum::DefaultAction::Stop
}

fn sleep_wake(cur: &sched::Task) -> SleepWake {
    use core::sync::atomic::Ordering;
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let masked = cur.sigmask.load(Ordering::Acquire);
        let sig = match sched::signum::next_deliverable(pending, masked) {
            Some(s) => s,
            None => return SleepWake::None,
        };
        let act = cur.sigactions_ref().get(sig);
        if ignored_or_noop(sig, act.handler) {
            cur.flush_pending_signal(sig as usize);
            continue;
        }
        if default_stop(sig, act.handler) {
            cur.flush_pending_signal(sig as usize);
            return SleepWake::Stop(sig);
        }
        return SleepWake::Complete;
    }
}

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

// `pub(crate)`: F721 conformance harness (`crates/kernel/vfs/tests/
// conformance_misc.rs`) pulls this file in via `#[path]` to drive the real
// EINVAL-on-negative/overflow timespec gate hosted; a bare `fn` is
// module-private even when spliced into another crate's test binary, so this
// is widened just enough for that — no behavior change.
pub(crate) fn read_timespec(ptr: u64) -> Result<u64, i64> {
    use syscall::errno::Errno;
    validate_user_buf(ptr, 16, 1)?;
    // SAFETY: ptr validated as readable 16-byte timespec storage.
    let secs = unsafe { core::ptr::read_unaligned(ptr as *const i64) };
    // SAFETY: ptr+8 is inside the validated timespec storage.
    let nsec = unsafe { core::ptr::read_unaligned((ptr + 8) as *const i64) };
    // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
    // KTIME_MAX_NS instead of an unbounded relative sleep duration.
    ::syscall::time::timespec_to_ns(secs, nsec).map_err(|_| -(Errno::Einval.as_i32() as i64))
}

fn write_remaining(rem: u64, left: u64) -> Result<(), i64> {
    if rem == 0 { return Ok(()); }
    validate_user_buf_writable(rem, 16, 1)?;
    let rsec = (left / 1_000_000_000) as i64;
    let rnsec = (left % 1_000_000_000) as i64;
    // SAFETY: rem validated writable for a 16-byte timespec.
    unsafe {
        core::ptr::write_unaligned(rem as *mut i64, rsec);
        core::ptr::write_unaligned((rem + 8) as *mut i64, rnsec);
    }
    Ok(())
}

fn interrupt_result(rem: u64, deadline: u64) -> i64 {
    let left = deadline.saturating_sub(monotonic_ns());
    if left != 0 {
        if let Err(rv) = write_remaining(rem, left) { return rv; }
    }
    syscall::restart::restart_block()
}

#[cfg(target_os = "oxide-kernel")]
fn sleep_until_deadline(cur: &sched::Task, deadline: u64, rem: u64) -> i64 {
    loop {
        if monotonic_ns() >= deadline { return 0; }
        match sleep_wake(cur) {
            SleepWake::Complete => return interrupt_result(rem, deadline),
            SleepWake::Stop(sig) => {
                sched::live::stop::stop_until_cont_sig(sig as u8);
                continue;
            }
            SleepWake::None => {}
        }
        // SAFETY: process context; the current task is enqueued on a scheduler
        // wait list with an absolute wake deadline, then immediately scheduled.
        unsafe {
            NANOSLEEP_WAIT.park_with_deadline(deadline);
            sched::live::park_yield();
        }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn sleep_until_deadline(cur: &sched::Task, deadline: u64, rem: u64) -> i64 {
    if monotonic_ns() >= deadline { return 0; }
    if sleep_wake(cur) == SleepWake::Complete {
        interrupt_result(rem, deadline)
    } else {
        -(syscall::Errno::Eintr.as_i32() as i64)
    }
}

/// `sys_nanosleep(req, rem)` — slot 35, Linux relative CLOCK_MONOTONIC sleep.
/// # C: O(schedules until deadline or signal)
pub fn sys_nanosleep(args: &SyscallArgs) -> i64 {
    let total = match read_timespec(args.a0) {
        Ok(ns) => ns,
        Err(rv) => return rv,
    };
    let start = monotonic_ns();
    let deadline = start.saturating_add(total);
    let rem = args.a1;
    if total == 0 { return 0; }
    let cur = match current_task() {
        Some(c) => c,
        None => return 0,
    };
    sleep_until_deadline(cur, deadline, rem)
}

#[cfg(test)]
pub fn nanosleep_actionable_signal_pending_for_test(cur: &sched::Task) -> bool {
    sleep_wake(cur) == SleepWake::Complete
}
