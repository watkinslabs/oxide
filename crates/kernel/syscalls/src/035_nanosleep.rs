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

use sched::SleepWake;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

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

/// Linux `do_nanosleep`'s interrupted tail (`kernel/time/hrtimer.c:2406-2423`)
/// plus `hrtimer_nanosleep`'s ABS/REL split (`hrtimer.c:2445-2458`):
///
/// * RELATIVE (`HRTIMER_MODE_REL` — every `nanosleep(2)` and a
///   `clock_nanosleep(2)` without `TIMER_ABSTIME`): copy the remaining time out
///   to `rmtp` when the caller passed one (`restart->nanosleep.type ==
///   TT_NATIVE`), arm the restart block with the ABSOLUTE expiry, and ask for
///   `-ERESTART_RESTARTBLOCK`. Carrying the absolute deadline is the entire
///   point — re-entering the relative call would sleep the FULL duration again.
/// * `TIMER_ABSTIME` (`HRTIMER_MODE_ABS`): the syscall entry already forced
///   `rmtp = NULL` (`kernel/time/posix-timers.c:1400-1401`), so nothing is
///   copied out, NO restart block is armed, and the code is `-ERESTARTNOHAND`
///   — re-entering the same absolute call is already the remainder.
/// # C: O(1)
fn interrupt_result(cur: &sched::Task, rem: u64, deadline: u64, is_abs: bool) -> i64 {
    let left = deadline.saturating_sub(monotonic_ns());
    // `rem <= 0` in Linux's `do_nanosleep`: the sleep actually completed.
    if left == 0 { return 0; }
    if is_abs { return syscall::restart::restart_nohand(); }
    if let Err(rv) = write_remaining(rem, left) { return rv; }
    arm_restart_block(cur, deadline, rem);
    syscall::restart::restart_block()
}

fn arm_restart_block(cur: &sched::Task, deadline: u64, rem: u64) {
    use sched::task::restart::RESTART_NANOSLEEP;
    cur.restart_block.arm(RESTART_NANOSLEEP, [deadline, rem, 0, 0, 0, 0]);
}

/// One pass of Linux `do_nanosleep`'s loop (`kernel/time/hrtimer.c:2394-2423`)
/// minus the park itself. Lives OUTSIDE the `target_os = "oxide-kernel"` gate so
/// the wake triage — which of the three exits runs the interrupted tail — is the
/// same code the hosted suite drives (`08§7` phantom-test rule).
pub(crate) enum SleepStep {
    /// `if (!t->task) return 0` (`:2408`) — the expiry passed.
    Done,
    /// A deliverable signal: the tail's code is the syscall's result and the
    /// syscall-return tail owns the ERESTART* decision.
    Return(i64),
    /// A SIG_DFL job-control stop. `signal_pending(current)` is TRUE for a stop
    /// signal, so Linux's loop condition (`:2404`) exits on it exactly like a
    /// deliverable one: `do_nanosleep`'s `rmtp` copyout (`:2412-2421`) and
    /// `hrtimer_nanosleep`'s restart-block arm (`:2455-2458`) BOTH run before
    /// the task ever stops in `get_signal`. This kernel collapses that stop and
    /// the `restart_syscall(2)` resume back into the park loop, so `tail`
    /// carries the code that ran ahead of the stop.
    Stop { sig: u32, tail: i64 },
    /// Nothing actionable — park until the absolute expiry.
    Park,
}

/// # C: O(1)
pub(crate) fn sleep_step(cur: &sched::Task, rem: u64, deadline: u64, is_abs: bool) -> SleepStep {
    if monotonic_ns() >= deadline { return SleepStep::Done; }
    match cur.sleep_wake() {
        SleepWake::Deliver => SleepStep::Return(interrupt_result(cur, rem, deadline, is_abs)),
        SleepWake::Stop(sig) => SleepStep::Stop { sig, tail: interrupt_result(cur, rem, deadline, is_abs) },
        SleepWake::None => SleepStep::Park,
    }
}

/// Whether the stop arm's tail produced a result that must reach userspace
/// instead of being resumed. Only `nanosleep_copyout`'s EFAULT
/// (`hrtimer.c:2382`) qualifies: an ERESTART* code means "resume", which the
/// collapsed loop performs itself, and `0` means the expiry passed, which the
/// loop head re-derives on the next pass.
/// # C: O(1)
pub(crate) const fn stop_tail_is_fatal(tail: i64) -> bool {
    tail != 0 && !syscall::restart::is_restart_code(tail)
}

/// Linux `hrtimer_nanosleep_restart`: the `restart_syscall(2)` continuation.
/// Resumes an HRTIMER_MODE_ABS sleep against the stored expiry, so repeated
/// interruptions never extend the total sleep.
/// # C: O(schedules until deadline or actionable signal)
#[cfg(target_os = "oxide-kernel")]
pub fn nanosleep_restart(cur: &sched::Task, deadline: u64, rem: u64) -> i64 {
    // Linux `hrtimer_nanosleep_restart` runs `do_nanosleep` DIRECTLY, not
    // through `hrtimer_nanosleep`, so the ABS/REL conversion at
    // `hrtimer.c:2450` never applies: a resumed sleep keeps the relative
    // form's copy-out-and-rearm tail. Only the relative form ever arms a
    // block, so this is the only continuation that can be reached.
    sleep_until_deadline(cur, deadline, rem, false)
}

/// Shared interruptible-sleep engine — Linux `do_nanosleep`. `nanosleep(2)`
/// (035) and `clock_nanosleep(2)` (230) both land here, so there is ONE park
/// loop, ONE signal triage (`Task::sleep_wake`) and ONE interrupted tail.
/// # C: O(schedules until deadline or actionable signal)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn sleep_until_deadline(cur: &sched::Task, deadline: u64, rem: u64, is_abs: bool) -> i64 {
    loop {
        match sleep_step(cur, rem, deadline, is_abs) {
            SleepStep::Done => return 0,
            SleepStep::Return(rv) => return rv,
            SleepStep::Stop { sig, tail } => {
                // Linux stops in `get_signal` AFTER `hrtimer_nanosleep` has
                // returned, so the copyout above already happened; SIGCONT then
                // resumes through `restart_syscall(2)` against the same absolute
                // expiry, which is what re-entering this loop does.
                sched::live::stop::stop_until_cont_sig(sig as u8);
                if stop_tail_is_fatal(tail) { return tail; }
                continue;
            }
            SleepStep::Park => {}
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
pub(crate) fn sleep_until_deadline(cur: &sched::Task, deadline: u64, rem: u64, is_abs: bool) -> i64 {
    // One pass: hosted has no scheduler to park or stop on, so the stop arm
    // reports the tail it ran ahead of the stop — the copyout and armed block
    // the guest observes across a SIGSTOP/SIGCONT pair.
    match sleep_step(cur, rem, deadline, is_abs) {
        SleepStep::Done => 0,
        SleepStep::Return(rv) => rv,
        SleepStep::Stop { sig, tail } => { let _ = sig; tail }
        SleepStep::Park => -(syscall::Errno::Eintr.as_i32() as i64),
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
    // Linux `SYSCALL_DEFINE2(nanosleep)`: `restart_block.fn =
    // do_no_restart_syscall` before the sleep, so a fresh call never inherits
    // a previous one's continuation.
    cur.restart_block.disarm();
    // `nanosleep(2)` is always `HRTIMER_MODE_REL` + CLOCK_MONOTONIC
    // (`kernel/time/hrtimer.c:2480`), so it can never take the ABSTIME arm.
    sleep_until_deadline(cur, deadline, rem, false)
}

#[cfg(test)]
pub fn nanosleep_actionable_signal_pending_for_test(cur: &sched::Task) -> bool {
    cur.sleep_wake() == SleepWake::Deliver
}
