// CPU-time `clock_nanosleep(2)` — Linux `kernel/time/posix-cpu-timers.c`
// `do_cpu_nanosleep` (`:1537-1626`), `posix_cpu_nsleep` (`:1630-1655`) and
// `posix_cpu_nsleep_restart` (`:1657-1665`).
//
// Linux does NOT convert a CPU clock to a wall deadline. `do_cpu_nanosleep`
// arms a TEMPORARY `k_itimer` with `it.cpu.nanosleep = true` and blocks; when
// the timer fires, `cpu_timer_fire` (`:682-688`) takes its wake branch instead
// of queueing a signal. Converting to wall time — which this kernel used to do
// — makes a process-CPU sleep expire on ELAPSED time, which is wrong whenever
// the caller is not the only runnable task.
//
// It has to be event-driven for a structural reason: a task that is asleep
// accrues no CPU time, so only a RUNNING sibling can advance the clock. That is
// also exactly why Linux rejects a per-thread clock naming the caller — such a
// sleep could never complete.
//
// The pure rules live here (non-gated, hosted-tested); the park loop is in
// `body`, which needs a live runqueue.

use crate::posix_clock::ClockSpec;

/// Linux `posix_cpu_nsleep`'s "diagnose required errors first"
/// (`posix-cpu-timers.c:1637-1642`):
///
/// ```c
/// if (CPUCLOCK_PERTHREAD(which_clock) &&
///     (CPUCLOCK_PID(which_clock) == 0 ||
///      CPUCLOCK_PID(which_clock) == task_pid_vnr(current)))
///     return -EINVAL;
/// ```
///
/// A per-thread CPU clock naming pid 0 or the caller itself can never make
/// progress, so it is rejected up front rather than sleeping forever.
/// # C: O(1)
pub const fn perthread_names_self(per_thread: bool, target_pid: u32, caller_pid: u32) -> bool {
    per_thread && (target_pid == 0 || target_pid == caller_pid)
}

/// What an interrupted CPU sleep returns — Linux `do_cpu_nanosleep`'s tail
/// (`posix-cpu-timers.c:1606-1620`) plus `posix_cpu_nsleep`'s ABS/REL split
/// (`:1646-1653`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuSleepExit {
    /// `if ((it.it_value.tv_sec | it.it_value.tv_nsec) == 0) return 0;` — the
    /// timer did fire after all, so the sleep completed.
    Completed,
    /// `TIMER_ABSTIME` — `-ERESTARTNOHAND`, no restart block, no remainder
    /// copied out (`:1648-1649`).
    RestartNoHand,
    /// Relative — arm `posix_cpu_nsleep_restart` with the ABSOLUTE CPU expiry
    /// and return `-ERESTART_RESTARTBLOCK` (`:1616-1619`, `:1651-1652`).
    RestartBlock,
}

/// The interrupted-return decision. `remaining_ns` is `it.it_value` — the CPU
/// time still owed when the signal landed.
///
/// NOTE the ordering: "did it actually fire" is tested BEFORE the ABS/REL
/// split, so an absolute sleep that completed in the same instant returns 0
/// rather than ERESTARTNOHAND.
/// # C: O(1)
pub const fn cpu_sleep_exit(is_abs: bool, remaining_ns: u64) -> CpuSleepExit {
    if remaining_ns == 0 { return CpuSleepExit::Completed; }
    if is_abs { return CpuSleepExit::RestartNoHand; }
    CpuSleepExit::RestartBlock
}

/// Whether `clock` is one this path owns.
/// # C: O(1)
pub const fn is_cpu_clock(clock: ClockSpec) -> bool {
    matches!(clock, ClockSpec::Cpu(_) | ClockSpec::CpuEncoded { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_perthread_clock_naming_self_or_pid_zero_is_rejected() {
        // Such a sleep can never progress: the sleeper accrues no CPU time.
        assert!(perthread_names_self(true, 0, 42));
        assert!(perthread_names_self(true, 42, 42));
    }

    #[test]
    fn a_perthread_clock_naming_another_thread_is_allowed() {
        // That thread's CPU time advances while the caller sleeps.
        assert!(!perthread_names_self(true, 43, 42));
    }

    #[test]
    fn a_process_wide_clock_is_never_rejected_by_this_rule() {
        // `CPUCLOCK_PERTHREAD(which_clock)` gates the whole check.
        assert!(!perthread_names_self(false, 0, 42));
        assert!(!perthread_names_self(false, 42, 42));
    }

    #[test]
    fn a_sleep_with_nothing_left_owed_completed_regardless_of_form() {
        // `it.it_value == 0` is tested before the ABSTIME split, so an
        // absolute sleep that just fired returns 0, not ERESTARTNOHAND.
        assert_eq!(cpu_sleep_exit(true, 0), CpuSleepExit::Completed);
        assert_eq!(cpu_sleep_exit(false, 0), CpuSleepExit::Completed);
    }

    #[test]
    fn timer_abstime_never_arms_a_restart_block() {
        assert_eq!(cpu_sleep_exit(true, 1), CpuSleepExit::RestartNoHand);
        assert_eq!(cpu_sleep_exit(true, u64::MAX), CpuSleepExit::RestartNoHand);
    }

    #[test]
    fn the_relative_form_arms_one() {
        assert_eq!(cpu_sleep_exit(false, 1), CpuSleepExit::RestartBlock);
        assert_eq!(cpu_sleep_exit(false, 5_000_000_000), CpuSleepExit::RestartBlock);
    }

    #[test]
    fn only_the_cpu_clock_specs_route_here() {
        assert!(!is_cpu_clock(ClockSpec::Monotonic));
        assert!(!is_cpu_clock(ClockSpec::Realtime));
        assert!(!is_cpu_clock(ClockSpec::Boottime));
        assert!(!is_cpu_clock(ClockSpec::RealtimeAlarm));
    }
}

/// Linux `do_cpu_nanosleep` (`posix-cpu-timers.c:1537-1626`): arm a temporary
/// timer on the CPU clock, block until it fires or a signal lands, then report
/// the CPU time still owed.
///
/// `value_ns` is the request; `absolute` selects `TIMER_ABSTIME`. Returns the
/// remaining CPU time (0 = the sleep completed).
///
/// The timer lives in the thread group's slot table with [`Notify::Wake`], so
/// `account_cpu_tick` — which already runs on the RUNNING task — is what
/// releases the sleeper. That is Linux's structure, not a parallel mechanism.
/// # SAFETY: process context on the running task with the runqueue installed.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(schedules until the CPU deadline or a signal)
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
pub unsafe fn body(current: &crate::Task, clock: ClockSpec, absolute: bool, value_ns: u64) -> u64 {
    use super::{backend, clock as clockmod, runtime, slots};
    use crate::timer_model::{Notify, PosixTimer};
    let domain = crate::posix_clock::sample_domain(clock);
    let Some(now) = clockmod::now_ns(domain) else { return 0 };
    let deadline = if absolute { value_ns } else { now.saturating_add(value_ns) }.max(1);
    if deadline <= now { return 0; }

    let id = {
        let _guard = backend::lock();
        // SAFETY: the backend lock serializes all process-wide timer slot access.
        let table = unsafe { &mut *current.thread_group.posix_timers.get() };
        let Some(id) = slots::allocate_id(table) else { return 0 };
        let mut timer = PosixTimer::allocate(clock, Notify::Wake { tid: current.tid });
        timer.set(domain, deadline, 0);
        table[id] = timer;
        id
    };

    loop {
        let sampled = clockmod::now_ns(domain).unwrap_or(deadline);
        if sampled >= deadline { break; }
        if current.deliverable_signals() != 0 { break; }
        // SAFETY: process context; the CPU-timer tick on a running sibling
        // wakes us through `service_wake`'s `Notify::Wake` branch, and the
        // deadline scanner is not involved because this clock is not wall time.
        unsafe {
            CPU_SLEEPERS.park_interruptible_with_deadline(0);
            crate::live::park_yield();
        }
    }

    let remaining = {
        let _guard = backend::lock();
        // SAFETY: same slot-table contract as the arm above.
        let table = unsafe { &mut *current.thread_group.posix_timers.get() };
        let left = clockmod::now_ns(domain).map(|n| deadline.saturating_sub(n)).unwrap_or(0);
        if let Some(slot) = table.get_mut(id) { *slot = PosixTimer::default(); }
        left
    };
    let _ = runtime::reprogram_posix_timers;
    remaining
}

/// Wait list the CPU sleepers park on. They are released by
/// `service_wake`'s `ttwu_deferred`, not by a list wake, so this only provides
/// the Sleeping publication + signal-race close.
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
static CPU_SLEEPERS: crate::live::WaitList = crate::live::WaitList::new();
