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
use crate::Task;

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

/// `pid_for_clock(which_clock, false)` — Linux `posix_cpu_timer_create`
/// (`posix-cpu-timers.c:386-411`) resolves the encoded clockid to a
/// `struct pid` ONCE and stores it on the timer; every later sample reads that
/// task, never the encoding. `do_cpu_nanosleep` runs the same create for its
/// stack timer (`:1552`), so a CPU sleep is armed and sampled on the RESOLVED
/// clock.
///
/// Skipping that step is what made a CPU-clock sleep a no-op here: the static
/// `CLOCK_PROCESS_CPUTIME_ID` classifies to [`ClockSpec::CpuEncoded`], and
/// `timers::clock::now_ns` has no arm for the ENCODED form — it samples only
/// the resolved [`ClockSpec::Cpu`]. The arm therefore read `None` and reported
/// "already expired", so `clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, …)`
/// returned 0 immediately instead of blocking (B1450).
///
/// `None` is Linux's `-EINVAL` from the failed `pid_for_clock`.
/// # C: O(N_tasks)
pub fn sleep_clock(current: &Task, clock: ClockSpec) -> Option<ClockSpec> {
    if !is_cpu_clock(clock) { return None; }
    super::clock::resolve_clock(current, clock, false)
        .filter(|resolved| matches!(resolved, ClockSpec::Cpu(_)))
}

/// [`perthread_names_self`] against a LIVE task, which is what makes the rule
/// namespace-correct: Linux compares `CPUCLOCK_PID(which_clock)` — a
/// namespace-relative pid — with `task_pid_vnr(current)`, not with an internal
/// tid, so the encoded number must go through `pid_for_clock`'s resolution
/// before it can be compared to the caller.
/// # C: O(N_tasks)
pub fn names_self(current: &Task, clock: ClockSpec) -> bool {
    let (pid, per_thread) = match clock {
        ClockSpec::CpuEncoded { pid, per_thread, .. } => (pid, per_thread),
        ClockSpec::Cpu(cpu) => (cpu.target, cpu.per_thread),
        _ => return false,
    };
    if !per_thread { return false; }
    // `CPUCLOCK_PID(which_clock) == 0` needs no resolution — it IS the caller.
    if pid == 0 { return perthread_names_self(true, 0, current.tid); }
    let Some(ClockSpec::Cpu(cpu)) = sleep_clock(current, clock) else {
        // Unresolvable is EINVAL by `pid_for_clock`'s own route, not this rule.
        return false;
    };
    perthread_names_self(true, cpu.target, current.tid)
}

/// One armed CPU sleep: the thread-group slot it occupies, the RESOLVED clock
/// it samples, and the ABSOLUTE CPU-time expiry it fires at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuSleep { pub id: usize, pub clock: ClockSpec, pub deadline_ns: u64 }

/// What arming produced, as `do_cpu_nanosleep`'s first loop test reads it
/// (`posix-cpu-timers.c:1571-1580`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuArm {
    /// `!cpu_timer_getexpires(&timer.it.cpu)` on entry — the clock is already
    /// past the request, so the sleep completed without blocking.
    Expired,
    /// Armed with [`Notify::Wake`]; only the accounting tick on a RUNNING
    /// member of the group can retire it.
    Armed(CpuSleep),
}

/// Linux `posix_cpu_timer_set`'s failure modes as `do_cpu_nanosleep` returns
/// them (`:1562-1566`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuArmError {
    /// `pid_for_clock` named no live task — `-EINVAL`.
    Invalid,
    /// The slot table is at its cap; Linux's allocation-failure errno.
    NoSlot,
}

/// Arm the temporary timer `do_cpu_nanosleep` blocks on (`:1546-1570`).
///
/// Non-gated on purpose: this is the whole decision — resolve, sample, project
/// the expiry, take a slot — and it must be reachable from hosted tests, which
/// never build the park loop.
/// # C: O(N_tasks + SLOTS)
pub fn arm(current: &Task, clock: ClockSpec, absolute: bool, value_ns: u64)
    -> Result<CpuArm, CpuArmError>
{
    use super::{backend, clock as clockmod, slots};
    use crate::timer_model::{Notify, PosixTimer};
    let Some(resolved) = sleep_clock(current, clock) else { return Err(CpuArmError::Invalid) };
    let Some(now) = clockmod::now_ns(resolved) else { return Err(CpuArmError::Invalid) };
    let deadline = if absolute { value_ns } else { now.saturating_add(value_ns) };
    if deadline <= now { return Ok(CpuArm::Expired); }
    let _guard = backend::lock();
    // SAFETY: the backend lock serializes all process-wide timer slot access.
    let table = unsafe { &mut *current.thread_group.posix_timers.get() };
    let Some(id) = slots::allocate_id(table) else { return Err(CpuArmError::NoSlot) };
    let mut timer = PosixTimer::allocate(resolved, Notify::Wake { tid: current.tid });
    timer.set(resolved, deadline, 0);
    table[id] = timer;
    Ok(CpuArm::Armed(CpuSleep { id, clock: resolved, deadline_ns: deadline }))
}

/// `it.it_value` after the wait — the CPU time still owed (`:1595-1604`) — and
/// release the slot (`posix_cpu_timer_del`). 0 means the sleep completed.
/// # C: O(N_tasks)
pub fn disarm(current: &Task, sleep: CpuSleep) -> u64 {
    use super::{backend, clock as clockmod};
    use crate::timer_model::PosixTimer;
    let _guard = backend::lock();
    // SAFETY: the backend lock serializes all process-wide timer slot access.
    let table = unsafe { &mut *current.thread_group.posix_timers.get() };
    let left = clockmod::now_ns(sleep.clock)
        .map(|now| sleep.deadline_ns.saturating_sub(now))
        .unwrap_or(0);
    if let Some(slot) = table.get_mut(sleep.id) { *slot = PosixTimer::default(); }
    left
}

/// Whether the armed expiry has been reached — `do_cpu_nanosleep`'s
/// `!cpu_timer_getexpires(&timer.it.cpu)` loop test (`:1571-1580`), read off
/// the clock the timer samples rather than off the slot, so a tick that could
/// not take the timer lock only delays the wake and never loses it.
/// # C: O(N_tasks)
pub fn fired(sleep: CpuSleep) -> bool {
    super::clock::now_ns(sleep.clock).map(|now| now >= sleep.deadline_ns).unwrap_or(true)
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
pub unsafe fn body(current: &Task, clock: ClockSpec, absolute: bool, value_ns: u64) -> u64 {
    let armed = match arm(current, clock, absolute, value_ns) {
        Ok(CpuArm::Armed(sleep)) => sleep,
        // `Expired` is `it.it_value == 0`; an arm failure returns through the
        // same "nothing owed" tail the caller maps to a completed sleep.
        _ => return 0,
    };
    // `while (!signal_pending(current)) { … schedule(); }` (`:1571-1589`) —
    // TASK_INTERRUPTIBLE, no timeout: a CPU sleep has no wall deadline, and
    // only `cpu_timer_fire`'s wake or a signal ends it.
    // SAFETY: process context on the running task with the runqueue installed;
    // this holds no lock the waker takes — `service_wake` reaches us through
    // `ttwu_deferred` from the accounting tick on a running group member.
    unsafe {
        crate::live::wait_event(&CPU_SLEEPERS, crate::WaitState::Interruptible,
            0, || 0, || fired(armed));
    }
    disarm(current, armed)
}

/// Wait list the CPU sleepers park on. They are released by
/// `service_wake`'s `ttwu_deferred`, not by a list wake, so this only provides
/// the Sleeping publication + signal-race close.
static CPU_SLEEPERS: crate::live::WaitList = crate::live::WaitList::new();
