// 034 pause — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.

use syscall::SyscallArgs;

use sched::SleepWake;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// Linux `SYSCALL_DEFINE0(pause)` (`kernel/signal.c:4832-4839`):
/// `while (!signal_pending(current)) { set TASK_INTERRUPTIBLE; schedule(); }`
/// then `return -ERESTARTNOHAND`. A SIG_DFL job-control stop satisfies
/// `signal_pending` like any other signal, so it ENDS the loop; the
/// syscall-return tail runs `get_signal` -> `do_signal_stop`, and after SIGCONT
/// the no-handler arm of `arch_do_signal_or_restart` restarts `pause(2)` itself
/// (ERESTARTNOHAND). B1456: stopping inside this loop resumed by `continue`
/// instead, so the restart decision never ran.
/// # C: O(schedules until signal)
#[cfg(target_os = "oxide-kernel")]
fn sleep_until_actionable_signal(cur: &sched::Task) -> i64 {
    use sched::TaskState;
    loop {
        if cur.sleep_wake() == SleepWake::Deliver { return syscall::restart::restart_nohand(); }
        cur.set_state(TaskState::Sleeping);
        if cur.sleep_wake() == SleepWake::Deliver {
            cur.set_state(TaskState::Runnable);
            return syscall::restart::restart_nohand();
        }
        // SAFETY: current task was marked Sleeping; signal delivery wakes it via
        // try_to_wake_up, and the loop rechecks pending state after schedule.
        unsafe { sched::live::park_yield(); }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn sleep_until_actionable_signal(cur: &sched::Task) -> i64 {
    if cur.sleep_wake() == SleepWake::Deliver { syscall::restart::restart_nohand() }
    else { -(syscall::Errno::Eintr.as_i32() as i64) }
}

/// `sys_pause()` — slot 34. Sleep interruptibly until a signal is pending.
/// # C: O(schedules until signal)
pub fn sys_pause(_args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Eintr.as_i32() as i64),
    };
    sleep_until_actionable_signal(cur)
}

#[cfg(test)]
pub fn pause_actionable_signal_pending_for_test(cur: &sched::Task) -> bool {
    cur.sleep_wake() == SleepWake::Deliver
}
