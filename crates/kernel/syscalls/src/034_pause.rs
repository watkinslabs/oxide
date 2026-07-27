// 034 pause — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.

use syscall::SyscallArgs;

use sched::SleepWake;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

#[cfg(target_os = "oxide-kernel")]
fn sleep_until_actionable_signal(cur: &sched::Task) -> i64 {
    use sched::TaskState;
    loop {
        match cur.sleep_wake() {
            SleepWake::Deliver => return syscall::restart::restart_nohand(),
            SleepWake::Stop(sig) => {
                sched::live::stop::stop_until_cont_sig(sig as u8);
                continue;
            }
            SleepWake::None => {}
        }
        cur.set_state(TaskState::Sleeping);
        match cur.sleep_wake() {
            SleepWake::Deliver => {
                cur.set_state(TaskState::Runnable);
                return syscall::restart::restart_nohand();
            }
            SleepWake::Stop(sig) => {
                cur.set_state(TaskState::Runnable);
                sched::live::stop::stop_until_cont_sig(sig as u8);
                continue;
            }
            SleepWake::None => {}
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
