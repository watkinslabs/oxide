// 034 pause — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.

use syscall::SyscallArgs;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

fn ignored_or_noop(sig: u32, handler: u64) -> bool {
    if handler == SIG_IGN { return true; }
    if handler != SIG_DFL { return false; }
    matches!(sched::signum::default_action(sig),
        sched::signum::DefaultAction::Ign | sched::signum::DefaultAction::Cont)
}

fn default_stop(sig: u32, handler: u64) -> bool {
    handler == SIG_DFL && sched::signum::default_action(sig) == sched::signum::DefaultAction::Stop
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PauseWake {
    None,
    Complete,
    Stop(u32),
}

fn pause_wake(cur: &sched::Task) -> PauseWake {
    use core::sync::atomic::Ordering;
    loop {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let masked  = cur.sigmask.load(Ordering::Acquire);
        let sig = match sched::signum::next_deliverable(pending, masked) {
            Some(s) => s,
            None    => return PauseWake::None,
        };
        let act = cur.sigactions_ref().get(sig);
        if ignored_or_noop(sig, act.handler) {
            cur.flush_pending_signal(sig as usize);
            continue;
        }
        if default_stop(sig, act.handler) {
            cur.flush_pending_signal(sig as usize);
            return PauseWake::Stop(sig);
        }
        return PauseWake::Complete;
    }
}

#[cfg(target_os = "oxide-kernel")]
fn sleep_until_actionable_signal(cur: &sched::Task) -> i64 {
    use sched::TaskState;
    loop {
        match pause_wake(cur) {
            PauseWake::Complete => return syscall::restart::restart_nohand(),
            PauseWake::Stop(sig) => {
                sched::live::stop::stop_until_cont_sig(sig as u8);
                continue;
            }
            PauseWake::None => {}
        }
        cur.set_state(TaskState::Sleeping);
        match pause_wake(cur) {
            PauseWake::Complete => {
                cur.set_state(TaskState::Runnable);
                return syscall::restart::restart_nohand();
            }
            PauseWake::Stop(sig) => {
                cur.set_state(TaskState::Runnable);
                sched::live::stop::stop_until_cont_sig(sig as u8);
                continue;
            }
            PauseWake::None => {}
        }
        // SAFETY: current task was marked Sleeping; signal delivery wakes it via
        // try_to_wake_up, and the loop rechecks pending state after schedule.
        unsafe { sched::live::park_yield(); }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn sleep_until_actionable_signal(cur: &sched::Task) -> i64 {
    if pause_wake(cur) == PauseWake::Complete { syscall::restart::restart_nohand() }
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
    pause_wake(cur) == PauseWake::Complete
}
