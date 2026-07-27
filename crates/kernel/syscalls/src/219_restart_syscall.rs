// 219 restart_syscall — one syscall, one file (docs/53 §0).
//
// Linux `SYSCALL_DEFINE0(restart_syscall)`:
//     struct restart_block *restart = &current->restart_block;
//     return restart->fn(restart);
//
// Userspace never calls this deliberately. The syscall-return tail rewrites an
// interrupted task's syscall-number register to this slot when the call
// returned `-ERESTART_RESTARTBLOCK` and no handler ran
// (`dispatch/restart.rs`, Linux `arch_do_signal_or_restart`). The block
// carries an ABSOLUTE deadline, so resuming here sleeps the REMAINING time —
// re-entering the original relative call would restart the full duration.
//
// `docs/07§5` bans indirect-call tables in the kernel, so Linux's
// `restart->fn` pointer is a `kind` discriminant owned by
// `sched::task::restart` and the continuation bodies live here — one owner
// for the dispatch, no parallel registry.

#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;
use sched::task::restart::{RESTART_NANOSLEEP, RESTART_NONE};

/// Linux `do_no_restart_syscall(param)` — an unarmed (or already-consumed)
/// block reports EINTR.
/// # C: O(1)
pub const fn no_restart_syscall() -> i64 { -(syscall::errno::Errno::Eintr.as_i32() as i64) }

/// Continuation selected for a restart block of `kind`. `None` means Linux's
/// `do_no_restart_syscall`. Split out from the syscall body so the dispatch
/// table is hosted-testable without a live task.
/// # C: O(1)
pub const fn dispatches_to_nanosleep(kind: u32) -> bool { kind == RESTART_NANOSLEEP }

/// `sys_restart_syscall()` — slot 219.
/// # C: O(1) + the resumed call's cost
#[cfg(target_os = "oxide-kernel")]
pub fn sys_restart_syscall(_args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return no_restart_syscall(); };
    let kind = cur.restart_block.kind();
    if dispatches_to_nanosleep(kind) {
        // Linux `hrtimer_nanosleep_restart`: HRTIMER_MODE_ABS against the
        // stored expiry, with the original `rmtp` still armed for copyout.
        let a = cur.restart_block.args();
        return crate::s035_nanosleep::nanosleep_restart(cur, a[0], a[1]);
    }
    debug_assert!(kind == RESTART_NONE || !dispatches_to_nanosleep(kind));
    no_restart_syscall()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_block_is_eintr() {
        assert_eq!(no_restart_syscall(), -(syscall::errno::Errno::Eintr.as_i32() as i64));
        assert!(!dispatches_to_nanosleep(RESTART_NONE));
    }

    #[test]
    fn nanosleep_kind_selects_the_nanosleep_continuation() {
        assert!(dispatches_to_nanosleep(RESTART_NANOSLEEP));
        // Any unknown discriminant falls back to do_no_restart_syscall.
        assert!(!dispatches_to_nanosleep(RESTART_NANOSLEEP + 1));
        assert!(!dispatches_to_nanosleep(u32::MAX));
    }
}
