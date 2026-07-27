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
use sched::task::restart::{RESTART_CPU_NANOSLEEP, RESTART_FUTEX, RESTART_NANOSLEEP,
                           RESTART_NONE, RESTART_POLL};

/// Linux `do_no_restart_syscall(param)` — an unarmed (or already-consumed)
/// block reports EINTR.
/// # C: O(1)
pub const fn no_restart_syscall() -> i64 { -(syscall::errno::Errno::Eintr.as_i32() as i64) }

/// Which continuation a restart block of `kind` selects — Linux's
/// `restart->fn` pointer, as the discriminant `docs/07§5` requires instead.
/// `None` means `do_no_restart_syscall`. Split out from the syscall body so
/// the dispatch table is hosted-testable without a live task.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Continuation {
    /// Linux `do_no_restart_syscall`.
    None,
    /// Linux `hrtimer_nanosleep_restart` — `nanosleep(2)` and the RELATIVE
    /// form of `clock_nanosleep(2)`.
    Nanosleep,
    /// Linux `do_restart_poll` — `poll(2)` only.
    Poll,
    /// Linux `futex_wait_restart` — a TIMED `FUTEX_WAIT`/`FUTEX_WAIT_BITSET`.
    Futex,
    /// Linux `posix_cpu_nsleep_restart` — `clock_nanosleep` on a CPU clock.
    CpuNanosleep,
}

/// # C: O(1)
pub const fn continuation_for(kind: u32) -> Continuation {
    match kind {
        RESTART_NANOSLEEP => Continuation::Nanosleep,
        RESTART_POLL      => Continuation::Poll,
        RESTART_FUTEX     => Continuation::Futex,
        RESTART_CPU_NANOSLEEP => Continuation::CpuNanosleep,
        _                 => Continuation::None,
    }
}

/// `sys_restart_syscall()` — slot 219.
/// # C: O(1) + the resumed call's cost
#[cfg(target_os = "oxide-kernel")]
pub fn sys_restart_syscall(_args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return no_restart_syscall(); };
    let a = cur.restart_block.args();
    match continuation_for(cur.restart_block.kind()) {
        // Linux `hrtimer_nanosleep_restart`: HRTIMER_MODE_ABS against the
        // stored expiry, with the original `rmtp` still armed for copyout.
        Continuation::Nanosleep => crate::s035_nanosleep::nanosleep_restart(cur, a[0], a[1]),
        // Linux `do_restart_poll`: the stored absolute `end_time`, re-armed by
        // the continuation itself if it is interrupted again.
        Continuation::Poll => crate::poll::s007_poll::poll_restart(a[0], a[1], a[2], a[3]),
        // Linux `futex_wait_restart`: the SAME absolute deadline, so a
        // repeatedly interrupted wait never extends its timeout.
        Continuation::Futex => ::ipc::live::futex::dispatch_timed(
            a[0], a[1] as u32, a[2] as u32, a[3] as u32, a[4]),
        // Linux `posix_cpu_nsleep_restart`: `do_cpu_nanosleep(which_clock,
        // TIMER_ABSTIME, &t)` against the stored absolute CPU expiry.
        Continuation::CpuNanosleep =>
            crate::clock_nanosleep::cpu_nanosleep_restart(cur, a[0], a[1], a[2]),
        Continuation::None => no_restart_syscall(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_block_is_eintr() {
        assert_eq!(no_restart_syscall(), -(syscall::errno::Errno::Eintr.as_i32() as i64));
        assert_eq!(continuation_for(RESTART_NONE), Continuation::None);
    }

    #[test]
    fn every_armed_kind_selects_its_own_continuation() {
        assert_eq!(continuation_for(RESTART_NANOSLEEP), Continuation::Nanosleep);
        assert_eq!(continuation_for(RESTART_POLL), Continuation::Poll);
        assert_eq!(continuation_for(RESTART_FUTEX), Continuation::Futex);
        assert_eq!(continuation_for(RESTART_CPU_NANOSLEEP), Continuation::CpuNanosleep);
    }

    #[test]
    fn the_kind_discriminants_are_distinct_and_none_is_zero() {
        // A fresh `RestartBlock` is all-zero, so RESTART_NONE must be 0 or an
        // unarmed block would dispatch a stale continuation.
        assert_eq!(RESTART_NONE, 0);
        let kinds = [RESTART_NONE, RESTART_NANOSLEEP, RESTART_POLL, RESTART_FUTEX,
                     RESTART_CPU_NANOSLEEP];
        for (i, a) in kinds.iter().enumerate() {
            for b in &kinds[i + 1..] { assert_ne!(a, b); }
        }
    }

    #[test]
    fn an_unknown_discriminant_falls_back_to_do_no_restart_syscall() {
        for k in [RESTART_CPU_NANOSLEEP + 1, 99, u32::MAX] {
            assert_eq!(continuation_for(k), Continuation::None, "kind={k}");
        }
    }
}
