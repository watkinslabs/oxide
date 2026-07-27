// 141 setpriority — one syscall, one file (docs/53 §0).
//
// setpriority(which, who, prio): PRIO_PROCESS (0) / PRIO_PGRP (1) /
// PRIO_USER (2). Clamps nice to [-20,19] and rewrites the live CFS
// weight so the change shifts CPU shares. Shared target resolution
// lives in priority_common.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::priority_common::for_each_target;

/// `sys_setpriority(which, who, prio)` — slot 141. Clamps nice to [-20,19],
/// then applies Linux `set_one_prio` per target: an owner mismatch is EPERM and
/// an unprivileged nice reduction beyond RLIMIT_NICE is EACCES.
/// # C: O(N_tasks)
pub fn sys_setpriority(args: &SyscallArgs) -> i64 {
    use sched::rlimit::{nice_to_rlimit, prio_which};
    let (which, who, prio) = (args.a0, args.a1 as u32, args.a2 as i32);
    // EINVAL is the seed error: Linux only replaces it with -ESRCH after the
    // `which` bound passes, so a bad `which` reports EINVAL even when no task
    // would have matched.
    if which > prio_which::USER { return -(Errno::Einval.as_i32() as i64); }
    // Linux SATURATES an out-of-range niceval rather than rejecting it.
    let n = sched::rlimit::clamp_nice(prio);
    let w = sched::cputime::nice_to_weight(n);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    let has_nice = cur.has_cap(sched::cap::SYS_NICE);
    let euid = cur.creds.euid.load(Ordering::Acquire);

    // Linux seeds `error = -ESRCH`; a permitted target flips it to 0, a
    // permission failure overwrites it with EPERM/EACCES.
    let mut error: i64 = -(Errno::Esrch.as_i32() as i64);
    for_each_target(which, who, |t| {
        // `set_one_prio_perm`: caller's euid matches the target's euid or ruid,
        // or the caller holds CAP_SYS_NICE.
        let owner_ok = has_nice
            || euid == t.creds.euid.load(Ordering::Acquire)
            || euid == t.creds.ruid.load(Ordering::Acquire);
        if !owner_ok { error = -(Errno::Eperm.as_i32() as i64); return; }
        // `can_nice`: a nice reduction (raising priority) needs CAP_SYS_NICE or
        // RLIMIT_NICE headroom, expressed by Linux as `20 - nice`.
        let old = t.nice.load(Ordering::Acquire) as i32;
        if (n as i32) < old && !has_nice {
            let allowed = t.rlimit(sched::rlimit::rlim::NICE).0;
            if nice_to_rlimit(n as i32) as u64 > allowed { error = -(Errno::Eacces.as_i32() as i64); return; }
        }
        // Store the nice value AND rewrite the live CFS weight so the change
        // actually shifts CPU shares (`13§3`): nice<0 → heavier → more CPU.
        t.nice.store(n, Ordering::Release);
        t.load_weight.store(w, Ordering::Release);
        if error == -(Errno::Esrch.as_i32() as i64) { error = 0; }
    });
    error
}
