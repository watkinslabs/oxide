// 200 tkill — one syscall, one file (docs/53 §0).
//
// Linux `SYSCALL_DEFINE2(tkill, pid_t pid, int sig)`:
//     if (pid <= 0) return -EINVAL;
//     return do_tkill(0, pid, sig);
//
// This slot previously routed to `sys_kill`, which is a different syscall:
// `kill(2)` is thread-GROUP directed (PIDTYPE_TGID, si_code SI_USER) and gives
// `pid <= 0` pgrp/broadcast meanings, so `tkill(0, sig)` fanned a signal at the
// caller's whole process group and `tkill(-1, sig)` broadcast it. `tkill` is
// thread directed (PIDTYPE_PID, si_code SI_TKILL) and rejects every
// non-positive tid.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::tkill_common::{ArgCheck, arg_check, do_tkill, einval};

/// `sys_tkill(tid, sig)` — slot 200. Signals ONE thread, even a CLONE_THREAD
/// one, without the tid-reuse guard `tgkill(2)` adds.
/// # C: O(N_tasks) registry lookup
pub fn sys_tkill(args: &SyscallArgs) -> i64 {
    let tid = args.a0 as i32;
    let sig = args.a1 as i32;
    if arg_check(None, tid) == ArgCheck::Einval { return einval(); }
    do_tkill(None, tid as u32, sig)
}
