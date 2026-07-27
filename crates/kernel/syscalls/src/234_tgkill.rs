// 234 tgkill — one syscall, one file (docs/53 §0).
//
// Linux `SYSCALL_DEFINE3(tgkill, pid_t tgid, pid_t pid, int sig)`:
//     if (pid <= 0 || tgid <= 0) return -EINVAL;
//     return do_tkill(tgid, pid, sig);
//
// The `tgid` argument is load-bearing, not decoration: `do_send_specific`
// returns ESRCH when the tid exists but no longer belongs to that thread
// group, which is what closes the tid-reuse race `tkill(2)` leaves open. The
// delivery itself is shared with slot 200 in `tkill_common` so the two cannot
// drift.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::tkill_common::{ArgCheck, arg_check, do_tkill, einval};

/// `sys_tgkill(tgid, tid, sig)` — slot 234.
/// # C: O(N_tasks) registry lookup
pub fn sys_tgkill(args: &SyscallArgs) -> i64 {
    let tgid = args.a0 as i32;
    let tid  = args.a1 as i32;
    let sig  = args.a2 as i32;
    if arg_check(Some(tgid), tid) == ArgCheck::Einval { return einval(); }
    do_tkill(Some(tgid as u32), tid as u32, sig)
}
