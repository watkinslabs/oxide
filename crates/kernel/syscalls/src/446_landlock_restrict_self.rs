// 446 landlock_restrict_self — one syscall, one file (docs/53 §0). Moved verbatim from landlock.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::security::landlock::{self as ll};

use crate::landlock::LandlockRulesetInode;

/// `sys_landlock_restrict_self(ruleset_fd, flags)` — slot 446.
/// Push the ruleset id onto the caller's landlock_chain so every
/// subsequent path-based syscall consults it. Idempotent: re-
/// pushing the same id is allowed; chain order = registration
/// order.
/// # C: O(1)
pub fn sys_landlock_restrict_self(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let any = match file.inode().as_any() { Some(a) => a, None => return -(Errno::Einval.as_i32() as i64) };
    let rs_inode = match any.downcast_ref::<LandlockRulesetInode>() {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    if ll::lookup(rs_inode.ruleset_id).is_none() {
        return -(Errno::Einval.as_i32() as i64);
    }
    cur.landlock_chain.lock().push(rs_inode.ruleset_id);
    0
}
