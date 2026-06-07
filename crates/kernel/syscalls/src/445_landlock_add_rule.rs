// 445 landlock_add_rule — one syscall, one file (docs/53 §0). Moved verbatim from landlock.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::security::landlock::{self as ll, Rule};

use crate::landlock::LandlockRulesetInode;

/// `sys_landlock_add_rule(ruleset_fd, type, rule_attr, flags)` —
/// slot 445. Currently only `rule_type == LANDLOCK_RULE_PATH_BENEATH`
/// (1) is supported; arg is `struct landlock_path_beneath_attr
/// { __u64 allowed_access; __s32 parent_fd; }`.
/// # C: O(1)
pub fn sys_landlock_add_rule(args: &SyscallArgs) -> i64 {
    const LANDLOCK_RULE_PATH_BENEATH: u64 = 1;
    let fd        = args.a0 as i32;
    let rule_type = args.a1;
    let attr      = args.a2;
    if rule_type != LANDLOCK_RULE_PATH_BENEATH {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr == 0 || attr >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: attr validated < USER_VA_END; struct landlock_path_beneath_attr layout: u64 allowed + i32 parent_fd; aligned reads through caller's AS.
    let allowed = unsafe { core::ptr::read_volatile(attr as *const u64) };
    // SAFETY: parent_fd at attr+8 inside the same validated struct landlock_path_beneath_attr; aligned i32 read through caller's AS.
    let parent_fd = unsafe { core::ptr::read_volatile((attr + 8) as *const i32) };
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per `13§5` single-mutator.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Resolve ruleset fd.
    let rs_file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let rs_any = match rs_file.inode().as_any() { Some(a) => a, None => return -(Errno::Einval.as_i32() as i64) };
    let rs_inode = match rs_any.downcast_ref::<LandlockRulesetInode>() {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    let ruleset = match ll::lookup(rs_inode.ruleset_id) {
        Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
    };
    // Resolve parent_fd → path.
    let parent_file = match fdt.get(parent_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let path: String = parent_file.dentry().name().into();
    ruleset.add(Rule { path_prefix: path, allowed });
    0
}
