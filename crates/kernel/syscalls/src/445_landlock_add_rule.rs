// 445 landlock_add_rule — one syscall, one file (docs/53 §0). Parse, validate
// through `landlock::abi`, store on the ruleset. No policy here.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::landlock::abi;
use ::landlock::uapi::*;
use ::landlock::Ruleset;
use vfs::FileType;

/// `sys_landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)` — slot 445.
/// # C: O(1)
pub fn sys_landlock_add_rule(args: &SyscallArgs) -> i64 {
    let fd        = args.a0 as i32;
    let rule_type = args.a1;
    let attr      = args.a2;
    let flags     = args.a3 as u32;

    if let Err(e) = abi::add_rule_flags_ok(flags) { return -(e.as_i32() as i64); }
    let rs = match crate::landlock::ruleset_from_fd(fd) {
        Ok(r) => r, Err(e) => return -(e.as_i32() as i64),
    };
    match rule_type {
        RULE_PATH_BENEATH => add_path_beneath(&rs, attr, flags),
        RULE_NET_PORT     => add_net_port(&rs, attr, flags),
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// `struct landlock_path_beneath_attr`: packed u64 `allowed_access` then s32
/// `parent_fd`.
/// # C: O(1)
fn add_path_beneath(rs: &Arc<Ruleset>, attr: u64, flags: u32) -> i64 {
    let mut buf = [0u8; PATH_BENEATH_ATTR_SIZE];
    if attr == 0 || uaccess::copy_from_user(&mut buf, attr).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let allowed = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3],
                                      buf[4], buf[5], buf[6], buf[7]]);
    let parent_fd = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

    // Access admission runs before the descriptor is resolved, so a policy bug
    // is reported as such rather than as a descriptor problem.
    if let Err(e) = abi::rule_access_ok(allowed, rs.handled_fs, flags, rs.quiet_fs) {
        return -(e.as_i32() as i64);
    }

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of its own fd table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let pf = match fdt.get(parent_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // A ruleset fd names no hierarchy, so it can never anchor a rule; accepting
    // it would install a rule that matches nothing.
    if crate::landlock::is_ruleset_file(&pf) { return -(Errno::Ebadfd.as_i32() as i64); }
    let inode = pf.inode().clone();
    let is_dir = inode.file_type() == FileType::Directory;
    match rs.add_fs(inode, is_dir, allowed, flags) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// `struct landlock_net_port_attr`: u64 `allowed_access` then u64 `port`.
/// # C: O(1)
fn add_net_port(rs: &Arc<Ruleset>, attr: u64, flags: u32) -> i64 {
    let mut buf = [0u8; NET_PORT_ATTR_SIZE];
    if attr == 0 || uaccess::copy_from_user(&mut buf, attr).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let allowed = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3],
                                      buf[4], buf[5], buf[6], buf[7]]);
    let port = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11],
                                   buf[12], buf[13], buf[14], buf[15]]);
    match rs.add_net(port, allowed, flags) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}
