// 446 landlock_restrict_self — one syscall, one file (docs/53 §0). Snapshot the
// ruleset into a new layer on top of whatever the thread already enforces.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use ::landlock::abi;
use ::landlock::Domain;

/// `sys_landlock_restrict_self(ruleset_fd, flags)` — slot 446.
///
/// The resulting domain is a fresh immutable snapshot with one more layer than
/// before. Two consequences the shim depends on: the ruleset fd stays writable
/// but can no longer affect what is enforced, and the new domain is at least as
/// restrictive as the old one because layers are only appended.
/// # C: O(N_rules)
pub fn sys_landlock_restrict_self(args: &SyscallArgs) -> i64 {
    let fd    = args.a0 as i32;
    let flags = args.a1 as u32;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let nnp = cur.no_new_privs.load(core::sync::atomic::Ordering::Acquire);
    let cap = cur.has_cap(sched::cap::SYS_ADMIN);
    if let Err(e) = abi::restrict_self_precheck(nnp, cap, flags) {
        return -(e.as_i32() as i64);
    }

    let rs = match crate::landlock::ruleset_from_fd(fd) {
        Ok(r) => r, Err(e) => return -(e.as_i32() as i64),
    };
    let parent = crate::landlock::current_domain();
    let dom = match Domain::merge(parent.as_ref(), &rs) {
        Ok(d) => d, Err(e) => return -(e.as_i32() as i64),
    };
    match crate::landlock::set_current_domain(dom) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}
