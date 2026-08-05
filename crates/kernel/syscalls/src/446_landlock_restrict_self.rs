// 446 landlock_restrict_self — one syscall, one file (docs/53 §0). Snapshot the
// ruleset into a new layer on top of whatever the thread already enforces.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

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
/// # C: O(N_rules + N_threads)
pub fn sys_landlock_restrict_self(args: &SyscallArgs) -> i64 {
    let fd    = args.a0 as i32;
    let flags = args.a1 as u32;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let nnp = cur.no_new_privs.load(Ordering::Acquire);
    if let Err(e) = abi::restrict_self_precheck(nnp, cap_sys_admin_in_own_user_ns(&cur), flags) {
        return -(e.as_i32() as i64);
    }
    let plan = abi::restrict_plan(fd, flags, nnp);

    // A pure logging-configuration change installs no layer. With no audit
    // subsystem there is nothing for it to configure, so it succeeds having
    // changed nothing — which is what a caller quietening its own logs expects.
    if !plan.needs_ruleset {
        if plan.propagate_no_new_privs {
            if let Err(sched::landlock_tsync::StartError::Restart) =
                sched::landlock_tsync::restrict_siblings(cur, None, true)
            {
                return syscall::restart::restart_nointr();
            }
        }
        return 0;
    }

    let rs = match crate::landlock::ruleset_from_fd(fd) {
        Ok(r) => r, Err(e) => return -(e.as_i32() as i64),
    };
    let parent = crate::landlock::current_domain();
    let dom = match Domain::merge(parent.as_ref(), &rs) {
        Ok(d) => d, Err(e) => return -(e.as_i32() as i64),
    };
    if plan.tsync {
        if let Err(sched::landlock_tsync::StartError::Restart) =
            sched::landlock_tsync::restrict_siblings(
                cur, Some(dom), plan.propagate_no_new_privs)
        {
            return syscall::restart::restart_nointr();
        }
    } else if let Err(e) = crate::landlock::set_current_domain(dom) {
        return -(e.as_i32() as i64);
    }
    0
}

/// Whether the caller holds the administrative capability **in its own user
/// namespace**, which is the alternative to `no_new_privs` for enforcing a
/// policy. Testing the capability without resolving the namespace would let a
/// thread that is only root inside an unprivileged user namespace enforce a
/// policy a later set-user-ID exec still runs under.
/// # C: O(N_userns_depth)
fn cap_sys_admin_in_own_user_ns(cur: &sched::Task) -> bool {
    match cur.namespace_owner(namespace_identity::NamespaceKind::User) {
        Some(own) => nscg::proc_ns::has_cap_for(cur, &own.pin(), sched::cap::SYS_ADMIN),
        None => cur.has_cap(sched::cap::SYS_ADMIN),
    }
}
