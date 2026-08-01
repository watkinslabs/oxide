// 446 landlock_restrict_self — one syscall, one file (docs/53 §0). Snapshot the
// ruleset into a new layer on top of whatever the thread already enforces.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
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
        if plan.propagate_no_new_privs { propagate_no_new_privs(&cur); }
        return 0;
    }

    let rs = match crate::landlock::ruleset_from_fd(fd) {
        Ok(r) => r, Err(e) => return -(e.as_i32() as i64),
    };
    let parent = crate::landlock::current_domain();
    let dom = match Domain::merge(parent.as_ref(), &rs) {
        Ok(d) => d, Err(e) => return -(e.as_i32() as i64),
    };
    if let Err(e) = crate::landlock::set_current_domain(dom.clone()) {
        return -(e.as_i32() as i64);
    }
    if plan.tsync { sync_siblings(&cur, &dom, plan.propagate_no_new_privs); }
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

/// Replace every sibling thread's domain with `dom`.
///
/// The new domain replaces whatever a sibling had rather than stacking on it:
/// the point of synchronising is that the whole process ends up under one
/// policy, and a sibling that had sandboxed itself separately would otherwise
/// end up under a different one. Each thread's domain is its own lock, and the
/// caller's own was already set, so the caller is skipped here.
/// # C: O(N_threads)
fn sync_siblings(cur: &sched::Task, dom: &Arc<Domain>, nnp: bool) {
    let tgid = cur.tgid.load(Ordering::Acquire);
    for t in sched::registry::thread_group(tgid) {
        if t.tid == cur.tid { continue; }
        *t.landlock_domain.lock() = Some(dom.clone());
        if nnp { t.no_new_privs.store(true, Ordering::Release); }
    }
}

/// Turn on `no_new_privs` across the thread group without touching policy.
/// # C: O(N_threads)
fn propagate_no_new_privs(cur: &sched::Task) {
    let tgid = cur.tgid.load(Ordering::Acquire);
    for t in sched::registry::thread_group(tgid) {
        t.no_new_privs.store(true, Ordering::Release);
    }
}
