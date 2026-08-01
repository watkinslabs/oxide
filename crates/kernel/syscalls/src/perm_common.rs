// perm_common — cross-task permission-check helpers shared by the
// signal (docs/24) and resource-limit (docs/15) syscall families.
//
// Kept OUTSIDE the `target_os = "oxide-kernel"` gate (`kernel_body.rs`)
// deliberately: every function here is pure over `&sched::Task`, so
// `cargo test -p syscalls` exercises the actual security decision on
// the host, not only at QEMU boot (`CLAUDE.md` "Verify left").
// Single source of truth: `signal_common.rs`/`062_kill.rs` and
// `302_prlimit64.rs` call into this module rather than re-deriving
// the rule.

/// Linux signal-permission check per `kill(2)`: sender may signal
/// receiver if sender holds CAP_KILL OR sender's real/effective uid
/// matches receiver's real or saved-set uid. SIGCONT is additionally
/// allowed within the same session (so `kill -CONT 0` from a parent
/// shell works even after setuid drops). Also gates
/// `rt_sigqueueinfo(2)`/`rt_tgsigqueueinfo(2)` (Linux
/// `check_kill_permission`, the same rule for both paths).
/// # C: O(1)
pub(crate) fn sig_perm_check(cur: &sched::Task, target: &sched::Task, sig: i32) -> bool {
    use core::sync::atomic::Ordering;
    use sched::Signum;
    // Landlock signal scoping. A confined thread must not reach a process
    // outside its domain, and this applies to every path below — including a
    // sibling thread and a capability holder — so a denial here wins outright.
    if ::landlock::domain::scope_denied(cur.landlock_domain.lock().as_ref(),
                                        target.landlock_domain.lock().as_ref(),
                                        ::landlock::uapi::SCOPE_SIGNAL)
    {
        return false;
    }
    // Linux `check_kill_permission`: `!same_thread_group(current, t)` gates the
    // credential test, so a thread may always signal a SIBLING regardless of
    // whose credentials each thread carries. Testing only `tid == tid` denied a
    // `pthread_kill` issued after one thread ran `setresuid`, which is exactly
    // how glibc's `__nptl_setxid` broadcast works.
    if cur.tid == target.tid { return true; }
    if cur.tgid.load(Ordering::Acquire) == target.tgid.load(Ordering::Acquire) { return true; }
    // F118: CAP_KILL must be held in a NS that's an ancestor of (or
    // equal to) the target's user_ns. Init-NS callers pass through.
    if target.namespace_owner(namespace_identity::NamespaceKind::User).as_ref()
        .is_some_and(|owner| nscg::proc_ns::has_cap_for(cur, &owner.pin(), sched::cap::KILL))
    {
        return true;
    }
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let tr = target.creds.ruid.load(Ordering::Acquire);
    let ts = target.creds.suid.load(Ordering::Acquire);
    if ce == tr || ce == ts || cr == tr || cr == ts { return true; }
    // SIGCONT (18) — same session bypass.
    if sig == Signum::Sigcont as i32 && cur.sid() == target.sid() {
        return true;
    }
    false
}

/// Linux `check_prlimit_permission`: cross-task `prlimit64(2)` requires
/// the caller's real uid/gid to match the target's real/effective/saved
/// uid/gid, or `CAP_SYS_RESOURCE` in the target's user namespace.
/// # C: O(userns-depth)
pub(crate) fn prlimit_perm_check(cur: &sched::Task, target: &sched::Task) -> bool {
    use core::sync::atomic::Ordering;
    let cruid = cur.creds.ruid.load(Ordering::Acquire);
    let crgid = cur.creds.rgid.load(Ordering::Acquire);
    let tcred = &target.creds;
    let uid_ok = cruid == tcred.euid.load(Ordering::Acquire)
        && cruid == tcred.suid.load(Ordering::Acquire)
        && cruid == tcred.ruid.load(Ordering::Acquire);
    let gid_ok = crgid == tcred.egid.load(Ordering::Acquire)
        && crgid == tcred.sgid.load(Ordering::Acquire)
        && crgid == tcred.rgid.load(Ordering::Acquire);
    if uid_ok && gid_ok { return true; }
    let Some(target_ns) = target.namespace_owner(namespace_identity::NamespaceKind::User) else {
        return false;
    };
    nscg::proc_ns::has_cap_for(cur, &target_ns.pin(), sched::cap::SYS_RESOURCE)
}

/// Linux `capable(cap)`, which is `ns_capable(&init_user_ns, cap)` — the
/// capability must be held in the INITIAL user namespace, not merely in the
/// caller's effective set.
///
/// The distinction is the whole point for machine-wide operations
/// (`CAP_SYS_MODULE`, `CAP_SYS_BOOT`, `CAP_SYS_RAWIO`): root inside an
/// unprivileged user namespace holds a full effective set *in that namespace*
/// and would otherwise pass an effective-set-only test, letting any user load
/// kernel modules by first calling `unshare(CLONE_NEWUSER)`.
/// # C: O(1)
pub(crate) fn capable(cur: &sched::Task, cap: u32) -> bool {
    // A task with no published namespace set is in the initial namespace by
    // definition (the state of early boot, before the set exists) — the same
    // `is_none_or(is_initial)` reading `sched::live::in_initial_pid_namespace`
    // uses. Treating "no namespace yet" as "not initial" would deny PID 1 the
    // capability it demonstrably holds.
    cur.has_cap(cap)
        && cur.namespace_owner(namespace_identity::NamespaceKind::User)
              .is_none_or(|ns| ns.is_initial())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    fn task(tid: u32, uid: u32) -> sched::Task {
        let t = sched::Task::new(tid, "perm-test", sched::SchedClass::Normal { weight: 1024 });
        t.creds.ruid.store(uid, Ordering::Release);
        t.creds.euid.store(uid, Ordering::Release);
        t.creds.suid.store(uid, Ordering::Release);
        t.creds.rgid.store(uid, Ordering::Release);
        t.creds.egid.store(uid, Ordering::Release);
        t.creds.sgid.store(uid, Ordering::Release);
        // Simulate a real unprivileged process (post-setuid-drop): the
        // Task::new() default is CAP_FULL (root-equivalent), which would
        // make every check below a trivial no-op.
        t.creds.cap_effective.store(0, Ordering::Release);
        t
    }

    fn grant(t: &sched::Task, cap: u32) {
        t.creds.cap_effective.fetch_or(1u64 << cap, Ordering::Release);
    }

    // --- sig_perm_check ---------------------------------------------

    #[test]
    fn sig_perm_self_always_allowed() {
        let cur = task(1, 1000);
        assert!(sig_perm_check(&cur, &cur, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn sig_perm_same_uid_allowed_without_cap() {
        let cur = task(1, 1000);
        let target = task(2, 1000);
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn sig_perm_different_uid_denied_without_cap_kill() {
        let cur = task(1, 1000);
        let target = task(2, 2000);
        assert!(!sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn sig_perm_different_uid_allowed_with_cap_kill() {
        let cur = task(1, 1000);
        grant(&cur, sched::cap::KILL);
        let target = task(2, 2000);
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn sig_perm_sigcont_allowed_same_session_different_uid() {
        let cur = task(1, 1000);
        let target = task(2, 2000);
        cur.set_sid(42);
        target.set_sid(42);
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigcont as i32));
    }

    #[test]
    fn sig_perm_sigcont_denied_different_session_different_uid() {
        let cur = task(1, 1000);
        let target = task(2, 2000);
        cur.set_sid(42);
        target.set_sid(43);
        assert!(!sig_perm_check(&cur, &target, sched::Signum::Sigcont as i32));
    }

    // --- is_forged_si_code (rt_sigqueueinfo forgery guard) ----------

    #[test]
    fn si_code_forgery_rejects_kernel_and_user_origin() {
        assert!(sched::signum::is_forged_si_code(sched::signum::SI_USER));
        assert!(sched::signum::is_forged_si_code(sched::signum::SI_KERNEL));
        assert!(sched::signum::is_forged_si_code(sched::signum::SI_TKILL));
    }

    #[test]
    fn si_code_forgery_allows_queue_class_codes() {
        assert!(!sched::signum::is_forged_si_code(sched::signum::SI_QUEUE));
        assert!(!sched::signum::is_forged_si_code(-2)); // SI_TIMER
    }

    // --- prlimit_perm_check ------------------------------------------

    #[test]
    fn prlimit_perm_same_uid_allowed_without_cap() {
        let cur = task(1, 1000);
        let target = task(2, 1000);
        assert!(prlimit_perm_check(&cur, &target));
    }

    #[test]
    fn prlimit_perm_different_uid_denied_without_cap_sys_resource() {
        let cur = task(1, 1000);
        let target = task(2, 2000);
        assert!(!prlimit_perm_check(&cur, &target));
    }

    #[test]
    fn prlimit_perm_different_uid_allowed_with_cap_sys_resource() {
        let cur = task(1, 1000);
        grant(&cur, sched::cap::SYS_RESOURCE);
        let target = task(2, 2000);
        assert!(prlimit_perm_check(&cur, &target));
    }

}

#[cfg(test)]
mod landlock_signal_scope_tests {
    use super::sig_perm_check;
    use ::landlock::abi::RulesetAttr;
    use ::landlock::uapi::{SCOPE_SIGNAL, ACCESS_FS_READ_FILE};
    use ::landlock::{Domain, Ruleset};
    use core::sync::atomic::Ordering;

    fn task(tid: u32, uid: u32) -> sched::Task {
        let t = sched::Task::new(tid, "ll-scope", sched::SchedClass::Normal { weight: 1024 });
        for f in [&t.creds.ruid, &t.creds.euid, &t.creds.suid] { f.store(uid, Ordering::Release); }
        t
    }

    fn scoped_domain(parent: Option<&alloc::sync::Arc<Domain>>) -> alloc::sync::Arc<Domain> {
        let rs = Ruleset::new(&RulesetAttr { scoped: SCOPE_SIGNAL, ..Default::default() });
        Domain::merge(parent, &rs).unwrap()
    }

    #[test]
    fn a_signal_scope_denies_an_unconfined_target_even_with_full_capabilities() {
        // The task default is root-equivalent, so this also proves the scope
        // outranks the capability path rather than being shadowed by it.
        let cur = task(1, 0);
        let target = task(2, 0);
        *cur.landlock_domain.lock() = Some(scoped_domain(None));
        assert!(!sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn a_signal_scope_still_allows_a_target_inside_the_same_domain() {
        let cur = task(1, 0);
        let target = task(2, 0);
        let dom = scoped_domain(None);
        *cur.landlock_domain.lock() = Some(dom.clone());
        *target.landlock_domain.lock() = Some(dom);
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn a_signal_scope_reaches_a_target_that_sandboxed_itself_further() {
        let cur = task(1, 0);
        let target = task(2, 0);
        let outer = scoped_domain(None);
        let inner = scoped_domain(Some(&outer));
        *cur.landlock_domain.lock() = Some(outer);
        *target.landlock_domain.lock() = Some(inner.clone());
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
        // And the nested one cannot signal back out.
        *cur.landlock_domain.lock() = Some(inner);
        *target.landlock_domain.lock() = Some(scoped_domain(None));
        assert!(!sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn a_domain_that_scopes_nothing_does_not_affect_signalling() {
        // A filesystem-only policy must not accidentally isolate the process.
        let cur = task(1, 0);
        let target = task(2, 0);
        let rs = Ruleset::new(&RulesetAttr {
            handled_fs: ACCESS_FS_READ_FILE, ..Default::default() });
        *cur.landlock_domain.lock() = Some(Domain::merge(None, &rs).unwrap());
        assert!(sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }

    #[test]
    fn a_scoped_thread_cannot_reach_a_sibling_outside_its_domain() {
        // The sibling-thread shortcut must not bypass the scope.
        let cur = task(1, 0);
        let target = task(2, 0);
        cur.tgid.store(1, Ordering::Release);
        target.tgid.store(1, Ordering::Release);
        *cur.landlock_domain.lock() = Some(scoped_domain(None));
        assert!(!sig_perm_check(&cur, &target, sched::Signum::Sigterm as i32));
    }
}
