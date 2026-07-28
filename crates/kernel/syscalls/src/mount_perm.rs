// mount_perm — the ONE `may_mount()` gate for the whole mount(2) family
// (docs/53 §0). Linux `fs/namespace.c`:
//
//     bool may_mount(void)
//     {
//         return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
//     }
//
// NOT a flat effective-capability test. The capability must be held IN the user
// namespace that owns the mount namespace being modified. The difference is the
// whole point of the check: a task that entered an unprivileged user namespace
// carries a full effective capability set inside it, so `has_cap(SYS_ADMIN)`
// alone says "yes" to a caller that has no authority over the mount namespace it
// is pointing at. `nscg::proc_ns::has_cap_for` adds the ancestry test Linux's
// `ns_capable` performs.
//
// Callers: path_mount (165), umount2 (166), open_tree (428), move_mount (429),
// fsopen (430), fsmount (432), fspick (433), mount_setattr (442), pivot_root
// (155). Linux gates every one of them on this same predicate.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Linux `may_mount()`. # C: O(userns depth)
pub(crate) fn may_mount() -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    match cur.mount_namespace_snapshot() {
        Some(mnt_ns) => nscg::proc_ns::has_cap_for(
            &cur, &mnt_ns.owner_user_namespace(), sched::cap::SYS_ADMIN),
        None => false,
    }
}

/// [`may_mount`] as an early-return guard: `Some(-EPERM)` when refused, `None`
/// when the caller may proceed. # C: O(userns depth)
pub(crate) fn may_mount_or_eperm() -> Option<i64> {
    if may_mount() { None } else { Some(-(Errno::Eperm.as_i32() as i64)) }
}

/// Linux `capable(CAP_SYS_ADMIN)` — `ns_capable(&init_user_ns, CAP_SYS_ADMIN)`.
/// `has_cap_for` requires the target user namespace to be the caller's own or a
/// DESCENDANT of it, so a task inside a child user namespace fails this even
/// though it holds a full capability set there — exactly what `capable()` means.
/// # C: O(userns depth)
fn cap_sys_admin_in_init_user_ns() -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    let init = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    nscg::proc_ns::has_cap_for(&cur, &init.pin(), sched::cap::SYS_ADMIN)
}

/// The two capability facts Linux `mount_capable` chooses between, sampled once
/// per `mount(2)` so the decision itself stays a pure, hosted-testable function
/// (`fsmount_common::mount_dispatch::mount_capable`). # C: O(userns depth)
pub(crate) fn sample_mount_caps() -> crate::fsmount_common::MountCaps {
    crate::fsmount_common::MountCaps {
        init_user_ns: cap_sys_admin_in_init_user_ns(),
        mnt_user_ns: may_mount(),
    }
}
