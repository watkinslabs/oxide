// `setns(2)` install-time permission ladder — the per-namespace
// `ns_common_ops->install()` callbacks Linux runs from `validate_ns`
// (`kernel/nsproxy.c`).
//
// Sources: `kernel/utsname.c:utsns_install`, `ipc/namespace.c:ipcns_install`,
// `net/core/net_namespace.c:netns_install`, `fs/namespace.c:mntns_install`,
// `kernel/cgroup/namespace.c:cgroupns_install`,
// `kernel/pid_namespace.c:pidns_install`,
// `kernel/user_namespace.c:userns_install`.
//
// Every one of those callbacks is a capability gate. Without them any
// unprivileged process holding an `/proc/<pid>/ns/*` fd walks into the
// namespace — which is the whole container boundary.

use namespace_identity::{NamespaceKind, NamespacePin};
use syscall::errno::Errno;

use crate::owner::NsOwner;
use super::{NsKind, has_cap_for, user_ns_is_ancestor};

/// The user namespace that owned creation of `owner` — the namespace Linux
/// passes to `ns_capable(ns->user_ns, CAP_SYS_ADMIN)`. # C: O(1)
pub fn owner_user_ns(owner: &NsOwner) -> NamespacePin {
    match owner {
        NsOwner::Cgroup(v) | NsOwner::Ipc(v) | NsOwner::Pid(v)
        | NsOwner::Time(v) | NsOwner::User(v) | NsOwner::Uts(v) => v.owner_user_namespace(),
        NsOwner::Mnt(v) => v.owner_user_namespace(),
        NsOwner::Net(v) => v.owner_user_namespace(),
    }
}

/// The shared `!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
/// !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN)` gate that opens
/// `utsns_install`, `ipcns_install`, `netns_install`, `cgroupns_install`
/// and `pidns_install`. # C: O(depth)
fn sys_admin_both(cur: &sched::Task, own_user_ns: &NamespacePin,
                  target_user_ns: &NamespacePin) -> Result<(), Errno>
{
    if !has_cap_for(cur, target_user_ns, sched::cap::SYS_ADMIN)
        || !has_cap_for(cur, own_user_ns, sched::cap::SYS_ADMIN)
    { return Err(Errno::Eperm); }
    Ok(())
}

/// Full install ladder for one namespace fd, minus the state swap itself.
///
/// Ordering is Linux's, per callback: capabilities first, then the
/// namespace-specific structural rules (pid-namespace descendancy, user
/// namespace re-entry / single-thread). `setns_apply` runs this before it
/// touches any task slot, so a rejected call leaves the caller untouched.
/// # C: O(depth)
pub fn check_install(kind: NsKind, owner: &NsOwner, cur: &sched::Task) -> Result<(), Errno> {
    let target_user_ns = owner_user_ns(owner);
    // A caller whose namespace set is already released is exiting; every
    // install path needs `current_user_ns()` and there is none. `setns_apply`
    // reports the same ESRCH for a released destination slot.
    let Some(own_user) = cur.namespace_owner(NamespaceKind::User) else {
        return Err(Errno::Esrch);
    };
    let own_user = own_user.pin();
    match kind {
        // `userns_install` has its own shape: no "both namespaces" gate, but
        // re-entry and thread rules that stop a thread gaining capabilities
        // by stepping back into the namespace it already occupies.
        NsKind::User => {
            let NsOwner::User(target) = owner else { return Err(Errno::Einval) };
            if NamespacePin::ptr_eq(&own_user, &target.pin()) { return Err(Errno::Einval); }
            // "Tasks that share a thread group must share a user namespace."
            if !cur.thread_group.is_single_member() { return Err(Errno::Einval); }
            if !has_cap_for(cur, &target.pin(), sched::cap::SYS_ADMIN) {
                return Err(Errno::Eperm);
            }
            Ok(())
        }
        // `pidns_install`: entering the ACTIVE pid namespace or one of its
        // descendants only, so a process can never escape upward.
        NsKind::Pid | NsKind::PidForChildren => {
            sys_admin_both(cur, &own_user, &target_user_ns)?;
            let NsOwner::Pid(target) = owner else { return Err(Errno::Einval) };
            let Some(active) = cur.namespace_owner(NamespaceKind::Pid) else {
                return Err(Errno::Esrch);
            };
            if !user_ns_is_ancestor(&active.pin(), &target.pin()) { return Err(Errno::Einval); }
            Ok(())
        }
        // `mntns_install` additionally demands CAP_SYS_CHROOT in the caller's
        // user namespace: entering a mount namespace re-roots the task.
        NsKind::Mnt => {
            sys_admin_both(cur, &own_user, &target_user_ns)?;
            if !has_cap_for(cur, &own_user, sched::cap::SYS_CHROOT) { return Err(Errno::Eperm); }
            Ok(())
        }
        NsKind::Uts | NsKind::Ipc | NsKind::Net | NsKind::Cgroup => {
            sys_admin_both(cur, &own_user, &target_user_ns)
        }
        // `timens_install` is the one callback that also refuses a
        // multi-threaded caller (EUSERS); `setns_apply` owns that ladder
        // because it must also freeze the offsets.
        NsKind::Time | NsKind::TimeForChildren => Ok(()),
    }
}
