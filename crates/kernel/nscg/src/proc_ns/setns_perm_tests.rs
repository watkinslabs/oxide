// Hosted coverage for the `setns(2)` install-time permission ladder.
// Before F755 every non-time namespace installed with NO capability check at
// all, so an unprivileged holder of an `/proc/<pid>/ns/*` fd walked straight
// into the namespace. These tests pin each `*_install` gate.

use super::*;
use namespace_identity::NamespaceRef;

fn task(tid: u32, name: &'static str) -> sched::Task {
    sched::Task::new(tid, name, sched::SchedClass::Normal { weight: 1024 })
}

fn drop_all_caps(t: &sched::Task) {
    t.creds.cap_effective.store(0, core::sync::atomic::Ordering::Release);
}

fn eperm() -> i64 { -(syscall::errno::Errno::Eperm.as_i32() as i64) }
fn einval() -> i64 { -(syscall::errno::Errno::Einval.as_i32() as i64) }

fn initial_user() -> NamespaceRef { namespace_identity::initial(NamespaceKind::User) }

fn alloc_under(kind: NamespaceKind, user: NamespaceRef) -> NamespaceRef {
    namespace_identity::allocate(kind, user, None).unwrap()
}

#[test]
fn uts_setns_requires_sys_admin() {
    let uts = alloc_under(NamespaceKind::Uts, initial_user());
    let ns = NsInode::new(NsKind::Uts, NsOwner::Uts(uts.clone()));
    let privileged = task(600, "uts-cap");
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &privileged), 0);
    assert!(NamespaceRef::ptr_eq(
        &privileged.namespace_owner(NamespaceKind::Uts).unwrap(), &uts));

    let unprivileged = task(601, "uts-nocap");
    let before = unprivileged.namespace_owner(NamespaceKind::Uts).unwrap();
    drop_all_caps(&unprivileged);
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &unprivileged), eperm());
    assert!(NamespaceRef::ptr_eq(
        &unprivileged.namespace_owner(NamespaceKind::Uts).unwrap(), &before),
        "a rejected setns must leave the caller's namespace untouched");
}

#[test]
fn ipc_net_cgroup_setns_all_require_sys_admin() {
    let ipc = alloc_under(NamespaceKind::Ipc, initial_user());
    let cgroup = alloc_under(NamespaceKind::Cgroup, initial_user());
    let net = network_namespace::allocate(initial_user()).unwrap();
    let t = task(602, "multi-nocap");
    drop_all_caps(&t);
    assert_eq!(setns_apply(&NsInode::new(NsKind::Ipc, NsOwner::Ipc(ipc)),
                           CLONE_NEWIPC, &t), eperm());
    assert_eq!(setns_apply(&NsInode::new(NsKind::Cgroup, NsOwner::Cgroup(cgroup)),
                           CLONE_NEWCGROUP, &t), eperm());
    assert_eq!(setns_apply(&NsInode::new(NsKind::Net, NsOwner::Net(net)),
                           CLONE_NEWNET, &t), eperm());
}

#[test]
fn pid_setns_rejects_a_namespace_outside_the_active_subtree() {
    let t = task(603, "pid-escape");
    let active = t.namespace_owner(NamespaceKind::Pid).unwrap();
    // Sibling of the active namespace, not a descendant of it.
    let sibling = alloc_under(NamespaceKind::Pid, initial_user());
    let ns = NsInode::new(NsKind::Pid, NsOwner::Pid(sibling));
    assert_eq!(setns_apply(&ns, CLONE_NEWPID, &t), einval());

    let child = namespace_identity::allocate(NamespaceKind::Pid, initial_user(),
        Some(active.clone())).unwrap();
    let ns = NsInode::new(NsKind::Pid, NsOwner::Pid(child.clone()));
    assert_eq!(setns_apply(&ns, CLONE_NEWPID, &t), 0);
    assert!(NamespaceRef::ptr_eq(&t.pid_namespace_for_children().unwrap(), &child));
}

#[test]
fn pid_setns_checks_capabilities_before_descendancy() {
    let t = task(604, "pid-nocap");
    drop_all_caps(&t);
    let sibling = alloc_under(NamespaceKind::Pid, initial_user());
    let ns = NsInode::new(NsKind::Pid, NsOwner::Pid(sibling));
    // Linux `pidns_install` runs `ns_capable` first, so EPERM outranks the
    // EINVAL the descendancy rule would otherwise produce.
    assert_eq!(setns_apply(&ns, CLONE_NEWPID, &t), eperm());
}

#[test]
fn user_setns_refuses_reentering_the_same_namespace() {
    let t = task(605, "user-same");
    let own = t.namespace_owner(NamespaceKind::User).unwrap();
    let ns = NsInode::new(NsKind::User, NsOwner::User(own));
    assert_eq!(setns_apply(&ns, CLONE_NEWUSER, &t), einval());
}

#[test]
fn user_setns_refuses_a_multi_threaded_caller() {
    let leader = task(606, "user-mt");
    let child = namespace_identity::allocate(NamespaceKind::User, initial_user(),
        Some(initial_user())).unwrap();
    let ns = NsInode::new(NsKind::User, NsOwner::User(child));
    let mut sibling = task(607, "user-mt-sibling");
    sibling.join_thread_group(Arc::clone(&leader.thread_group));
    sibling.thread_group.commit_member();
    assert_eq!(setns_apply(&ns, CLONE_NEWUSER, &leader), einval());
}

#[test]
fn user_setns_requires_sys_admin_in_the_target_namespace() {
    let t = task(608, "user-nocap");
    let child = namespace_identity::allocate(NamespaceKind::User, initial_user(),
        Some(initial_user())).unwrap();
    let ns = NsInode::new(NsKind::User, NsOwner::User(child.clone()));
    drop_all_caps(&t);
    assert_eq!(setns_apply(&ns, CLONE_NEWUSER, &t), eperm());

    let privileged = task(609, "user-cap");
    assert_eq!(setns_apply(&ns, CLONE_NEWUSER, &privileged), 0);
    assert!(NamespaceRef::ptr_eq(
        &privileged.namespace_owner(NamespaceKind::User).unwrap(), &child));
}

#[test]
fn mnt_setns_requires_sys_chroot_on_top_of_sys_admin() {
    let mntns = vfs::mntns::allocate(initial_user()).unwrap();
    let ns = NsInode::new(NsKind::Mnt, NsOwner::Mnt(mntns));
    let t = task(610, "mnt-partial");
    // CAP_SYS_ADMIN alone is not enough: entering a mount namespace re-roots
    // the task, so Linux also demands CAP_SYS_CHROOT.
    let admin_only = 1u64 << sched::cap::SYS_ADMIN;
    t.creds.cap_effective.store(admin_only, core::sync::atomic::Ordering::Release);
    assert_eq!(setns_apply(&ns, CLONE_NEWNS, &t), eperm());

    // With CAP_SYS_CHROOT the permission ladder passes. The call still fails
    // EINVAL because this fixture's namespace has no root mount recorded, and
    // `mntns_install` refuses a namespace whose root it cannot resolve (Linux
    // rejects the analogous anonymous namespace outright, and its
    // `vfs_path_lookup` error arm reverts the swap). What matters here is that
    // it is no longer EPERM.
    let privileged = task(611, "mnt-cap");
    assert_ne!(setns_apply(&ns, CLONE_NEWNS, &privileged), eperm());
}

#[test]
fn capability_check_uses_the_target_namespace_not_just_the_callers() {
    // A namespace owned by a user namespace the caller does not contain must
    // be refused even when the caller is fully capable in its own.
    let foreign_user = namespace_identity::allocate(NamespaceKind::User,
        initial_user(), Some(initial_user())).unwrap();
    let uts = alloc_under(NamespaceKind::Uts, foreign_user.clone());
    let ns = NsInode::new(NsKind::Uts, NsOwner::Uts(uts));
    let t = task(612, "uts-descendant-ok");
    // The caller sits in the INITIAL user namespace, an ancestor of
    // `foreign_user`, so `ns_capable(ns->user_ns, ...)` holds.
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &t), 0);

    // Now put the caller INSIDE `foreign_user` and target a namespace owned by
    // a sibling branch: no ancestry, so no capability.
    let sibling_user = namespace_identity::allocate(NamespaceKind::User,
        initial_user(), Some(initial_user())).unwrap();
    let other = alloc_under(NamespaceKind::Uts, sibling_user);
    let ns = NsInode::new(NsKind::Uts, NsOwner::Uts(other));
    let inner = task(613, "uts-sibling-branch");
    assert!(inner.replace_namespace(foreign_user).is_ok());
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &inner), eperm());
}
