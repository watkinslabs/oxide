// unshare(2) gate tests — Linux `check_unshare_flags` +
// `unshare_nsproxy_namespaces` + `copy_cgroup_ns`, driven through the real
// `sys_unshare` over the parent harness's mocked task context.
// Child of `namespace_ownership_hosted.rs` (`08§7` file cap): the harness
// preamble (`extern crate self as sched`, the hostname/net_ns mocks, the
// serialized current-task hook) lives there and reaches here via `super`.

use super::*;

/// Linux `unshare_nsproxy_namespaces`: `ns_capable(user_ns, CAP_SYS_ADMIN)`
/// guards the whole namespace set. Without it, `unshare(CLONE_NEWNS)` from an
/// unprivileged unit would silently hand the caller a fresh mount namespace.
#[test]
fn sys_unshare_namespace_flags_require_cap_sys_admin() {
    let _guard = guard();
    let current = install_current(915);
    let before = current.namespace_snapshot().unwrap();
    current.creds.cap_effective.store(0, Ordering::Release);

    for flag in [CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID,
        CLONE_NEWCGROUP, CLONE_NEWTIME]
    {
        assert_eq!(s272_unshare::sys_unshare(&args(flag)),
            -(Errno::Eperm.as_i32() as i64), "namespace flag must be capability-gated");
    }
    assert_same_set(&before, &current.namespace_snapshot().unwrap());
}

/// `CLONE_NEWUSER` alone is exempt from the CAP_SYS_ADMIN test — creating a
/// user namespace is unprivileged in Linux.
#[test]
fn sys_unshare_newuser_alone_needs_no_cap_sys_admin() {
    let _guard = guard();
    let current = install_current(916);
    let before = current.namespace_snapshot().unwrap();
    current.creds.cap_effective.store(0, Ordering::Release);

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWUSER)), 0);
    assert!(!NamespaceRef::ptr_eq(&before.user,
        &current.namespace_snapshot().unwrap().user));
}

/// The rootless-container primitive: an unprivileged task pairing
/// `CLONE_NEWUSER` with another namespace flag is granted CAP_SYS_ADMIN by
/// having CREATED the user namespace that will own the rest of the set.
///
/// This fails closed when the capability test is run against the caller's OWN
/// user namespace instead of the one about to be created — the whole point is
/// that the caller holds nothing where it is now.
#[test]
fn rootless_unshare_of_a_user_namespace_carries_the_rest_of_the_set() {
    let _guard = guard();
    let current = install_current(918);
    let before = current.namespace_snapshot().unwrap();
    current.creds.cap_effective.store(0, Ordering::Release);
    current.creds.euid.store(1000, Ordering::Release);

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWUSER | CLONE_NEWNS)), 0,
        "the creator of the new user namespace is privileged inside it");
    let after = current.namespace_snapshot().unwrap();
    assert!(!NamespaceRef::ptr_eq(&before.user, &after.user));
    assert!(!alloc::sync::Arc::ptr_eq(&before.mount, &after.mount),
        "the mount namespace the capability gated must actually be new");

    // Linux `set_cred_user_ns`: init's capabilities, scoped to the new
    // namespace. Without them the very next in-namespace operation is EPERM.
    assert_eq!(current.creds.cap_effective.load(Ordering::Acquire),
        sched::task::Creds::CAP_FULL);
    assert_eq!(current.creds.cap_bounding.load(Ordering::Acquire),
        sched::task::Creds::CAP_FULL);
    assert_eq!(current.creds.cap_inheritable.load(Ordering::Acquire), 0);
    assert_eq!(current.creds.cap_ambient.load(Ordering::Acquire), 0,
        "an ambient set carried in from outside would survive an execve");
}

/// The grant is not "CLONE_NEWUSER disables the gate": it comes from OWNING
/// the new namespace, so a namespace flag WITHOUT CLONE_NEWUSER is still
/// refused, and the caller keeps the capabilities it had.
#[test]
fn a_namespace_flag_without_newuser_is_still_refused() {
    let _guard = guard();
    let current = install_current(919);
    let before = current.namespace_snapshot().unwrap();
    current.creds.cap_effective.store(0, Ordering::Release);
    current.creds.euid.store(1000, Ordering::Release);

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWNS)),
        -(Errno::Eperm.as_i32() as i64));
    assert_same_set(&before, &current.namespace_snapshot().unwrap());
    assert_eq!(current.creds.cap_effective.load(Ordering::Acquire), 0,
        "a refused unshare grants nothing");
}

/// The unprivileged resource unshares are not namespace operations and carry
/// no capability requirement.
#[test]
fn sys_unshare_files_and_fs_need_no_capability() {
    let _guard = guard();
    let current = install_current(917);
    current.creds.cap_effective.store(0, Ordering::Release);

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_FILES)), 0);
    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_FS)), 0);
    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_SYSVSEM)), 0);
}

/// Linux `check_unshare_flags`: `CLONE_THREAD`/`CLONE_SIGHAND`/`CLONE_VM` are
/// no-ops for a single-threaded caller, and `CLONE_NEWUSER` inherits that rule
/// through its `CLONE_THREAD` implication.
#[test]
fn sys_unshare_thread_flags_are_noops_when_single_threaded() {
    let _guard = guard();
    install_current(918);

    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_THREAD)), 0);
    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_VM)), 0);
}

/// Unknown bits are EINVAL and mutate nothing.
#[test]
fn sys_unshare_rejects_unknown_flag_bits() {
    let _guard = guard();
    let current = install_current(919);
    let before = current.namespace_snapshot().unwrap();

    assert_eq!(s272_unshare::sys_unshare(&args(1 << 63)),
        -(Errno::Einval.as_i32() as i64));
    assert_same_set(&before, &current.namespace_snapshot().unwrap());
}

/// "CLONE_SYSVSEM is equivalent to sys_exit()" — and `CLONE_NEWIPC` triggers
/// the same detach, because the arrays the undo entries name are unreachable
/// from the new IPC namespace.
#[test]
fn sys_unshare_detaches_the_sysvsem_undo_list() {
    use ipc::sysv::sem::undo::{find_alloc, get_undo_list, has_entry};
    const SEMID: i32 = 0x2720;
    const NSEMS: usize = 4;
    let _guard = guard();
    let current = install_current(920);
    current.tgid.store(920, Ordering::Release);
    let ns = owner(current, NamespaceKind::Ipc).id();
    // The list is reached through the TASK's handle, so each re-registration
    // below allocates a fresh one — which is itself the detach being asserted.
    let register = || {
        let id = get_undo_list(&current.sysvsem_undo).unwrap();
        find_alloc(id, ns, SEMID, NSEMS).unwrap();
        id
    };

    let id = register();
    assert!(has_entry(id, ns, SEMID));
    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_SYSVSEM)), 0);
    assert!(!has_entry(id, ns, SEMID), "CLONE_SYSVSEM is equivalent to sys_exit()");
    assert_eq!(current.sysvsem_undo.load(Ordering::Acquire), 0,
        "the caller is left holding no list at all, not an emptied one");

    // A flag set that touches neither SYSVSEM nor NEWIPC leaves it alone.
    let id = register();
    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWUTS)), 0);
    assert!(has_entry(id, ns, SEMID));

    // CLONE_NEWIPC detaches too: the arrays the entries name are unreachable
    // from the new namespace.
    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWIPC)), 0);
    assert!(!has_entry(id, ns, SEMID));
}

/// Linux `copy_cgroup_ns` pins the creating task's `css_set`, so the cgroup it
/// currently sits in becomes the new namespace's `/` and every later
/// `/proc/<pid>/cgroup` read from inside renders relative to it.
#[test]
fn sys_unshare_cgroup_pins_the_creators_cgroup_as_the_namespace_root() {
    let _guard = guard();
    let current = install_current(921);
    let before = owner(current, NamespaceKind::Cgroup);
    assert_eq!(nscg::cgroup_ns::root_of(&before), nscg::cgroup_ns::INIT_ROOT);

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWCGROUP)), 0);

    let after = owner(current, NamespaceKind::Cgroup);
    assert!(!NamespaceRef::ptr_eq(&before, &after), "a real new identity");
    // Unmounted hierarchy in the hosted harness: the creator's cgroup is `/`,
    // which is what the namespace pins — the seeding path ran.
    assert_eq!(nscg::cgroup_ns::root_of(&after),
        cgroup::cgroup_path_of(921));
}
