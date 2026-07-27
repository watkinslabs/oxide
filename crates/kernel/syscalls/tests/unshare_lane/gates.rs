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
    use ipc::sysv::sem::undo::{find_alloc, has_entry};
    const SEMID: i32 = 0x2720;
    const NSEMS: usize = 4;
    let _guard = guard();
    let current = install_current(920);
    current.tgid.store(920, Ordering::Release);
    let ns = owner(current, NamespaceKind::Ipc).id();

    find_alloc(920, ns, SEMID, NSEMS).unwrap();
    assert!(has_entry(920, ns, SEMID));
    assert_eq!(s272_unshare::sys_unshare(&args(unshare_policy::CLONE_SYSVSEM)), 0);
    assert!(!has_entry(920, ns, SEMID), "CLONE_SYSVSEM is equivalent to sys_exit()");

    // A flag set that touches neither SYSVSEM nor NEWIPC leaves it alone.
    find_alloc(920, ns, SEMID, NSEMS).unwrap();
    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWUTS)), 0);
    assert!(has_entry(920, ns, SEMID));

    // CLONE_NEWIPC detaches too: the arrays the entries name are unreachable
    // from the new namespace.
    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWIPC)), 0);
    assert!(!has_entry(920, ns, SEMID));
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
