use syscall::errno::Errno;
use syscalls::unshare_policy::*;

#[test]
fn newuser_implies_thread_and_fs() {
    let f = expand_implied(CLONE_NEWUSER);
    assert_ne!(f & CLONE_THREAD, 0);
    assert_ne!(f & CLONE_FS, 0);
}

#[test]
fn newns_implies_fs_and_empty_mntns_implies_newns() {
    assert_ne!(expand_implied(CLONE_NEWNS) & CLONE_FS, 0);
    let f = expand_implied(UNSHARE_EMPTY_MNTNS);
    assert_ne!(f & CLONE_NEWNS, 0);
    assert_ne!(f & CLONE_FS, 0);
}

#[test]
fn vm_implies_sighand_implies_thread() {
    let f = expand_implied(CLONE_VM);
    assert_ne!(f & CLONE_SIGHAND, 0);
    assert_ne!(f & CLONE_THREAD, 0);
}

#[test]
fn unknown_bits_are_einval() {
    assert_eq!(check_unshare_flags(1 << 63, true, false), Err(Errno::Einval));
    // CLONE_PIDFD / CLONE_PTRACE and friends are not unshareable.
    assert_eq!(check_unshare_flags(0x0000_1000, true, false), Err(Errno::Einval));
}

#[test]
fn thread_sighand_vm_are_noops_when_single_threaded() {
    assert_eq!(check_unshare_flags(CLONE_THREAD, true, false), Ok(()));
    assert_eq!(check_unshare_flags(CLONE_SIGHAND | CLONE_THREAD, true, false), Ok(()));
    assert_eq!(check_unshare_flags(expand_implied(CLONE_VM), true, false), Ok(()));
}

#[test]
fn thread_sighand_vm_are_einval_when_multi_threaded() {
    assert_eq!(check_unshare_flags(CLONE_THREAD, false, false), Err(Errno::Einval));
    assert_eq!(check_unshare_flags(CLONE_SIGHAND, false, false), Err(Errno::Einval));
    assert_eq!(check_unshare_flags(CLONE_VM, false, false), Err(Errno::Einval));
    // ...and so is CLONE_NEWUSER, through the CLONE_THREAD implication.
    assert_eq!(
        check_unshare_flags(expand_implied(CLONE_NEWUSER), false, false),
        Err(Errno::Einval),
    );
}

#[test]
fn sighand_or_vm_with_a_shared_sighand_is_einval() {
    assert_eq!(
        check_unshare_flags(CLONE_SIGHAND | CLONE_THREAD, true, true),
        Err(Errno::Einval),
    );
    assert_eq!(
        check_unshare_flags(expand_implied(CLONE_VM), true, true),
        Err(Errno::Einval),
    );
    // A shared sighand does NOT block the plain namespace flags.
    assert_eq!(check_unshare_flags(CLONE_NEWNET, true, true), Ok(()));
}

#[test]
fn plain_resource_flags_are_accepted_multi_threaded() {
    assert_eq!(check_unshare_flags(CLONE_FILES, false, true), Ok(()));
    assert_eq!(check_unshare_flags(CLONE_FS, false, true), Ok(()));
    assert_eq!(check_unshare_flags(CLONE_SYSVSEM, false, true), Ok(()));
    assert_eq!(check_unshare_flags(CLONE_NEWNET | CLONE_NEWUTS, false, true), Ok(()));
}

#[test]
fn sys_admin_is_needed_for_every_namespace_except_user_alone() {
    assert!(!needs_sys_admin(CLONE_NEWUSER));
    assert!(!needs_sys_admin(expand_implied(CLONE_NEWUSER)));
    assert!(!needs_sys_admin(CLONE_FILES | CLONE_FS | CLONE_SYSVSEM));
    for flag in [
        CLONE_NEWNS,
        CLONE_NEWUTS,
        CLONE_NEWIPC,
        CLONE_NEWPID,
        CLONE_NEWNET,
        CLONE_NEWCGROUP,
        CLONE_NEWTIME,
    ] {
        assert!(needs_sys_admin(flag), "namespace flag must be capability-gated");
        assert!(needs_sys_admin(flag | CLONE_NEWUSER));
    }
}

#[test]
fn sysvsem_detach_covers_both_triggers() {
    assert!(detaches_sysvsem(CLONE_SYSVSEM));
    assert!(detaches_sysvsem(CLONE_NEWIPC));
    assert!(!detaches_sysvsem(CLONE_NEWNET | CLONE_FILES));
}

#[test]
fn clone_ns_all_covers_the_eight_namespace_kinds() {
    assert_eq!(CLONE_NS_ALL.count_ones(), 8);
    assert_eq!(CLONE_NS_ALL & UNSHARE_ALLOWED, CLONE_NS_ALL);
}
