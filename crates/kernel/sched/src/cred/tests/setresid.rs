// Linux `__sys_setresuid` / `__sys_setresgid` (`kernel/sys.c`).

use core::sync::atomic::Ordering;

use super::fixtures::{err, gids, privileged, set_gids, set_uids, uids, unprivileged};
use crate::cred::gid::setresgid_on;
use crate::cred::limits::ID_UNCHANGED;
use crate::cred::uid::setresuid_on;
use syscall::errno::Errno;

const KEEP: u32 = ID_UNCHANGED;

#[test]
fn setresuid_applies_all_three_ids_for_a_cap_holder() {
    let task = privileged();
    assert_eq!(setresuid_on(&task, 1000, 2000, 3000), 0);
    assert_eq!(uids(&task), (1000, 2000, 3000, 2000), "fsuid follows the new euid");
}

#[test]
fn setresuid_minus_one_leaves_each_id_unchanged() {
    let task = privileged();
    set_uids(&task, (10, 20, 30));
    assert_eq!(setresuid_on(&task, KEEP, KEEP, 40), 0);
    assert_eq!(uids(&task), (10, 20, 40, 20));
}

#[test]
fn setresuid_resets_the_fs_uid_to_the_effective_uid_even_when_euid_is_unchanged() {
    // Linux assigns `new->fsuid = new->euid` unconditionally, so a prior
    // setfsuid() is undone by ANY successful setresuid().
    let task = privileged();
    set_uids(&task, (10, 20, 30));
    task.creds.fsuid.store(99, Ordering::Release);
    assert_eq!(setresuid_on(&task, 11, KEEP, KEEP), 0);
    assert_eq!(uids(&task), (11, 20, 30, 20));
}

#[test]
fn setresuid_no_op_call_returns_success_without_touching_anything() {
    let task = unprivileged((10, 20, 30), (0, 0, 0));
    // set_uids already made fsuid == euid, so this is Linux's no-op case.
    assert_eq!(setresuid_on(&task, 10, 20, 30), 0);
    assert_eq!(uids(&task), (10, 20, 30, 20));
}

#[test]
fn setresuid_permits_any_permutation_of_the_existing_triple_without_a_cap() {
    let task = unprivileged((10, 20, 30), (0, 0, 0));
    assert_eq!(setresuid_on(&task, 30, 10, 20), 0);
    assert_eq!(uids(&task), (30, 10, 20, 10));
}

#[test]
fn setresuid_rejects_a_new_id_in_any_position_without_cap_setuid() {
    for args in [(99u32, KEEP, KEEP), (KEEP, 99, KEEP), (KEEP, KEEP, 99)] {
        let task = unprivileged((10, 20, 30), (0, 0, 0));
        assert_eq!(setresuid_on(&task, args.0, args.1, args.2), err(Errno::Eperm));
        assert_eq!(uids(&task), (10, 20, 30, 20), "rejected call must not apply the other ids");
    }
}

#[test]
fn setresuid_checks_every_argument_before_applying_any_of_them() {
    // The third argument is the only illegal one; Linux still applies none.
    let task = unprivileged((10, 20, 30), (0, 0, 0));
    assert_eq!(setresuid_on(&task, 30, 10, 99), err(Errno::Eperm));
    assert_eq!(uids(&task), (10, 20, 30, 20));
}

#[test]
fn setresgid_mirrors_the_uid_rules_over_the_gid_triple() {
    let task = unprivileged((0, 0, 0), (10, 20, 30));
    assert_eq!(setresgid_on(&task, 30, 10, 20), 0);
    assert_eq!(gids(&task), (30, 10, 20, 10));
    assert_eq!(setresgid_on(&task, ID_UNCHANGED, 99, ID_UNCHANGED), err(Errno::Eperm));
}

#[test]
fn setresgid_resets_the_fs_gid_to_the_effective_gid() {
    let task = privileged();
    set_gids(&task, (10, 20, 30));
    task.creds.fsgid.store(77, Ordering::Release);
    assert_eq!(setresgid_on(&task, 11, ID_UNCHANGED, ID_UNCHANGED), 0);
    assert_eq!(gids(&task), (11, 20, 30, 20));
}

#[test]
fn setresgid_no_op_call_succeeds() {
    let task = unprivileged((0, 0, 0), (10, 20, 30));
    assert_eq!(setresgid_on(&task, 10, 20, 30), 0);
    assert_eq!(gids(&task), (10, 20, 30, 20));
}
