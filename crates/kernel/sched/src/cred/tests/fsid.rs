// Linux `__sys_setfsuid` / `__sys_setfsgid` (`kernel/sys.c`): they return the
// PREVIOUS id on every path and can never report an error.

use core::sync::atomic::Ordering;

use super::fixtures::{gids, grant_caps, privileged, set_gids, set_uids, uids, unprivileged};
use crate::cred::fsid::{setfsgid_on, setfsuid_on};
use crate::cred::limits::ID_UNCHANGED;
use crate::Creds;

#[test]
fn setfsuid_returns_the_previous_fsuid_and_applies_the_change() {
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    assert_eq!(setfsuid_on(&task, 1000), 0, "returns the OLD fsuid, not the new one");
    assert_eq!(uids(&task), (0, 0, 0, 1000));
    assert_eq!(setfsuid_on(&task, 1001), 1000);
}

#[test]
fn setfsuid_reports_no_error_when_the_change_is_refused() {
    let task = unprivileged((10, 10, 10), (0, 0, 0));
    assert_eq!(setfsuid_on(&task, 999), 10, "refusal is indistinguishable from success");
    assert_eq!(uids(&task), (10, 10, 10, 10), "the refused id was not applied");
}

#[test]
fn setfsuid_accepts_any_member_of_the_uid_triple_without_a_cap() {
    let task = unprivileged((10, 20, 30), (0, 0, 0));
    for target in [10u32, 20, 30] {
        setfsuid_on(&task, target);
        assert_eq!(uids(&task).3, target);
    }
}

#[test]
fn setfsuid_treats_the_invalid_id_as_a_pure_query() {
    let task = privileged();
    set_uids(&task, (5, 5, 5));
    assert_eq!(setfsuid_on(&task, ID_UNCHANGED), 5);
    assert_eq!(uids(&task).3, 5);
}

#[test]
fn setfsuid_leaving_root_drops_the_filesystem_capabilities() {
    // Linux `cap_task_fix_setuid(LSM_SETID_FS)`: CAP_FS_MASK follows fsuid.
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    assert_eq!(setfsuid_on(&task, 1000), 0);
    let effective = task.creds.cap_effective.load(Ordering::Acquire);
    assert_eq!(effective & (1u64 << crate::cap::DAC_OVERRIDE), 0);
    assert_eq!(effective & (1u64 << crate::cap::CHOWN), 0);
    assert_ne!(effective & (1u64 << crate::cap::SYS_ADMIN), 0,
        "only the fs mask is dropped");
}

#[test]
fn setfsuid_returning_to_root_raises_the_filesystem_capabilities_from_permitted() {
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    setfsuid_on(&task, 1000);
    assert_eq!(setfsuid_on(&task, 0), 1000);
    let effective = task.creds.cap_effective.load(Ordering::Acquire);
    assert_ne!(effective & (1u64 << crate::cap::DAC_OVERRIDE), 0);
    assert_ne!(effective & (1u64 << crate::cap::FOWNER), 0);
}

#[test]
fn setfsuid_with_the_no_setuid_fixup_securebit_leaves_capabilities_alone() {
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    task.creds.securebits.store(
        crate::task::creds::securebits::SECBIT_NO_SETUID_FIXUP, Ordering::Release);
    setfsuid_on(&task, 1000);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), Creds::CAP_FULL);
}

#[test]
fn setfsgid_returns_the_previous_fsgid_and_never_fails() {
    let task = unprivileged((0, 0, 0), (10, 20, 30));
    assert_eq!(setfsgid_on(&task, 30), 20);
    assert_eq!(gids(&task), (10, 20, 30, 30));
    assert_eq!(setfsgid_on(&task, 999), 30, "refused change still returns the previous id");
    assert_eq!(gids(&task).3, 30);
}

#[test]
fn setfsgid_with_cap_setgid_accepts_an_arbitrary_gid() {
    let task = privileged();
    set_gids(&task, (10, 10, 10));
    grant_caps(&task, &[crate::cap::SETGID]);
    assert_eq!(setfsgid_on(&task, 4242), 10);
    assert_eq!(gids(&task).3, 4242);
}

#[test]
fn setfsgid_treats_the_invalid_id_as_a_pure_query() {
    let task = privileged();
    set_gids(&task, (7, 7, 7));
    assert_eq!(setfsgid_on(&task, ID_UNCHANGED), 7);
    assert_eq!(gids(&task).3, 7);
}
