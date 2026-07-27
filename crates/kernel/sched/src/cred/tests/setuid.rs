// Linux `__sys_setuid` / `__sys_setgid` / `__sys_setreuid` / `__sys_setregid`
// (`kernel/sys.c`).

use super::fixtures::{err, gids, grant_caps, privileged, set_gids, set_uids, uids, unprivileged};
use crate::cred::gid::{setgid_on, setregid_on};
use crate::cred::uid::{setreuid_on, setuid_on};
use crate::cred::limits::ID_UNCHANGED;
use syscall::errno::Errno;

#[test]
fn setuid_from_root_sets_real_effective_saved_and_fs() {
    let task = privileged();
    assert_eq!(setuid_on(&task, 1000), 0);
    assert_eq!(uids(&task), (1000, 1000, 1000, 1000));
}

#[test]
fn setuid_without_cap_changes_only_effective_and_fs() {
    let task = unprivileged((1000, 1000, 0), (0, 0, 0));
    assert_eq!(setuid_on(&task, 0), 0, "saved uid 0 is a permitted target");
    assert_eq!(uids(&task), (1000, 0, 0, 0), "real and saved uid must not move");
}

#[test]
fn setuid_without_cap_rejects_an_id_outside_real_and_saved() {
    let task = unprivileged((1000, 1000, 1000), (0, 0, 0));
    assert_eq!(setuid_on(&task, 1001), err(Errno::Eperm));
    assert_eq!(uids(&task), (1000, 1000, 1000, 1000), "rejected call must not mutate");
}

#[test]
fn setuid_without_cap_rejects_the_current_effective_uid_when_it_is_neither_real_nor_saved() {
    // Linux checks `old->uid` and `old->suid` ONLY; the effective uid is
    // deliberately not a permitted target for setuid(2).
    let task = unprivileged((1000, 2000, 3000), (0, 0, 0));
    assert_eq!(setuid_on(&task, 2000), err(Errno::Eperm));
}

#[test]
fn setuid_rejects_the_invalid_id_with_einval() {
    let task = privileged();
    assert_eq!(setuid_on(&task, ID_UNCHANGED), err(Errno::Einval));
    assert_eq!(uids(&task), (0, 0, 0, 0));
}

#[test]
fn setgid_rejects_the_invalid_id_with_einval() {
    let task = privileged();
    assert_eq!(setgid_on(&task, ID_UNCHANGED), err(Errno::Einval));
}

#[test]
fn setgid_from_cap_holder_sets_the_whole_quad() {
    let task = privileged();
    assert_eq!(setgid_on(&task, 500), 0);
    assert_eq!(gids(&task), (500, 500, 500, 500));
}

#[test]
fn setgid_without_cap_accepts_saved_gid_and_rejects_anything_else() {
    let task = unprivileged((0, 0, 0), (100, 100, 200));
    assert_eq!(setgid_on(&task, 200), 0);
    assert_eq!(gids(&task), (100, 200, 200, 200));
    assert_eq!(setgid_on(&task, 300), err(Errno::Eperm));
}

#[test]
fn setreuid_minus_one_pair_is_a_no_op_and_preserves_the_saved_uid() {
    // Linux only touches suid when ruid was set, or the NEW euid differs
    // from the OLD ruid; `setreuid(-1,-1)` satisfies neither.
    let task = privileged();
    set_uids(&task, (1000, 2000, 3000));
    grant_caps(&task, &[crate::cap::SETUID]);
    assert_eq!(setreuid_on(&task, ID_UNCHANGED, ID_UNCHANGED), 0);
    assert_eq!(uids(&task), (1000, 2000, 3000, 2000));
}

#[test]
fn setreuid_setting_the_real_uid_moves_the_saved_uid_to_the_effective_uid() {
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    assert_eq!(setreuid_on(&task, 1000, ID_UNCHANGED), 0);
    assert_eq!(uids(&task), (1000, 0, 0, 0));
}

#[test]
fn setreuid_swaps_real_and_effective_for_an_unprivileged_caller() {
    let task = unprivileged((1000, 0, 0), (0, 0, 0));
    assert_eq!(setreuid_on(&task, 0, 1000), 0);
    assert_eq!(uids(&task), (0, 1000, 1000, 1000), "saved uid follows the new effective uid");
}

#[test]
fn setreuid_real_uid_target_excludes_the_saved_uid() {
    // Linux permits `{old->uid, old->euid}` for the REAL uid — not suid.
    let task = unprivileged((1000, 1000, 3000), (0, 0, 0));
    assert_eq!(setreuid_on(&task, 3000, ID_UNCHANGED), err(Errno::Eperm));
    assert_eq!(setreuid_on(&task, ID_UNCHANGED, 3000), 0, "the saved uid IS a valid euid target");
}

#[test]
fn setreuid_reports_eperm_for_the_real_uid_before_looking_at_the_effective_uid() {
    let task = unprivileged((1000, 1000, 1000), (0, 0, 0));
    assert_eq!(setreuid_on(&task, 4000, 5000), err(Errno::Eperm));
    assert_eq!(uids(&task), (1000, 1000, 1000, 1000), "no partial application");
}

#[test]
fn setregid_minus_one_pair_preserves_the_saved_gid() {
    let task = privileged();
    set_gids(&task, (10, 20, 30));
    assert_eq!(setregid_on(&task, ID_UNCHANGED, ID_UNCHANGED), 0);
    assert_eq!(gids(&task), (10, 20, 30, 20));
}

#[test]
fn setregid_real_gid_target_excludes_the_saved_gid() {
    let task = unprivileged((0, 0, 0), (100, 100, 300));
    assert_eq!(setregid_on(&task, 300, ID_UNCHANGED), err(Errno::Eperm));
    assert_eq!(setregid_on(&task, ID_UNCHANGED, 300), 0);
    assert_eq!(gids(&task), (100, 300, 300, 300));
}

#[test]
fn setregid_always_mirrors_the_effective_gid_into_the_fs_gid() {
    let task = privileged();
    set_gids(&task, (0, 0, 0));
    assert_eq!(setregid_on(&task, ID_UNCHANGED, 700), 0);
    assert_eq!(gids(&task), (0, 700, 700, 700));
}
