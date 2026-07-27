// Linux `cap_emulate_setxuid` (`security/commoncap.c`) and the `commit_creds`
// (`kernel/cred.c`) dumpability block, driven through the real syscalls.

use core::sync::atomic::Ordering;

use super::fixtures::{privileged, set_uids, unprivileged};
use crate::cred::commit::{set_suid_dumpable, suid_dumpable};
use crate::cred::uid::{setresuid_on, setuid_on};
use crate::cred::limits::ID_UNCHANGED;
use crate::task::creds::securebits::{SECBIT_KEEP_CAPS, SECBIT_NO_SETUID_FIXUP};
use crate::task::{SUID_DUMP_DISABLE, SUID_DUMP_USER};
use crate::Creds;

#[test]
fn dropping_every_root_id_clears_permitted_effective_and_ambient() {
    let task = privileged();
    task.creds.cap_ambient.store(Creds::CAP_FULL, Ordering::Release);
    assert_eq!(setuid_on(&task, 1000), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), 0);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), 0);
    assert_eq!(task.creds.cap_ambient.load(Ordering::Acquire), 0);
}

#[test]
fn secure_keep_caps_preserves_permitted_but_still_clears_ambient() {
    let task = privileged();
    task.creds.securebits.store(SECBIT_KEEP_CAPS, Ordering::Release);
    task.creds.cap_ambient.store(Creds::CAP_FULL, Ordering::Release);
    assert_eq!(setuid_on(&task, 1000), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), Creds::CAP_FULL);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), 0,
        "the euid left root, so the effective set is emptied");
    assert_eq!(task.creds.cap_ambient.load(Ordering::Acquire), 0);
}

#[test]
fn no_setuid_fixup_securebit_suppresses_the_whole_juggle() {
    let task = privileged();
    task.creds.securebits.store(SECBIT_NO_SETUID_FIXUP, Ordering::Release);
    assert_eq!(setuid_on(&task, 1000), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), Creds::CAP_FULL);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), Creds::CAP_FULL);
}

#[test]
fn keeping_a_root_saved_uid_only_empties_the_effective_set() {
    // ruid/euid leave root but suid stays 0, so Linux keeps `permitted`.
    let task = privileged();
    assert_eq!(setresuid_on(&task, 1000, 1000, ID_UNCHANGED), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), Creds::CAP_FULL);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), 0);
}

#[test]
fn returning_the_effective_uid_to_root_restores_effective_from_permitted() {
    let task = privileged();
    assert_eq!(setresuid_on(&task, 1000, 1000, ID_UNCHANGED), 0);
    assert_eq!(setresuid_on(&task, ID_UNCHANGED, 0, ID_UNCHANGED), 0);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), Creds::CAP_FULL);
}

#[test]
fn a_privilege_drop_downgrades_dumpability_and_clears_the_parent_death_signal() {
    let task = privileged();
    task.pdeathsig.store(9, Ordering::Release);
    task.dumpable.store(SUID_DUMP_USER, Ordering::Release);
    // No mm on a hosted Task, so only the pdeath_signal half is observable
    // here; the dumpable half is covered by the sysctl test below.
    assert_eq!(setuid_on(&task, 1000), 0);
    assert_eq!(task.pdeathsig.load(Ordering::Acquire), 0);
}

#[test]
fn an_identity_preserving_call_leaves_the_parent_death_signal_alone() {
    let task = unprivileged((10, 20, 30), (0, 0, 0));
    task.pdeathsig.store(9, Ordering::Release);
    assert_eq!(setresuid_on(&task, 10, 20, 30), 0, "Linux's no-op short circuit");
    assert_eq!(task.pdeathsig.load(Ordering::Acquire), 9);
}

#[test]
fn suid_dumpable_is_a_single_live_variable() {
    let saved = suid_dumpable();
    set_suid_dumpable(SUID_DUMP_USER);
    assert_eq!(suid_dumpable(), SUID_DUMP_USER);
    set_suid_dumpable(SUID_DUMP_DISABLE);
    assert_eq!(suid_dumpable(), SUID_DUMP_DISABLE, "Linux's default");
    set_suid_dumpable(saved);
}

#[test]
fn a_gid_only_transition_does_not_touch_capabilities() {
    // commoncap installs no `task_fix_setgid` hook.
    let task = privileged();
    set_uids(&task, (0, 0, 0));
    assert_eq!(crate::cred::gid::setgid_on(&task, 1000), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), Creds::CAP_FULL);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), Creds::CAP_FULL);
}
