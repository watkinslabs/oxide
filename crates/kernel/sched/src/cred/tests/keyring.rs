// Linux `commit_creds`' `key_fsuid_changed` / `key_fsgid_changed` arms: every
// credential syscall that moves the filesystem ids must re-own the task's
// thread keyring, and one that does not must leave it alone.

use super::fixtures::{drop_caps, set_gids, set_uids};
use crate::cred::fsid::{setfsgid_on, setfsuid_on};
use crate::cred::gid::setresgid_on;
use crate::cred::limits::ID_UNCHANGED;
use crate::cred::uid::setresuid_on;
use crate::task::{SchedClass, Task};
use crate::tests::keyring_hooks::{fsid_records, record};

extern crate std;

/// Each case owns a distinct tid so the process-global hook log can be filtered
/// down to this case's own commits.
fn task(tid: u32) -> Task {
    let task = Task::new(tid, "cred-keyring", SchedClass::Normal { weight: 1024 });
    set_uids(&task, (0, 0, 0));
    set_gids(&task, (0, 0, 0));
    task
}

#[test]
fn setfsuid_drives_the_keyring_fsid_hook() {
    let _r = record();
    let t = task(4201);
    setfsuid_on(&t, 1000);
    assert_eq!(fsid_records(4201), std::vec![(4201, 1000, 0)]);
}

#[test]
fn setfsgid_drives_the_keyring_fsid_hook() {
    let _r = record();
    let t = task(4202);
    setfsgid_on(&t, 1001);
    assert_eq!(fsid_records(4202), std::vec![(4202, 0, 1001)]);
}

#[test]
fn setresuid_carries_the_derived_fsuid_to_the_keyring_hook() {
    let _r = record();
    let t = task(4203);
    // Linux derives the new fsuid from the new euid, so the id-triple syscalls
    // reach the same hook without naming it.
    assert_eq!(setresuid_on(&t, ID_UNCHANGED, 1234, ID_UNCHANGED), 0);
    assert_eq!(fsid_records(4203), std::vec![(4203, 1234, 0)]);
}

#[test]
fn setresgid_carries_the_derived_fsgid_to_the_keyring_hook() {
    let _r = record();
    let t = task(4204);
    assert_eq!(setresgid_on(&t, ID_UNCHANGED, 4321, ID_UNCHANGED), 0);
    assert_eq!(fsid_records(4204), std::vec![(4204, 0, 4321)]);
}

#[test]
fn a_rejected_setfsuid_leaves_the_keyring_untouched() {
    let _r = record();
    // Unprivileged and the target is none of {ruid, euid, suid, fsuid}: Linux
    // applies nothing and still returns the previous id, so no key moves.
    let t = task(4205);
    set_uids(&t, (500, 500, 500));
    drop_caps(&t);
    setfsuid_on(&t, 1);
    assert!(fsid_records(4205).is_empty());
}

#[test]
fn setting_the_fsuid_to_its_current_value_does_not_move_the_keyring() {
    let _r = record();
    let t = task(4206);
    set_uids(&t, (7, 7, 7));
    setfsuid_on(&t, 7);
    assert!(fsid_records(4206).is_empty());
}
