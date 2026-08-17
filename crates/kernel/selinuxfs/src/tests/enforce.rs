// The enforcement-mode control.

use vfs::VfsError;

use crate::fake::FakeOps;
use crate::nodes::enforce::{read_enforce, write_enforce, PERM_SETENFORCE};

#[test]
fn a_non_zero_write_enforces_and_a_zero_write_does_not() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_enforce(&mut ops, b"1\n").unwrap(), 2);
    assert!(ops.enforcing);
    assert_eq!(read_enforce(&mut ops), "1");
    write_enforce(&mut ops, b"0").unwrap();
    assert!(!ops.enforcing);
    assert_eq!(read_enforce(&mut ops), "0");
    write_enforce(&mut ops, b"2").unwrap();
    assert!(ops.enforcing);
}

#[test]
fn a_written_word_is_refused() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_enforce(&mut ops, b"on").err(), Some(VfsError::Einval));
    assert!(!ops.enforcing);
}

#[test]
fn a_change_of_mode_is_gated_and_a_denial_changes_nothing() {
    let mut ops = FakeOps::denying(PERM_SETENFORCE);
    assert_eq!(write_enforce(&mut ops, b"1").err(), Some(VfsError::Eacces));
    assert!(!ops.enforcing, "a denied write must not change the mode");
    assert!(ops.was_checked(PERM_SETENFORCE), "the write must consult the policy");
}

#[test]
fn a_write_asking_for_the_mode_already_in_force_is_not_a_change() {
    let mut ops = FakeOps::denying(PERM_SETENFORCE);
    assert_eq!(write_enforce(&mut ops, b"0").unwrap(), 1);
    assert!(!ops.was_checked(PERM_SETENFORCE));
}

#[test]
fn a_change_of_mode_is_announced_to_the_userspace_avc() {
    // The userspace AVC answers permissive decisions from its own cache, so a
    // mode change it is never told about leaves it on the old mode.
    use crate::notify::tests::announced;
    use crate::notify::Notice;
    let mut ops = FakeOps::allow_all();
    write_enforce(&mut ops, b"1").unwrap();
    assert_eq!(announced(), alloc::vec![Notice::Setenforce(true)]);
    write_enforce(&mut ops, b"0").unwrap();
    assert_eq!(announced(), alloc::vec![Notice::Setenforce(false)]);
}

#[test]
fn a_write_that_changes_nothing_and_a_denied_one_announce_nothing() {
    use crate::notify::tests::announced;
    let mut ops = FakeOps::allow_all();
    write_enforce(&mut ops, b"0").unwrap();
    assert!(announced().is_empty(), "the mode already in force is not an event");
    let mut denied = FakeOps::denying(PERM_SETENFORCE);
    assert_eq!(write_enforce(&mut denied, b"1").err(), Some(VfsError::Eacces));
    assert!(announced().is_empty(), "a refused write changed no mode to announce");
}
