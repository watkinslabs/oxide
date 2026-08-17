// The policy-load node.

use vfs::VfsError;

use crate::fake::FakeOps;
use crate::nodes::load::{read_policy, write_load, PERM_LOAD_POLICY, PERM_READ_POLICY};
use crate::notify::tests::announced;
use crate::notify::Notice;

#[test]
fn a_whole_image_is_accepted_and_handed_back_verbatim() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_load(&mut ops, 0, b"Policy").unwrap(), 6);
    let mut buf = [0u8; 6];
    assert_eq!(read_policy(&mut ops, 0, &mut buf).unwrap(), 6);
    assert_eq!(&buf, b"Policy");
    assert!(ops.was_checked(PERM_LOAD_POLICY));
    assert!(ops.was_checked(PERM_READ_POLICY));
}

#[test]
fn a_streamed_image_is_refused_and_nothing_is_announced() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_load(&mut ops, 1, b"Policy").err(), Some(VfsError::Einval));
    assert_eq!(write_load(&mut ops, 0, b"").err(), Some(VfsError::Einval));
    assert!(ops.image.is_none());
    assert!(announced().is_empty(), "a refused load changes no policy to announce");
}

#[test]
fn a_denied_load_announces_nothing() {
    let mut ops = FakeOps::denying(PERM_LOAD_POLICY);
    assert_eq!(write_load(&mut ops, 0, b"Policy").err(), Some(VfsError::Eacces));
    assert!(ops.image.is_none());
    assert!(announced().is_empty());
}

#[test]
fn a_malformed_image_announces_nothing() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_load(&mut ops, 0, b"junk").err(), Some(VfsError::Einval));
    assert!(announced().is_empty(), "a policy that did not load did not change");
}

#[test]
fn an_accepted_load_announces_the_sequence_number_the_new_policy_carries() {
    // Without this the userspace AVC keeps answering from decisions the
    // REPLACED policy produced, which is what the reference's policyload
    // notification exists to prevent.
    let mut ops = FakeOps::allow_all();
    ops.facts.seqno = 4;
    write_load(&mut ops, 0, b"Policy").unwrap();
    assert_eq!(announced(), alloc::vec![Notice::Policyload(4)]);
}
