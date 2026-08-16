// Per-boolean values, staging, and the commit.

use vfs::VfsError;

use crate::fake::FakeOps;
use crate::nodes::booleans::{read_bool, write_bool, write_commit, PERM_SETBOOL};

#[test]
fn a_boolean_reads_as_two_decimals_one_space_apart() {
    let mut ops = FakeOps::allow_all().with_bool("httpd_t", false);
    assert_eq!(read_bool(&mut ops, "httpd_t").unwrap(), "0 0");
    write_bool(&mut ops, "httpd_t", b"1").unwrap();
    assert_eq!(read_bool(&mut ops, "httpd_t").unwrap(), "0 1");
}

#[test]
fn a_write_stages_and_does_not_commit() {
    // Committing on write would let a caller setting several related booleans
    // be observed in a combination no policy author wrote.
    let mut ops = FakeOps::allow_all().with_bool("one", false);
    write_bool(&mut ops, "one", b"1").unwrap();
    assert_eq!(ops.bools["one"], (false, true), "committed must not move on a write");
    assert_eq!(ops.commits, 0, "a write must not commit");
}

#[test]
fn the_commit_node_applies_every_staged_value_at_once() {
    let mut ops = FakeOps::allow_all().with_bool("one", false).with_bool("two", false);
    write_bool(&mut ops, "one", b"1").unwrap();
    write_bool(&mut ops, "two", b"1").unwrap();
    write_commit(&mut ops, b"1").unwrap();
    assert_eq!(ops.bools["one"], (true, true));
    assert_eq!(ops.bools["two"], (true, true));
    assert_eq!(ops.commits, 1);
}

#[test]
fn a_zero_commit_applies_nothing() {
    let mut ops = FakeOps::allow_all().with_bool("one", false);
    write_bool(&mut ops, "one", b"1").unwrap();
    write_commit(&mut ops, b"0").unwrap();
    assert_eq!(ops.bools["one"], (false, true));
    assert_eq!(ops.commits, 0);
}

#[test]
fn a_denied_write_stages_nothing() {
    let mut ops = FakeOps { denied: alloc::vec![PERM_SETBOOL.into()],
                            ..FakeOps::allow_all() }.with_bool("one", false);
    assert_eq!(write_bool(&mut ops, "one", b"1").err(), Some(VfsError::Eacces));
    assert_eq!(ops.bools["one"], (false, false));
    assert_eq!(write_commit(&mut ops, b"1").err(), Some(VfsError::Eacces));
    assert_eq!(ops.commits, 0);
}

#[test]
fn a_word_and_an_unknown_boolean_are_both_refused() {
    let mut ops = FakeOps::allow_all().with_bool("one", false);
    assert_eq!(write_bool(&mut ops, "one", b"yes").err(), Some(VfsError::Einval));
    assert_eq!(write_bool(&mut ops, "absent", b"1").err(), Some(VfsError::Einval));
    assert_eq!(read_bool(&mut ops, "absent").err(), Some(VfsError::Einval));
}
