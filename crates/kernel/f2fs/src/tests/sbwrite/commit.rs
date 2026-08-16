//! The two decisions a commit makes before it touches a medium: whether it may
//! write at all, and which copies it writes in which order.

use alloc::vec;

use super::*;

#[test]
fn a_read_only_medium_refuses_every_commit() {
    assert!(refuses(false, false, true));
    assert!(refuses(true, false, true));
}

#[test]
fn a_read_only_mount_refuses_a_repair_and_allows_a_change() {
    // The repair is the one a read-only mount must not make; an ordinary
    // change reaches here from a remount that is turning the volume writable.
    assert!(refuses(true, true, false));
    assert!(!refuses(false, true, false));
}

#[test]
fn a_writable_mount_on_a_writable_medium_refuses_nothing() {
    assert!(!refuses(false, false, false));
    assert!(!refuses(true, false, false));
}

#[test]
fn the_copy_that_is_not_believed_is_written_first() {
    assert_eq!(copies(0, false), vec![1, 0]);
    assert_eq!(copies(1, false), vec![0, 1]);
}

#[test]
fn a_repair_writes_only_the_copy_that_failed() {
    assert_eq!(copies(0, true), vec![1]);
    assert_eq!(copies(1, true), vec![0]);
}

#[test]
fn the_believed_copy_is_never_the_first_write() {
    for valid in 0..SUPER_COPIES {
        for recover in [false, true] {
            assert_ne!(copies(valid, recover)[0], valid,
                       "valid={valid} recover={recover}");
        }
    }
}
