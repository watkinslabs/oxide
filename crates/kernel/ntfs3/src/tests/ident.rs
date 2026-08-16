use super::*;
use crate::record::Reference;
use crate::uapi::{MFT_REC_ROOT, MFT_REC_USER};

#[test]
fn an_inode_number_is_the_record_number() {
    assert_eq!(inode_number(42), 42);
    assert_eq!(root_inode_number(), MFT_REC_ROOT);
}

#[test]
fn a_reference_carrying_a_stale_sequence_does_not_resolve() {
    // A record number alone is reused; the sequence is what makes a stale
    // reference name the file that WAS there rather than its successor.
    let r = Reference { number: 30, sequence: 4 };
    assert!(reference_is_current(&r, 4));
    assert!(!reference_is_current(&r, 5));
}

#[test]
fn a_reference_with_no_sequence_resolves_to_whatever_is_there() {
    let r = Reference { number: 30, sequence: 0 };
    assert!(reference_is_current(&r, 9));
}

#[test]
fn the_volumes_own_records_are_not_user_files() {
    // Presenting them puts `$MFT` and `$Bitmap` in the root of every mount.
    for n in [0u64, 5, 10, 23] { assert!(!is_user_record(n), "{n}"); }
    assert!(is_user_record(MFT_REC_USER));
    assert!(is_user_record(100));
}
