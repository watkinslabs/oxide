//! One identity's record, in both revisions.

use alloc::vec;

use crate::quota::dqblk::{self, Dqblk};
use crate::quota::info::Revision;
use crate::quota::uapi::*;
use crate::quota::QuotaError;

/// A revision-one record, written field by field from the format.
fn r1(id: u32) -> alloc::vec::Vec<u8> {
    let mut e = vec![0u8; R1_SIZE];
    e[R1_ID..R1_ID + U32_LEN].copy_from_slice(&id.to_le_bytes());
    e[R1_IHARDLIMIT..R1_IHARDLIMIT + U64_LEN].copy_from_slice(&200u64.to_le_bytes());
    e[R1_ISOFTLIMIT..R1_ISOFTLIMIT + U64_LEN].copy_from_slice(&100u64.to_le_bytes());
    e[R1_CURINODES..R1_CURINODES + U64_LEN].copy_from_slice(&7u64.to_le_bytes());
    e[R1_BHARDLIMIT..R1_BHARDLIMIT + U64_LEN].copy_from_slice(&2048u64.to_le_bytes());
    e[R1_BSOFTLIMIT..R1_BSOFTLIMIT + U64_LEN].copy_from_slice(&1024u64.to_le_bytes());
    e[R1_CURSPACE..R1_CURSPACE + U64_LEN].copy_from_slice(&999u64.to_le_bytes());
    e[R1_BTIME..R1_BTIME + U64_LEN].copy_from_slice(&555u64.to_le_bytes());
    e[R1_ITIME..R1_ITIME + U64_LEN].copy_from_slice(&666u64.to_le_bytes());
    e
}

#[test]
fn a_space_limit_is_stored_in_units_and_used_in_bytes() {
    let d = dqblk::parse(&r1(9), Revision::R1).unwrap();
    // Two thousand and forty-eight UNITS is two mebibytes, not two kibibytes.
    assert_eq!(d.bhardlimit, 2048 * SPACE_UNIT);
    assert_eq!(d.bsoftlimit, 1024 * SPACE_UNIT);
    assert_eq!(d.bhardlimit, 2 * 1024 * 1024);
    // Usage beside it is already bytes and is not scaled.
    assert_eq!(d.curspace, 999);
}

#[test]
fn inode_counts_and_graces_are_read_as_stored() {
    let d = dqblk::parse(&r1(9), Revision::R1).unwrap();
    assert_eq!(d.ihardlimit, 200);
    assert_eq!(d.isoftlimit, 100);
    assert_eq!(d.curinodes, 7);
    assert_eq!(d.btime, 555);
    assert_eq!(d.itime, 666);
}

#[test]
fn a_record_round_trips_through_both_revisions() {
    let d = dqblk::parse(&r1(9), Revision::R1).unwrap();
    let back = dqblk::encode(&d, 9, Revision::R1);
    assert_eq!(back, r1(9));
    assert_eq!(dqblk::parse(&back, Revision::R1).unwrap(), d);

    let e0 = dqblk::encode(&d, 9, Revision::R0);
    assert_eq!(e0.len(), R0_SIZE);
    assert_eq!(dqblk::parse(&e0, Revision::R0).unwrap(), d);
}

#[test]
fn a_partial_unit_of_limit_rounds_up_so_a_limit_never_shrinks() {
    let d = Dqblk { bhardlimit: SPACE_UNIT + 1, ..Dqblk::default() };
    let back = dqblk::parse(&dqblk::encode(&d, 1, Revision::R1), Revision::R1).unwrap();
    assert_eq!(back.bhardlimit, 2 * SPACE_UNIT);
    assert!(back.bhardlimit >= d.bhardlimit);
    assert_eq!(dqblk::bytes_to_units(0), 0);
    assert_eq!(dqblk::bytes_to_units(1), 1);
    assert_eq!(dqblk::bytes_to_units(SPACE_UNIT), 1);
    assert_eq!(dqblk::units_to_bytes(3), 3 * SPACE_UNIT);
}

#[test]
fn an_all_zero_record_is_a_free_slot() {
    let e = vec![0u8; R1_SIZE];
    assert!(dqblk::unused(&e));
    assert_eq!(dqblk::id_of(&e, Revision::R1), None);
    let mut e2 = e.clone();
    e2[R1_CURINODES] = 1;
    assert!(!dqblk::unused(&e2));
    assert_eq!(dqblk::id_of(&e2, Revision::R1), Some(0));
}

#[test]
fn an_empty_record_is_escaped_so_it_is_not_mistaken_for_free() {
    // Everything zero: the encode must not leave bytes that read as free.
    let d = Dqblk::default();
    let e = dqblk::encode(&d, 0, Revision::R1);
    assert!(!dqblk::unused(&e), "an empty record must not read as a free slot");
    assert_eq!(dqblk::id_of(&e, Revision::R1), Some(0));
    // And the escape is undone on the way back, not reported as a grace.
    assert_eq!(dqblk::parse(&e, Revision::R1).unwrap(), d);
    assert_eq!(dqblk::parse(&e, Revision::R1).unwrap().itime, 0);
}

#[test]
fn a_record_that_only_looks_empty_keeps_its_grace() {
    // Same escape value, but another field is set, so it is a real record.
    let d = Dqblk { itime: 1, curinodes: 3, ..Dqblk::default() };
    let e = dqblk::encode(&d, 0, Revision::R1);
    assert_eq!(dqblk::parse(&e, Revision::R1).unwrap().itime, 1);
}

#[test]
fn the_id_is_read_from_where_the_revision_puts_it() {
    assert_eq!(dqblk::id_of(&r1(0x4142_4344), Revision::R1), Some(0x4142_4344));
    let d = Dqblk { curinodes: 1, ..Dqblk::default() };
    let e0 = dqblk::encode(&d, 77, Revision::R0);
    assert_eq!(dqblk::id_of(&e0, Revision::R0), Some(77));
    assert_eq!(&e0[R0_ID..R0_ID + U32_LEN], &77u32.to_le_bytes());
}

#[test]
fn a_short_record_is_refused_rather_than_read_short() {
    assert_eq!(dqblk::parse(&vec![0u8; R1_SIZE - 1], Revision::R1), Err(QuotaError::Truncated));
    assert_eq!(dqblk::id_of(&vec![1u8; R0_SIZE - 1], Revision::R0), None);
}

#[test]
fn a_limit_too_wide_for_the_narrow_revision_is_seen_before_it_is_written() {
    let wide = Dqblk { bhardlimit: R0_MAX_SPACE_LIMIT + SPACE_UNIT, ..Dqblk::default() };
    assert!(!dqblk::limits_fit(&wide, Revision::R0));
    assert!(dqblk::limits_fit(&wide, Revision::R1));
    let many = Dqblk { ihardlimit: R0_MAX_INODE_LIMIT + 1, ..Dqblk::default() };
    assert!(!dqblk::limits_fit(&many, Revision::R0));
    assert!(dqblk::limits_fit(&Dqblk::default(), Revision::R0));
}
