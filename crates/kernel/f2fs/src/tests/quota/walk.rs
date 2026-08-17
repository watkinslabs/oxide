//! Walking the tree to a record, and refusing a tree that cannot be walked.

use crate::quota::info::{self, Revision};
use crate::quota::tree;
use crate::quota::uapi::*;
use crate::quota::QuotaError;

use super::image;

/// A file whose tree leads to one leaf holding `id`.
///
/// Six blocks: headers, four levels of index block, leaf. The chain is the
/// depth the format derives, so a walk that stops one level early lands on an
/// interior block and finds no record.
fn one_record(id: u32) -> (alloc::vec::Vec<u8>, info::Info) {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, id, inf.depth, &[2, 3, 4, 5]);
    image::r1_entry(&mut f, 5, 0, id, 200, 100, 7, 2048, 1024, 999, 0, 0);
    (f, inf)
}

#[test]
fn a_record_is_found_at_the_full_depth_of_the_tree() {
    let (f, inf) = one_record(5);
    assert_eq!(inf.depth, 4);
    let at = tree::find_entry(&f, &inf, 5).unwrap().expect("planted");
    assert_eq!(at, image::entry_at(5, 0, Revision::R1));
    let d = tree::read(&f, &inf, 5).unwrap().unwrap();
    assert_eq!(d.curinodes, 7);
    assert_eq!(d.bhardlimit, 2048 * SPACE_UNIT);
}

#[test]
fn a_record_whose_id_spans_every_level_is_found() {
    // Each byte of the id selects at a different level, so this fails if any
    // level's index is computed with the wrong slice.
    let id = 0x0102_0304;
    let (f, inf) = one_record(id);
    assert!(tree::find_entry(&f, &inf, id).unwrap().is_some());
    // A neighbour differing only in the top byte must not resolve.
    assert_eq!(tree::find_entry(&f, &inf, 0x0202_0304).unwrap(), None);
    // Nor one differing only in the bottom byte, which is the leaf level's
    // own slice: its reference is zero, so nothing is reached.
    assert_eq!(tree::find_entry(&f, &inf, 0x0102_0305).unwrap(), None);
}

#[test]
fn a_record_in_a_later_slot_of_the_leaf_is_found() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 300, inf.depth, &[2, 3, 4, 5]);
    image::r1_entry(&mut f, 5, 0, 44, 0, 0, 1, 0, 0, 0, 0, 0);
    image::r1_entry(&mut f, 5, 1, 300, 0, 0, 2, 0, 0, 0, 0, 0);
    let at = tree::find_entry(&f, &inf, 300).unwrap().unwrap();
    assert_eq!(at, image::entry_at(5, 1, Revision::R1));
    assert_eq!(tree::read(&f, &inf, 300).unwrap().unwrap().curinodes, 2);
}

#[test]
fn an_identity_with_no_reference_anywhere_is_absent_not_an_error() {
    let (f, inf) = one_record(5);
    // Differs at the top level, where the reference is zero.
    assert_eq!(tree::find_entry(&f, &inf, 0x0100_0005).unwrap(), None);
    assert_eq!(tree::read(&f, &inf, 0x0100_0005).unwrap(), None);
}

#[test]
fn a_leaf_reached_without_the_record_it_promised_is_corruption() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 5, inf.depth, &[2, 3, 4, 5]);
    // The path exists; the leaf holds someone else.
    image::r1_entry(&mut f, 5, 0, 6, 0, 0, 1, 0, 0, 0, 0, 0);
    assert_eq!(tree::find_entry(&f, &inf, 5), Err(QuotaError::DanglingLeaf));
}

#[test]
fn a_reference_past_the_last_block_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 5, inf.depth, &[2, 3, 4, 5]);
    // The leaf level's slot for this id, pointed one block past the file.
    image::link(&mut f, 4, 5, 6);
    assert_eq!(tree::find_entry(&f, &inf, 5), Err(QuotaError::BlockOutOfRange));
}

#[test]
fn a_reference_to_the_header_block_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 5, inf.depth, &[2, 3, 4, 5]);
    // Block zero holds the headers and is never part of the tree.
    image::link(&mut f, 2, 0, 0);
    assert_eq!(tree::find_entry(&f, &inf, 5).unwrap(), None, "zero means absent");
    image::link(&mut f, 2, 0, u32::MAX);
    assert_eq!(tree::find_entry(&f, &inf, 5), Err(QuotaError::BlockOutOfRange));
}

#[test]
fn a_tree_that_points_back_at_itself_is_refused_rather_than_followed() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 0, inf.depth, &[2, 3, 4, 5]);
    // Level two points back at the root: every index for id zero is zero, so
    // a walk without a cycle check reads the same blocks forever.
    image::link(&mut f, 4, 0, QT_TREE_OFF);
    assert_eq!(tree::find_entry(&f, &inf, 0), Err(QuotaError::Cycle));
}

#[test]
fn a_block_pointing_at_itself_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::link(&mut f, QT_TREE_OFF, 0, 2);
    image::link(&mut f, 2, 0, 2);
    assert_eq!(tree::find_entry(&f, &inf, 0), Err(QuotaError::Cycle));
}

#[test]
fn a_tree_deeper_than_the_bound_is_refused_before_it_is_walked() {
    let (f, inf) = one_record(5);
    let deep = info::Info { depth: MAX_TREE_DEPTH, ..inf.clone() };
    assert_eq!(tree::find_entry(&f, &deep, 5), Err(QuotaError::DepthTooBig));
    let deeper = info::Info { depth: MAX_TREE_DEPTH + 3, ..inf.clone() };
    assert_eq!(tree::find_entry(&f, &deeper, 5), Err(QuotaError::DepthTooBig));
    let none = info::Info { depth: 0, ..inf };
    assert_eq!(tree::find_entry(&f, &none, 5), Err(QuotaError::DepthTooBig));
}

#[test]
fn a_file_with_no_root_block_is_refused() {
    let f = image::file(USRQUOTA, Revision::R1, 1);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    assert_eq!(tree::find_entry(&f, &inf, 5), Err(QuotaError::NoRoot));
}

#[test]
fn a_leaf_claiming_more_records_than_fit_is_refused() {
    let (mut f, inf) = one_record(5);
    let full = info::entries_per_block(QT_BLOCK_SIZE, Revision::R1);
    assert_eq!(tree::block_entries(&f, &inf, 5).unwrap(), 1);
    image::put16(&mut f, image::block_at(5) + DQDH_ENTRIES, full as u16 + 1);
    assert_eq!(tree::block_entries(&f, &inf, 5), Err(QuotaError::BadEntryCount));
}

#[test]
fn a_leaf_whose_free_links_leave_the_file_is_refused() {
    let (mut f, inf) = one_record(5);
    image::put32(&mut f, image::block_at(5) + DQDH_NEXT_FREE, inf.blocks);
    assert_eq!(tree::block_entries(&f, &inf, 5), Err(QuotaError::BlockOutOfRange));
}

#[test]
fn a_changed_record_is_written_back_where_it_was_found() {
    let (mut f, inf) = one_record(5);
    let mut d = tree::read(&f, &inf, 5).unwrap().unwrap();
    d.curspace = 4096;
    d.btime = 12_345;
    tree::write(&mut f, &inf, 5, &d).unwrap();
    assert_eq!(tree::read(&f, &inf, 5).unwrap().unwrap(), d);
    // The neighbouring slot is untouched.
    let at = image::entry_at(5, 1, Revision::R1);
    assert!(f[at..at + R1_SIZE].iter().all(|&b| b == 0));
}

#[test]
fn writing_a_record_the_tree_has_no_slot_for_is_refused() {
    let (mut f, inf) = one_record(5);
    let d = crate::quota::Dqblk::default();
    assert_eq!(tree::write(&mut f, &inf, 0x0100_0005, &d), Err(QuotaError::NoEntry));
}

#[test]
fn writing_a_limit_the_revision_cannot_hold_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R0, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 5, inf.depth, &[2, 3, 4, 5]);
    let at = image::entry_at(5, 0, Revision::R0);
    image::put32(&mut f, at + R0_ID, 5);
    image::put32(&mut f, at + R0_CURINODES, 1);
    let mut d = tree::read(&f, &inf, 5).unwrap().unwrap();
    d.bhardlimit = R0_MAX_SPACE_LIMIT + SPACE_UNIT;
    assert_eq!(tree::write(&mut f, &inf, 5, &d), Err(QuotaError::LimitTooWide));
}

#[test]
fn a_truncated_file_is_refused_rather_than_read_past() {
    let (f, inf) = one_record(5);
    let short = &f[..3 * QT_BLOCK_SIZE];
    assert_eq!(tree::find_entry(short, &inf, 5), Err(QuotaError::Truncated));
}
