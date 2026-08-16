//! The next identity at or after a given one.

use alloc::vec::Vec;

use crate::quota::info::{self, Info, Revision};
use crate::quota::tree;
use crate::quota::uapi::*;
use crate::quota::{Dqblk, QuotaError};

use super::image;

fn empty() -> (Vec<u8>, Info) {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    (f, inf)
}

fn rec(inodes: u64) -> Dqblk {
    Dqblk { bhardlimit: 0, bsoftlimit: 0, curspace: 0, ihardlimit: 0, isoftlimit: 0,
            curinodes: inodes, btime: 0, itime: 0, rsvspace: 0 }
}

/// A tree holding exactly `ids`, planted by hand so the scan is read against
/// the format rather than against whatever the insert happened to build.
///
/// Every id must be under one block's fan-out: they then share every level
/// above the leaf, which is what makes the planted tree hold exactly these
/// ids and not every combination of their level indexes.
fn holding(ids: &[u32]) -> (Vec<u8>, Info) {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    for (slot, id) in ids.iter().enumerate() {
        assert!(*id < 256, "ids sharing every level but the last");
        image::plant(&mut f, *id, inf.depth, &[2, 3, 4, 5]);
        image::r1_entry(&mut f, 5, slot, *id, 0, 0, u64::from(*id) + 1, 0, 0, 0, 0, 0);
    }
    (f, inf)
}

/// A tree holding `ids`, grown by the insert. Anything spread across more
/// than one level has to be built this way: a hand-planted tree that SHARES
/// its interior blocks between two ids holds every id their level indexes can
/// be combined into, not the two that were planted.
fn built(ids: &[u32]) -> (Vec<u8>, Info) {
    let (mut f, mut inf) = empty();
    for id in ids { tree::write_or_create(&mut f, &mut inf, *id, &rec(u64::from(*id) + 1)).unwrap(); }
    (f, inf)
}

#[test]
fn a_tree_holding_nothing_has_no_next_identity() {
    let (f, inf) = empty();
    assert_eq!(tree::next_id(&f, &inf, 0).unwrap(), None);
    assert_eq!(tree::next_id(&f, &inf, u32::MAX).unwrap(), None);
}

#[test]
fn the_scan_finds_the_lowest_identity_at_or_after_the_one_asked_for() {
    let (f, inf) = holding(&[5, 9, 200]);
    assert_eq!(tree::next_id(&f, &inf, 0).unwrap(), Some(5));
    assert_eq!(tree::next_id(&f, &inf, 5).unwrap(), Some(5), "the bound includes itself");
    assert_eq!(tree::next_id(&f, &inf, 6).unwrap(), Some(9));
    assert_eq!(tree::next_id(&f, &inf, 10).unwrap(), Some(200));
    assert_eq!(tree::next_id(&f, &inf, 200).unwrap(), Some(200));
    assert_eq!(tree::next_id(&f, &inf, 201).unwrap(), None);
}

#[test]
fn the_scan_crosses_every_level_of_the_tree() {
    // One identity per level of the key: an implementation that advances by
    // the wrong span skips one of these or reports it twice.
    let ids = [0u32, 255, 256, 0x0001_0000, 0x0102_0304, u32::MAX];
    let (f, inf) = built(&ids);
    let mut seen = Vec::new();
    let mut from = 0u32;
    loop {
        let Some(id) = tree::next_id(&f, &inf, from).unwrap() else { break };
        seen.push(id);
        let Some(next) = id.checked_add(1) else { break };
        from = next;
    }
    assert_eq!(seen, ids, "every identity, in order, exactly once");
}

#[test]
fn the_scan_answers_with_the_record_as_well_as_the_identity() {
    let (f, inf) = holding(&[5, 9]);
    assert_eq!(tree::next_record(&f, &inf, 6).unwrap(), Some((9, rec(10))));
    assert_eq!(tree::next_record(&f, &inf, 10).unwrap(), None);
}

#[test]
fn the_scan_finds_what_a_create_put_there_and_stops_finding_what_a_delete_took() {
    let (mut f, mut inf) = empty();
    for id in [4u32, 70_000, 9] { tree::write_or_create(&mut f, &mut inf, id, &rec(1)).unwrap(); }
    assert_eq!(tree::next_id(&f, &inf, 0).unwrap(), Some(4));
    assert_eq!(tree::next_id(&f, &inf, 5).unwrap(), Some(9));
    assert_eq!(tree::next_id(&f, &inf, 10).unwrap(), Some(70_000));
    tree::delete(&mut f, &mut inf, 9).unwrap();
    assert_eq!(tree::next_id(&f, &inf, 5).unwrap(), Some(70_000), "the removed one is gone");
    tree::delete(&mut f, &mut inf, 70_000).unwrap();
    assert_eq!(tree::next_id(&f, &inf, 5).unwrap(), None);
    assert_eq!(tree::next_id(&f, &inf, 0).unwrap(), Some(4), "and the rest still answers");
}

#[test]
fn a_reference_leaving_the_file_stops_the_scan_rather_than_being_followed() {
    let (mut f, inf) = holding(&[5]);
    // The leaf-level slot for this identity, pointed one block past the file.
    image::link(&mut f, 4, 5, inf.blocks);
    assert_eq!(tree::next_id(&f, &inf, 0), Err(QuotaError::BlockOutOfRange));
}

#[test]
fn a_tree_deeper_than_the_bound_is_refused_before_it_is_scanned() {
    let (f, inf) = holding(&[5]);
    let deep = Info { depth: MAX_TREE_DEPTH, ..inf };
    assert_eq!(tree::next_id(&f, &deep, 0), Err(QuotaError::DepthTooBig));
}
