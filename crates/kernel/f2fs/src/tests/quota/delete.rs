//! Removing a record, and giving back exactly what held it.

use alloc::vec::Vec;

use crate::quota::info::{self, entries_per_block, Info, Revision};
use crate::quota::tree::{self, block};
use crate::quota::uapi::*;
use crate::quota::{Dqblk, QuotaError};

use super::image;

fn empty() -> (Vec<u8>, Info) {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    (f, inf)
}

fn rec(space: u64) -> Dqblk {
    Dqblk { bhardlimit: 0, bsoftlimit: 0, curspace: space, ihardlimit: 0, isoftlimit: 0,
            curinodes: 1, btime: 0, itime: 0, rsvspace: 0 }
}

fn free_blocks(f: &[u8], inf: &Info) -> Vec<u32> {
    let mut out = Vec::new();
    let mut blk = inf.free_blk;
    while blk != 0 && !out.contains(&blk) {
        out.push(blk);
        blk = block::next_free(f, blk).unwrap();
    }
    out
}

/// The leaves on the free-entry list, head first.
fn free_entries(f: &[u8], inf: &Info) -> Vec<u32> {
    let mut out = Vec::new();
    let mut blk = inf.free_entry;
    while blk != 0 && !out.contains(&blk) {
        out.push(blk);
        blk = block::next_free(f, blk).unwrap();
    }
    out
}

#[test]
fn removing_the_only_record_gives_back_every_block_its_path_needed() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    let grown = inf.blocks;
    assert!(tree::delete(&mut f, &mut inf, 7).unwrap());
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), None);
    assert_eq!(inf.blocks, grown, "a quota file does not shrink; its blocks are reused");
    let mut back = free_blocks(&f, &inf);
    back.sort_unstable();
    assert_eq!(back, [2, 3, 4, 5], "the three index blocks and the leaf");
    assert_eq!(inf.free_entry, 0, "and no leaf is offered any more");
    // The root survives: it is the tree, not a block of it.
    assert!(!back.contains(&QT_TREE_OFF));
}

#[test]
fn removing_one_of_two_records_leaves_the_other_and_the_blocks_alone() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    tree::write_or_create(&mut f, &mut inf, 9, &rec(8192)).unwrap();
    let before = inf.clone();
    assert!(tree::delete(&mut f, &mut inf, 7).unwrap());
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), None);
    assert_eq!(tree::read(&f, &inf, 9).unwrap(), Some(rec(8192)), "the neighbour is untouched");
    assert_eq!(inf.blocks, before.blocks);
    assert_eq!(free_blocks(&f, &inf), Vec::<u32>::new(), "nothing came back");
    assert_eq!(tree::block_entries(&f, &inf, 5).unwrap(), 1);
    assert_eq!(inf.free_entry, 5, "the leaf still has slots and stays on the list");
}

#[test]
fn a_leaf_that_was_full_rejoins_the_list_of_leaves_with_a_slot() {
    let (mut f, mut inf) = empty();
    let per = entries_per_block(QT_BLOCK_SIZE, Revision::R1) as u32;
    for id in 0..per { tree::write_or_create(&mut f, &mut inf, id, &rec(u64::from(id))).unwrap(); }
    assert_eq!(inf.free_entry, 0, "full, so off the list");
    tree::delete(&mut f, &mut inf, 3).unwrap();
    assert_eq!(inf.free_entry, 5, "one slot back is enough to be offered again");
    assert_eq!(free_entries(&f, &inf), [5]);
    // An identity on the same path, so nothing but the slot is needed.
    let blocks = inf.blocks;
    tree::write_or_create(&mut f, &mut inf, 200, &rec(1)).unwrap();
    assert_eq!(inf.blocks, blocks, "and the slot is what the next record uses");
    assert_eq!(tree::read(&f, &inf, 200).unwrap(), Some(rec(1)));
}

#[test]
fn removing_an_identity_the_tree_never_held_changes_nothing() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    let before = (f.clone(), inf.clone());
    assert!(!tree::delete(&mut f, &mut inf, 8).unwrap(), "nothing to remove");
    assert!(!tree::delete(&mut f, &mut inf, 0x0100_0007).unwrap(), "nor on another path");
    assert_eq!(inf, before.1);
    assert_eq!(f, before.0);
}

#[test]
fn what_a_delete_gave_back_is_what_the_next_create_uses() {
    let (mut f, mut inf) = empty();
    let ids: [u32; 5] = [1, 2, 3, 0x0002_0000, 0x0300_0000];
    for id in ids { tree::write_or_create(&mut f, &mut inf, id, &rec(u64::from(id))).unwrap(); }
    let peak = inf.blocks;
    for id in ids { assert!(tree::delete(&mut f, &mut inf, id).unwrap(), "id {id}"); }
    for id in ids { assert_eq!(tree::read(&f, &inf, id).unwrap(), None, "id {id}"); }
    // Everything but the root came back, and the same ids fit again without
    // the file growing by a single block.
    for id in ids { tree::write_or_create(&mut f, &mut inf, id, &rec(u64::from(id))).unwrap(); }
    assert_eq!(inf.blocks, peak, "a create/delete cycle must not leak blocks");
    for id in ids { assert_eq!(tree::read(&f, &inf, id).unwrap(), Some(rec(u64::from(id)))); }
}

#[test]
fn the_header_a_delete_left_survives_being_written_back() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    tree::write_or_create(&mut f, &mut inf, 8, &rec(1)).unwrap();
    tree::delete(&mut f, &mut inf, 7).unwrap();
    info::store(&mut f, &inf).unwrap();
    let again = info::parse(&f, USRQUOTA).unwrap();
    assert_eq!(again, inf);
    assert_eq!(tree::read(&f, &again, 8).unwrap(), Some(rec(1)));
}

#[test]
fn a_leaf_claiming_to_hold_nothing_while_holding_a_record_is_refused() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    image::put16(&mut f, image::block_at(5) + DQDH_ENTRIES, 0);
    assert_eq!(tree::delete(&mut f, &mut inf, 7), Err(QuotaError::BadEntryCount));
}

#[test]
fn a_delete_walking_a_tree_that_points_back_at_itself_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let mut inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 0, inf.depth, &[2, 3, 4, 5]);
    image::r1_entry(&mut f, 5, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0);
    // Found by the walk, then the third level is pointed back at the root.
    assert!(tree::read(&f, &inf, 0).unwrap().is_some());
    image::link(&mut f, 4, 0, QT_TREE_OFF);
    assert_eq!(tree::delete(&mut f, &mut inf, 0), Err(QuotaError::Cycle));
}
