//! Making a slot for an identity the tree has never held.

use alloc::vec::Vec;

use crate::quota::info::{self, entries_per_block, Info, Revision};
use crate::quota::tree::{self, block};
use crate::quota::uapi::*;
use crate::quota::{Dqblk, QuotaError};

use super::image;

/// A file with nothing in it but the two headers and an empty root block.
fn empty() -> (Vec<u8>, Info) {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    let inf = info::parse(&f, USRQUOTA).unwrap();
    (f, inf)
}

/// A record with something in every field, so a slot that is written but not
/// found again cannot pass by reading back as the default.
fn rec(space: u64) -> Dqblk {
    Dqblk { bhardlimit: 16 * SPACE_UNIT, bsoftlimit: 8 * SPACE_UNIT, curspace: space,
            ihardlimit: 20, isoftlimit: 10, curinodes: 3, btime: 0, itime: 0, rsvspace: 0 }
}

/// Every block on the free-block list, head first.
fn free_blocks(f: &[u8], inf: &Info) -> Vec<u32> {
    let mut out = Vec::new();
    let mut blk = inf.free_blk;
    while blk != 0 && !out.contains(&blk) {
        out.push(blk);
        blk = block::next_free(f, blk).unwrap();
    }
    out
}

#[test]
fn a_first_record_grows_a_whole_path_and_is_read_back() {
    let (mut f, mut inf) = empty();
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), None, "nothing there to begin with");
    assert!(tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap(), "a slot was made");
    // Three index levels below the root, and the leaf.
    assert_eq!(inf.blocks, 6);
    assert_eq!(f.len(), 6 * QT_BLOCK_SIZE, "the file grew with them");
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), Some(rec(4096)));
    assert_eq!(tree::block_entries(&f, &inf, 5).unwrap(), 1);
    assert_eq!(inf.free_entry, 5, "the new leaf has slots left");
    assert_eq!(inf.free_blk, 0, "and nothing was left over");
}

#[test]
fn the_grown_header_survives_being_written_back_and_read_again() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    info::store(&mut f, &inf).unwrap();
    let again = info::parse(&f, USRQUOTA).unwrap();
    assert_eq!(again, inf, "a header the caller forgets to store loses the tree");
    assert_eq!(tree::read(&f, &again, 7).unwrap(), Some(rec(4096)));
}

#[test]
fn a_second_identity_on_the_same_path_shares_the_leaf_and_grows_nothing() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    let after_first = inf.blocks;
    assert!(tree::write_or_create(&mut f, &mut inf, 9, &rec(8192)).unwrap());
    assert_eq!(inf.blocks, after_first, "the leaf had a slot spare");
    assert_eq!(tree::block_entries(&f, &inf, 5).unwrap(), 2);
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), Some(rec(4096)));
    assert_eq!(tree::read(&f, &inf, 9).unwrap(), Some(rec(8192)));
}

#[test]
fn a_record_the_tree_already_has_is_rewritten_where_it_is() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    let before = inf.clone();
    assert!(!tree::write_or_create(&mut f, &mut inf, 7, &rec(9999)).unwrap(), "no slot was made");
    assert_eq!(inf, before, "and nothing moved");
    assert_eq!(tree::read(&f, &inf, 7).unwrap(), Some(rec(9999)));
    assert_eq!(tree::block_entries(&f, &inf, 5).unwrap(), 1);
}

#[test]
fn a_leaf_that_fills_leaves_the_free_entry_list_and_the_next_identity_takes_another() {
    let (mut f, mut inf) = empty();
    let per = entries_per_block(QT_BLOCK_SIZE, Revision::R1) as u32;
    for id in 0..per { tree::write_or_create(&mut f, &mut inf, id, &rec(id as u64)).unwrap(); }
    let leaf = 5;
    assert_eq!(tree::block_entries(&f, &inf, leaf).unwrap(), per as u16);
    assert_eq!(inf.free_entry, 0, "a full leaf is no use to the next insert");
    let full = inf.blocks;
    tree::write_or_create(&mut f, &mut inf, per, &rec(77)).unwrap();
    assert_eq!(inf.blocks, full + 1, "so a block was taken for another leaf");
    assert_eq!(inf.free_entry, full, "which is where the next record goes");
    for id in 0..=per {
        let want = if id == per { rec(77) } else { rec(u64::from(id)) };
        assert_eq!(tree::read(&f, &inf, id).unwrap(), Some(want), "id {id}");
    }
}

#[test]
fn identities_spread_across_the_whole_key_space_each_get_their_own_path() {
    let (mut f, mut inf) = empty();
    let ids = [0u32, 1, 255, 256, 0x0001_0000, 0x0102_0304, u32::MAX];
    for (n, id) in ids.iter().enumerate() {
        tree::write_or_create(&mut f, &mut inf, *id, &rec(n as u64 * 512)).unwrap();
    }
    for (n, id) in ids.iter().enumerate() {
        assert_eq!(tree::read(&f, &inf, *id).unwrap(), Some(rec(n as u64 * 512)), "id {id}");
    }
    // Neighbours of a planted id must still be absent: a level index computed
    // one slice off would land every one of these in the same slot.
    for id in [2u32, 254, 257, 0x0001_0001, 0x0102_0305] {
        assert_eq!(tree::read(&f, &inf, id).unwrap(), None, "id {id}");
    }
}

#[test]
fn a_limit_the_revision_cannot_hold_is_refused_before_anything_is_taken() {
    let mut f = image::file(USRQUOTA, Revision::R0, 2);
    let mut inf = info::parse(&f, USRQUOTA).unwrap();
    let mut d = rec(0);
    d.bhardlimit = R0_MAX_SPACE_LIMIT + SPACE_UNIT;
    assert_eq!(tree::write_or_create(&mut f, &mut inf, 7, &d), Err(QuotaError::LimitTooWide));
    assert_eq!(inf.blocks, 2, "a refused write must not grow the file");
    assert_eq!(f.len(), 2 * QT_BLOCK_SIZE);
}

#[test]
fn an_insert_that_fails_below_gives_back_every_block_it_took() {
    let (mut f, mut inf) = empty();
    // A leaf offered as having slots spare, whose header contradicts itself.
    // The insert reaches it only after taking three index blocks.
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    let full = entries_per_block(QT_BLOCK_SIZE, Revision::R1) as u16;
    image::put16(&mut f, image::block_at(5) + DQDH_ENTRIES, full + 1);
    // A far-away identity: nothing on its path exists yet.
    let grown = inf.blocks;
    assert_eq!(
        tree::write_or_create(&mut f, &mut inf, 0x8000_0000, &rec(1)),
        Err(QuotaError::BadEntryCount)
    );
    let leaked = inf.blocks - grown;
    assert_eq!(free_blocks(&f, &inf).len() as u32, leaked, "every block taken came back");
    assert!(leaked > 0, "the failure must happen after something was taken");
}

#[test]
fn a_block_on_the_free_block_list_is_used_before_the_file_grows() {
    let (mut f, mut inf) = empty();
    tree::write_or_create(&mut f, &mut inf, 7, &rec(4096)).unwrap();
    assert!(tree::delete(&mut f, &mut inf, 7).unwrap());
    let freed = free_blocks(&f, &inf);
    assert!(!freed.is_empty(), "the delete gave blocks back");
    let blocks = inf.blocks;
    let len = f.len();
    tree::write_or_create(&mut f, &mut inf, 0x0102_0304, &rec(64)).unwrap();
    assert_eq!(inf.blocks, blocks, "the free list answered before the file end did");
    assert_eq!(f.len(), len);
    assert_eq!(tree::read(&f, &inf, 0x0102_0304).unwrap(), Some(rec(64)));
}

#[test]
fn a_file_with_no_root_block_is_refused_rather_than_grown_into() {
    let mut f = image::file(USRQUOTA, Revision::R1, 1);
    let mut inf = info::parse(&f, USRQUOTA).unwrap();
    assert_eq!(tree::write_or_create(&mut f, &mut inf, 7, &rec(0)), Err(QuotaError::NoRoot));
}

#[test]
fn a_tree_holding_a_reference_where_the_walk_found_none_is_corruption() {
    // The last level's slot for this identity names a leaf that does not hold
    // it: the walk reports a dangling leaf, and the insert must not add a
    // second slot for the same identity beside it.
    let mut f = image::file(USRQUOTA, Revision::R1, 6);
    let mut inf = info::parse(&f, USRQUOTA).unwrap();
    image::plant(&mut f, 5, inf.depth, &[2, 3, 4, 5]);
    image::r1_entry(&mut f, 5, 0, 6, 0, 0, 1, 0, 0, 0, 0, 0);
    assert_eq!(tree::write_or_create(&mut f, &mut inf, 5, &rec(0)), Err(QuotaError::DanglingLeaf));
}
