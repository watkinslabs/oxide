//! Replaying a slot that holds a reservation rather than a block.
//!
//! A generation that reserved room for a write it never made leaves
//! `NEW_ADDR` in the slot. Replay keeps it: a read finds a hole and the next
//! write allocates over it, which is what the crashed generation had promised
//! its caller. What it also has to keep is the ACCOUNT — a reservation is room
//! set aside, so it costs a block against the volume even though it sets no
//! bit in the segment table, and the count has to be given back the moment the
//! slot stops holding one. Charging without releasing leaks the volume's free
//! space; releasing without charging lets two writers be promised one block.

use crate::uapi::*;
use crate::volume::dnode::put32;
use crate::volume::map::Mapped;
use crate::volume::recover::fixture::*;
use crate::volume::recover::marks;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use sectors::MemImage;

/// Put `addr` in the file's second slot the way a crashed generation that had
/// written that slot would leave it.
fn chain_slot(v: &mut Volume<MemImage>, ino: u32, addr: u32) {
    let inode = v.read_inode(ino).expect("inode");
    let mut block = v.inode_bytes(ino).expect("bytes");
    put32(&mut block, inode.addr_base() + 4, addr);
    v.write_chained_node(ino, ino, block, marks::flag_word(0, true, false, true)).expect("node");
}

/// The address the checkpointed file has at its second block.
fn second_block(v: &Volume<MemImage>, ino: u32) -> u32 {
    let inode = v.read_inode(ino).expect("inode");
    let Mapped::At(addr) = v.map_block(&inode, ino, 1).expect("map") else { panic!("block one") };
    addr
}

#[test]
fn a_recovered_reservation_reads_as_a_hole_and_frees_what_it_replaced() {
    let (mut v, ino, _) = checkpointed(b"f");
    let old = second_block(&v, ino);
    chain_slot(&mut v, ino, NEW_ADDR);
    let mut v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(v.map_block(&inode, ino, 1).expect("map"), Mapped::Hole);
    v.load_segments().expect("segments");
    assert!(!v.addr_is_live(old), "the displaced block goes back to the allocator");
}

#[test]
fn a_recovered_reservation_costs_the_volume_the_block_it_holds() {
    // The block it displaced is given back and the reservation takes its
    // place, so the count is where it started — the reservation is holding
    // room for exactly the write the released block used to hold.
    let (mut v, ino, _) = checkpointed(b"f");
    let before = v.checkpoint().valid_block_count;
    chain_slot(&mut v, ino, NEW_ADDR);
    let v = crash(v);
    assert_eq!(v.checkpoint().valid_block_count, before);
}

#[test]
fn a_reservation_over_a_hole_costs_one_block_more() {
    // Nothing is displaced here, so the charge stands alone. A build that did
    // not charge would report the room as free while a writer is promised it.
    let (mut v, ino, _) = checkpointed(b"f");
    v.truncate_file(ino, BLKSIZE as u64).expect("truncate");
    v.commit().expect("commit");
    let before = v.checkpoint().valid_block_count;
    chain_slot(&mut v, ino, NEW_ADDR);
    let v = crash(v);
    assert_eq!(v.checkpoint().valid_block_count, before + 1);
}

#[test]
fn the_segment_table_and_the_count_differ_by_the_reservation() {
    // The two are deliberately not the same number: a reservation occupies no
    // block of the medium, so it is counted and not mapped.
    let (mut v, ino, _) = checkpointed(b"f");
    v.truncate_file(ino, BLKSIZE as u64).expect("truncate");
    v.commit().expect("commit");
    let mut before = crash_ro(v);
    before.load_segments().expect("segments");
    let live: u64 = (0..before.super_block().segment_count_main)
        .map(|s| u64::from(before.seg_valid(s)))
        .sum();
    assert_eq!(live, before.checkpoint().valid_block_count, "no reservation yet");
    let mut v = remount(before.into_source().snapshot(), true);
    chain_slot(&mut v, ino, NEW_ADDR);
    let mut v = crash(v);
    v.load_segments().expect("segments");
    let live: u64 = (0..v.super_block().segment_count_main)
        .map(|s| u64::from(v.seg_valid(s)))
        .sum();
    assert_eq!(live + 1, v.checkpoint().valid_block_count, "one outstanding reservation");
}

#[test]
fn a_reservation_a_later_chain_block_replaces_gives_its_charge_back() {
    // Both halves inside one replay: the first marked block reserves the slot,
    // the second puts a real block in it. The reservation's charge becomes the
    // block's, and the volume is charged once, not twice.
    let (mut v, ino, _) = checkpointed(b"f");
    let old = second_block(&v, ino);
    let before = v.checkpoint().valid_block_count;
    let fresh = v.write_data(ino, 1, false, NULL_ADDR, &alloc::vec![0xC7u8; BLKSIZE])
        .expect("data");
    chain_slot(&mut v, ino, NEW_ADDR);
    chain_slot(&mut v, ino, fresh);
    let mut v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(v.map_block(&inode, ino, 1).expect("map"), Mapped::At(fresh));
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(fresh));
    assert!(!v.addr_is_live(old));
    assert_eq!(v.checkpoint().valid_block_count, before,
               "one block in the slot, charged once");
}

#[test]
fn a_reservation_a_later_chain_block_empties_gives_its_charge_back() {
    let (mut v, ino, _) = checkpointed(b"f");
    let before = v.checkpoint().valid_block_count;
    chain_slot(&mut v, ino, NEW_ADDR);
    chain_slot(&mut v, ino, NULL_ADDR);
    let v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    assert_eq!(v.map_block(&inode, ino, 1).expect("map"), Mapped::Hole);
    assert_eq!(v.checkpoint().valid_block_count, before - 1,
               "the block that was there is gone and nothing holds its room");
}

#[test]
fn a_reservation_the_file_already_had_is_left_where_it_is() {
    // The slot and the recovered block agree, so nothing is charged and
    // nothing is released. Doing either would move the count for a slot that
    // did not change.
    let (mut v, ino, _) = checkpointed(b"f");
    chain_slot(&mut v, ino, NEW_ADDR);
    let mut v = crash(v);
    let before = v.checkpoint().valid_block_count;
    chain_slot(&mut v, ino, NEW_ADDR);
    let v = crash(v);
    assert_eq!(v.checkpoint().valid_block_count, before);
}

#[test]
fn a_block_the_replay_adopts_is_counted_in_the_inode_it_joins() {
    // A crashed generation's block becomes the file's, so it shows in the
    // count the file reports. Left alone, every recovered file goes back with
    // the shape it had before the crash, and a check reports the difference as
    // a leak.
    let (mut v, ino, _) = checkpointed(b"f");
    let before = v.count_blocks(ino).expect("count");
    append_block(&mut v, ino, 0xC3, true);
    let mut v = crash(v);
    let held = v.count_blocks(ino).expect("count");
    assert_eq!(held, before + 1, "the adopted block is not in the tree");
    assert_eq!(v.read_inode(ino).expect("inode").blocks, held,
               "the inode still reports the shape it had before the crash");
}

#[test]
fn a_block_the_replay_adopts_is_charged_to_the_identity_that_owns_it() {
    // The charge can be REFUSED, which fails the replay and with it the mount:
    // putting a volume back with blocks charged to nobody is the state a quota
    // check reports and cannot repair.
    const UID: u32 = 4242;
    const QUOTA_INO: u32 = 9;
    let file = crate::test_image::quota_image::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[crate::volume::quotas::USRQUOTA] = QUOTA_INO;
    let blocks: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    crate::test_image::nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = b.mount_opts(o).expect("mount");
    let owned = NewInode { mode: crate::mode::S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0,
                           now: NOW };
    let ino = v.create(ROOT_INO, b"f", &owned, None).expect("create");
    v.write_file(ino, 0, &pattern(0x5A)).expect("write");
    v.commit().expect("commit");
    let before = v.quota_record(crate::volume::quotas::USRQUOTA, UID).expect("record").curspace;
    append_block(&mut v, ino, 0xC3, true);
    let mut v = crash(v);
    let after = v.quota_record(crate::volume::quotas::USRQUOTA, UID).expect("record").curspace;
    assert_eq!(after, before + BLKSIZE as u64, "the adopted block was charged to nobody");
}
