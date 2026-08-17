//! The NODE mapping: nodes changed here and placed later, keyed by node id.
//!
//! The property under test is that a node's ADDRESS IS CHOSEN AT WRITEBACK.
//! A node changed four times between two flushes costs one block, not four;
//! until the flush the mapping is the only copy of it, and the node table says
//! the node is present with no address yet. Every test names, in its own
//! comment, the line that turns it red.

use alloc::vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, NEW_ADDR, NULL_ADDR};
use syscall::errno::Errno;

use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A writable volume holding one empty file, quiesced. # C: O(image)
fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.sync_data().unwrap();
    (v, ino)
}

/// Live blocks the segment table counts across the whole main area.
/// # C: O(main segments)
fn live(v: &mut Volume<MemImage>) -> u32 {
    v.load_segments().unwrap();
    (0..v.sb.segment_count_main).map(|s| u32::from(v.seg_valid(s))).sum()
}

// -------------------------------------------------------------- the deferral

#[test]
fn a_node_changed_four_times_before_a_flush_costs_one_block() {
    // The whole point. Reverting `write_node` to allocate would make this four.
    let (mut v, ino) = with_file();
    let before = live(&mut v);
    for i in 0..4u64 { v.stamp_inode(ino, move |b| b[crate::uapi::I_ATIME] = i as u8).unwrap(); }
    assert_eq!(v.dirty_node_pages(), 1, "the four changes are not one page");
    v.sync_data().unwrap();
    // One block taken for the new copy, one released for the old, so the live
    // count is where it started — and it would have moved four times.
    assert_eq!(live(&mut v), before, "the node was placed more than once");
}

#[test]
fn a_node_changed_and_not_placed_still_names_its_old_block_and_reads_back_new() {
    // A change moves nothing on the medium: the table still names the block
    // the node used to occupy, and the mapping holds what it says now. A read
    // that consulted the table first would answer with the OLD contents.
    let (mut v, ino) = with_file();
    let was = v.node_addr(ino).unwrap();
    v.stamp_inode(ino, |b| b[crate::uapi::I_ADVISE] = 0x5a).unwrap();
    assert_eq!(v.node_addr(ino).unwrap(), was, "the node was placed at once");
    assert_eq!(v.read_node(ino, Some(ino)).unwrap().block[crate::uapi::I_ADVISE], 0x5a,
               "the read did not see the change");
    // And the medium still holds the old copy, which is what makes this a
    // deferral rather than a rewrite in place.
    assert_ne!(v.read_main_block(was).unwrap()[crate::uapi::I_ADVISE], 0x5a);
    v.sync_data().unwrap();
    assert_ne!(v.node_addr(ino).unwrap(), was, "placing it did not move the block");
}

#[test]
fn a_node_created_and_not_placed_reads_as_present_with_no_address() {
    // The marker the table carries for a node that exists and has not been
    // written. A node id in that state must still resolve to its bytes.
    let (mut v, ino) = with_file();
    let nid = v.alloc_nid().unwrap();
    let mut block = vec![0u8; BLKSIZE];
    crate::volume::dnode::set_node_ofs(&mut block, 1);
    v.write_node(nid, ino, block, crate::volume::curseg::Kind::FileNode).unwrap();
    assert_eq!(v.node_addr(nid).unwrap(), NEW_ADDR, "a new node was given an address");
    assert_eq!(v.read_node(nid, Some(ino)).unwrap().footer.nid, nid);
}

#[test]
fn a_flush_gives_every_changed_node_a_real_address() {
    // The invariant the checkpoint depends on: the node table must never
    // record the no-address marker, because the next mount reads it as a node
    // that is not there.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![7u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert_eq!(v.dirty_node_pages(), 0, "a node was left in the mapping");
    let addr = v.node_addr(ino).unwrap();
    assert_ne!(addr, NEW_ADDR);
    assert_ne!(addr, NULL_ADDR);
    assert!(v.sb.valid_main_blkaddr(addr), "the node's address is not a main block");
}

#[test]
fn a_checkpoint_places_every_node_before_it_writes_the_table() {
    // A remount reads only what the medium holds, so a node left in the
    // mapping at checkpoint time is a node the next mount cannot resolve.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![3u8; 2 * BLKSIZE]).unwrap();
    v.commit().unwrap();
    assert_eq!(v.dirty_node_pages(), 0);
    let bytes = v.source_ref().snapshot();
    let v2 = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                crate::opts::Options::defaults(), true).unwrap();
    let i = v2.read_inode(ino).unwrap();
    assert_eq!(v2.read_whole(&i, ino).unwrap(), vec![3u8; 2 * BLKSIZE]);
}

// --------------------------------------------------------------- the keying

#[test]
fn the_mapping_is_keyed_by_node_id_and_two_nodes_do_not_collide() {
    // Keyed by nid, as the reference keys it. A mapping keyed by block address
    // would lose one of these the moment the other moved.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let a = v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    assert_ne!(a, b);
    v.sync_data().unwrap();
    v.stamp_inode(a, |x| x[crate::uapi::I_ADVISE] = 1).unwrap();
    v.stamp_inode(b, |x| x[crate::uapi::I_ADVISE] = 2).unwrap();
    assert_eq!(v.dirty_node_pages(), 2, "two nodes share one page");
    assert_eq!(v.read_node(a, Some(a)).unwrap().block[crate::uapi::I_ADVISE], 1);
    assert_eq!(v.read_node(b, Some(b)).unwrap().block[crate::uapi::I_ADVISE], 2);
}

#[test]
fn a_released_node_leaves_no_page_behind_for_the_next_holder_of_its_id() {
    // A node id is handed out again. A page left under it would answer for
    // whatever node next takes the id — with another file's bytes.
    let (mut v, ino) = with_file();
    v.stamp_inode(ino, |b| b[crate::uapi::I_ADVISE] = 0x33).unwrap();
    assert!(v.peek_node(ino).is_some(), "the change was not filed");
    v.release_node(ino).unwrap();
    assert!(v.peek_node(ino).is_none(), "the released node kept its page");
}

// ------------------------------------------------------- the placement rules

#[test]
fn the_log_a_node_goes_to_is_read_off_its_own_footer() {
    // There is no caller at writeback to say which log a node belongs in, so
    // the block carries it. A dnode of a file is warm, a dnode of a directory
    // is hot, an indirection node is cold — the reference's own encoding.
    use crate::volume::curseg::{node_kind_of, stamp_node_temp, Kind};
    use crate::volume::recover::marks;
    let mut block = vec![0u8; BLKSIZE];
    crate::volume::dnode::set_node_ofs(&mut block, 1);
    stamp_node_temp(&mut block, Kind::FileNode);
    let f = crate::node::footer::parse(&block).unwrap();
    assert_eq!(node_kind_of(&f), Kind::FileNode);
    stamp_node_temp(&mut block, Kind::DirNode);
    let f = crate::node::footer::parse(&block).unwrap();
    assert_eq!(node_kind_of(&f), Kind::DirNode);
    // An offset that names a node holding node ids is an indirection node
    // whatever the mark says.
    crate::volume::dnode::set_node_ofs(&mut block, 3);
    stamp_node_temp(&mut block, Kind::FileNode);
    let f = crate::node::footer::parse(&block).unwrap();
    assert!(!marks::is_dnode(f.ofs_of_node()));
    assert_eq!(node_kind_of(&f), Kind::IndirectNode);
}

#[test]
fn the_temperature_stamp_leaves_the_recovery_marks_alone() {
    // The flag word carries the node's offset and the two recovery marks
    // beside the temperature. Stamping the whole word instead of the one bit
    // would write a chain the next mount reads as a different chain.
    use crate::volume::curseg::{stamp_node_temp, Kind};
    use crate::volume::recover::marks;
    let mut block = vec![0u8; BLKSIZE];
    marks::set_flag(&mut block, marks::flag_word(7, true, true, false));
    stamp_node_temp(&mut block, Kind::FileNode);
    let f = crate::node::footer::parse(&block).unwrap();
    assert_eq!(f.ofs_of_node(), 7);
    assert!(f.is_fsync() && f.is_dent() && f.is_cold());
}

#[test]
fn an_inodes_checksum_survives_the_footer_being_finished_at_writeback() {
    // The checkpoint version and the forward pointer are stamped when the
    // block is placed, long after the inode was sealed. Covering the footer
    // would make every deferred inode fail its own checksum — and would
    // disagree with the value any other implementation computes.
    let mut block = vec![0u8; BLKSIZE];
    for (i, b) in block.iter_mut().enumerate() { *b = i as u8; }
    let seed = 0x1234_5678u32;
    let before = crate::checksum::inode_chksum(seed, &block).unwrap();
    let at = crate::uapi::NODE_FOOTER_OFF;
    block[at + crate::uapi::FOOTER_CP_VER..at + crate::uapi::FOOTER_CP_VER + 8].fill(0xee);
    block[at + crate::uapi::FOOTER_NEXT_BLKADDR..at + crate::uapi::FOOTER_NEXT_BLKADDR + 4]
        .fill(0xdd);
    assert_eq!(crate::checksum::inode_chksum(seed, &block).unwrap(), before,
               "the footer is inside what the inode's checksum covers");
}

#[test]
fn an_out_of_line_attribute_node_carries_its_own_reserved_offset() {
    // Left at zero the attribute node claims to BE the inode: a replay reads
    // it as one, and the log it belongs in — which is now read off the block —
    // is decided by that same offset.
    use crate::volume::recover::marks;
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.big", Some(&vec![7u8; 1024]), false, false).unwrap();
    let nid = v.read_inode(ino).unwrap().xattr_nid;
    assert_ne!(nid, 0, "no attribute node was made, so the case proves nothing");
    let f = v.read_node(nid, Some(ino)).unwrap().footer;
    assert_eq!(f.ofs_of_node(), marks::xattr_node_offset(),
               "the attribute node claims to be the inode");
}

// ------------------------------------------------------------- the unwinding

#[test]
fn a_node_the_tree_could_not_reach_strands_no_block() {
    // What `undo_new_node` used to have to clean up: a node written to the
    // medium and then orphaned by a failed link. Nothing is written now, so
    // the unwind is the id and the counts and nothing else.
    let (mut v, ino) = with_file();
    let before = live(&mut v);
    let nid = v.alloc_nid().unwrap();
    v.write_node(nid, ino, vec![0u8; BLKSIZE], crate::volume::curseg::Kind::FileNode).unwrap();
    assert_eq!(live(&mut v), before, "the new node took a block before it was linked");
    v.undo_new_node(ino, nid).unwrap();
    assert_eq!(live(&mut v), before);
    assert!(v.peek_node(nid).is_none(), "the undone node kept its page");
    v.sync_data().unwrap();
    assert_eq!(live(&mut v), before, "the undone node was placed anyway");
}

// ------------------------------------------------------- the placed-one page

#[test]
fn a_node_placed_one_at_a_time_stays_cached_and_is_not_read_back_off_the_medium() {
    // `writeback_node` used to INVALIDATE the page it had just placed, because
    // there was no way to tell the layer below that a page it still called
    // dirty had already been written. The bytes it dropped are the node's
    // current bytes, so the next read of an fsync'd node went to the device
    // for what the mount was already holding.
    //
    // The device read is what is asserted, and it is asserted so that it can
    // fail: the medium's copy of the block is OVERWRITTEN with a byte pattern
    // no valid node can carry, so a read that reaches the device cannot come
    // back with the right contents — it comes back with a footer that does not
    // name this node, which is an `EIO`. Restoring the `forget` call turns the
    // `unwrap` below into a panic.
    let (mut v, ino) = with_file();
    v.stamp_inode(ino, |b| b[crate::uapi::I_ADVISE] = 0x77).unwrap();
    assert_eq!(v.dirty_node_pages(), 1, "the change was not left in the mapping");
    let misses = v.node_cache_misses();

    v.write_fsync_chain(ino, false).unwrap();
    assert_eq!(v.dirty_node_pages(), 0, "the placed node is still dirty");
    let addr = v.node_addr(ino).unwrap();
    assert_ne!(addr, NEW_ADDR, "the node was not placed at all");
    v.source.poke(addr as usize * BLKSIZE, &vec![0xff; BLKSIZE]);

    let back = v.read_node(ino, Some(ino)).unwrap();
    assert_eq!(back.block[crate::uapi::I_ADVISE], 0x77,
               "the placed node came back from the poisoned medium");
    assert_eq!(v.node_cache_misses(), misses,
               "the placed node was read off the medium instead of the mapping");
}

#[test]
fn placing_one_node_leaves_the_rest_of_the_mapping_dirty() {
    // The one-page entry point claims exactly the index it was given. A claim
    // that took the whole mapping would place nodes in an order this caller
    // did not choose, which is the entire reason it does not use the batch.
    let (mut v, ino) = with_file();
    let other = v.alloc_nid().unwrap();
    let mut block = vec![0u8; BLKSIZE];
    crate::volume::dnode::set_node_ofs(&mut block, 1);
    v.write_node(other, ino, block, crate::volume::curseg::Kind::FileNode).unwrap();
    v.stamp_inode(ino, |b| b[crate::uapi::I_ADVISE] = 0x11).unwrap();
    assert_eq!(v.dirty_node_pages(), 2, "the fixture is not two dirty nodes");
    v.writeback_node(ino).unwrap();
    assert_eq!(v.dirty_node_pages(), 1, "the named node was not the only one placed");
    assert_eq!(v.node_addr(other).unwrap(), NEW_ADDR, "the other node was placed too");
}

// ----------------------------------------------------------------- the drain

#[test]
fn the_node_drain_runs_until_the_mapping_is_clean_however_many_passes_it_takes() {
    // A fixed pass count and a run-to-clean loop are indistinguishable on
    // every workload that converges in one pass, which is every workload this
    // filesystem has — so the bound is asserted on the decision itself.
    // Reinstating `for _ in 0..8` turns this red.
    let left = core::cell::Cell::new(20usize);
    let mut passes = 0usize;
    crate::volume::nodeback::drain_nodes(
        || left.get(),
        || { left.set(left.get() - 1); passes += 1; None }).unwrap();
    assert_eq!(passes, 20, "the drain gave up before the mapping was clean");
}

#[test]
fn the_node_drain_stops_at_the_first_pass_that_reports() {
    // Never a spin on a mapping that cannot be written: an erroring pass ends
    // the loop with its own errno, not with a count exhausted.
    let mut passes = 0usize;
    let err = crate::volume::nodeback::drain_nodes(|| 1, || { passes += 1; Some(Errno::Eio) })
        .unwrap_err();
    assert_eq!(err, Errno::Eio);
    assert_eq!(passes, 1, "the drain kept going after a failure");
}

// ---------------------------------------------------------------- the counts

#[test]
fn a_node_not_yet_placed_is_already_counted_against_the_volume() {
    // A window in which a promised node is uncounted is a window in which the
    // volume says it has room it has already given away.
    let (mut v, ino) = with_file();
    let before = v.valid_block_count;
    let nid = v.alloc_nid().unwrap();
    v.write_node(nid, ino, vec![0u8; BLKSIZE], crate::volume::curseg::Kind::FileNode).unwrap();
    assert_eq!(v.valid_block_count, before + 1, "the promised node was not counted");
    v.sync_data().unwrap();
    assert_eq!(v.valid_block_count, before + 1, "placing it counted it twice");
}
