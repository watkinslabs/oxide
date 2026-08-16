//! What changed since the checkpoint, and which sync has to care.
//!
//! The comparison is the whole mechanism, so it is tested twice: once on two
//! blocks alone, where every field can be moved in isolation, and once against
//! a live volume, where the question is whether the real writing paths move
//! the fields the comparison expects them to. The second is the one that
//! catches a data write which leaves no trace in the inode at all.

use super::*;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::dnode::{put32, put64};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 7);
const LATER: (u64, u32) = (1_800_000_099, 3);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

// --------------------------------------------------------- two blocks alone

fn blocks() -> (Vec<u8>, Vec<u8>) { (vec![0u8; BLKSIZE], vec![0u8; BLKSIZE]) }

#[test]
fn two_identical_blocks_are_clean() {
    let (a, b) = blocks();
    let d = block_dirty(&a, &b, true);
    assert!(d.clean());
    assert!(!d.needs_sync(false));
    assert!(!d.needs_sync(true));
}

#[test]
fn a_moved_time_is_metadata_and_nothing_else() {
    let (a, mut b) = blocks();
    put64(&mut b, I_MTIME, LATER.0);
    put32(&mut b, I_MTIME_NSEC, LATER.1);
    let d = block_dirty(&a, &b, true);
    assert_eq!(d, Dirty { data: false, meta: true });
    assert!(d.needs_sync(false), "a full sync owes the caller the time");
    assert!(!d.needs_sync(true), "a data sync does not");
}

#[test]
fn every_stored_time_counts_as_metadata() {
    for at in [I_ATIME, I_CTIME, I_MTIME, I_ATIME_NSEC, I_CTIME_NSEC, I_MTIME_NSEC] {
        let (a, mut b) = blocks();
        b[at] = 0x5A;
        assert_eq!(block_dirty(&a, &b, true), Dirty { data: false, meta: true },
                   "field at {at}");
    }
}

#[test]
fn the_mode_and_the_two_identities_count_as_metadata() {
    for at in [I_MODE, I_UID, I_GID] {
        let (a, mut b) = blocks();
        b[at] = 0x11;
        assert_eq!(block_dirty(&a, &b, true), Dirty { data: false, meta: true },
                   "field at {at}");
    }
}

#[test]
fn a_changed_length_is_data() {
    let (a, mut b) = blocks();
    put64(&mut b, I_SIZE, 4096);
    let d = block_dirty(&a, &b, true);
    assert_eq!(d, Dirty { data: true, meta: false });
    assert!(d.needs_sync(true), "a data sync owes the caller the length");
}

#[test]
fn a_changed_address_is_data() {
    let (a, mut b) = blocks();
    put32(&mut b, OFFSET_OF_END_OF_I_EXT + 16, 0x1234);
    assert!(block_dirty(&a, &b, true).data);
}

#[test]
fn a_changed_node_id_is_data() {
    let (a, mut b) = blocks();
    put32(&mut b, I_NID_OFF, 42);
    assert!(block_dirty(&a, &b, true).data);
}

#[test]
fn both_sides_can_be_dirty_at_once() {
    let (a, mut b) = blocks();
    put64(&mut b, I_SIZE, 4096);
    put64(&mut b, I_MTIME, LATER.0);
    assert_eq!(block_dirty(&a, &b, true), Dirty { data: true, meta: true });
}

#[test]
fn the_footer_is_not_compared() {
    // Every block written out of place gets a new forward pointer and a new
    // flag word. Comparing them would report every file as changed.
    let (a, mut b) = blocks();
    b[NODE_FOOTER_OFF + FOOTER_NEXT_BLKADDR] = 0x77;
    b[NODE_FOOTER_OFF + FOOTER_FLAG] = 0x0E;
    assert!(block_dirty(&a, &b, true).clean());
}

#[test]
fn the_checksum_is_not_compared_where_it_is_the_checksum() {
    // It covers the whole block, so it differs whenever anything does and
    // would make every metadata change look like a data change.
    let (a, mut b) = blocks();
    put32(&mut b, I_INODE_CHECKSUM, 0xDEAD_BEEF);
    assert!(block_dirty(&a, &b, true).clean());
}

#[test]
fn the_checksum_slot_is_compared_where_it_is_an_address() {
    // Without the extra-attribute region those four bytes are one of the
    // file's own block addresses, and skipping them would hide a write.
    let (a, mut b) = blocks();
    put32(&mut b, I_INODE_CHECKSUM, 0xDEAD_BEEF);
    assert!(block_dirty(&a, &b, false).data);
}

// ------------------------------------------------------------ a live volume

/// A volume with one checkpointed file of two blocks, which is the state in
/// which nothing is dirty.
fn checkpointed() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_opts(Options::defaults()).expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).expect("create");
    v.write_file(ino, 0, &vec![0x5A; 2 * BLKSIZE]).expect("write");
    v.commit().expect("commit");
    (v, ino)
}

#[test]
fn a_checkpointed_file_is_clean() {
    let (v, ino) = checkpointed();
    assert!(v.inode_dirty(ino).expect("dirty").clean());
}

#[test]
fn a_write_dirties_the_data_side() {
    let (mut v, ino) = checkpointed();
    v.write_file(ino, 0, b"x").expect("write");
    assert!(v.inode_dirty(ino).expect("dirty").data);
}

#[test]
fn a_time_change_dirties_only_the_metadata_side() {
    let (mut v, ino) = checkpointed();
    v.set_times(ino, LATER, LATER).expect("times");
    assert_eq!(v.inode_dirty(ino).expect("dirty"), Dirty { data: false, meta: true });
}

#[test]
fn a_mode_change_dirties_only_the_metadata_side() {
    let (mut v, ino) = checkpointed();
    v.set_attr(ino, Some(0o600), None, LATER).expect("attr");
    assert_eq!(v.inode_dirty(ino).expect("dirty"), Dirty { data: false, meta: true });
}

#[test]
fn a_checkpoint_makes_the_file_clean_again() {
    let (mut v, ino) = checkpointed();
    v.write_file(ino, 0, b"x").expect("write");
    v.commit().expect("commit");
    assert!(v.inode_dirty(ino).expect("dirty").clean());
}

#[test]
fn an_inode_the_checkpoint_never_saw_is_dirty_on_both_sides() {
    let (mut v, _) = checkpointed();
    let fresh = v.create(ROOT_INO, b"g", &spec(), None).expect("create");
    assert_eq!(v.inode_dirty(fresh).expect("dirty"), Dirty { data: true, meta: true });
}

/// The first file index that cannot be reached from the inode's own array, so
/// its address lives in a direct node instead.
fn first_indexed_index(v: &Volume<MemImage>, ino: u32) -> u64 {
    v.read_inode(ino).expect("inode").addrs_per_inode() as u64
}

#[test]
fn an_overwrite_that_leaves_the_inode_alone_is_still_data() {
    // The failure this guards: rewriting a block moves it, which rewrites the
    // direct node holding its address and leaves the inode's own bytes saying
    // nothing new. Read off the inode alone the write is invisible, and a data
    // sync would return having written nothing.
    let (mut v, ino) = checkpointed();
    let index = first_indexed_index(&v, ino);
    let at = index * BLKSIZE as u64;
    v.write_file(ino, at, &vec![0x11; BLKSIZE]).expect("write");
    v.commit().expect("commit");
    assert!(v.inode_dirty(ino).expect("clean").clean());
    v.write_file(ino, at, &vec![0x22; BLKSIZE]).expect("overwrite");
    let d = v.inode_dirty(ino).expect("dirty");
    assert!(d.data, "a node below the inode was written");
    assert!(d.needs_sync(true));
}

#[test]
fn the_two_table_predicates_answer_different_questions() {
    let (mut v, ino) = checkpointed();
    assert!(v.node_is_checkpointed(ino));
    assert!(!v.node_written_since_checkpoint(ino));
    v.write_file(ino, 0, b"x").expect("write");
    assert!(v.node_is_checkpointed(ino), "a rewrite does not unmake the node");
    assert!(v.node_written_since_checkpoint(ino));
    let fresh = v.create(ROOT_INO, b"h", &spec(), None).expect("create");
    assert!(!v.node_is_checkpointed(fresh), "the checkpoint has never heard of it");
    assert!(v.node_written_since_checkpoint(fresh));
}
