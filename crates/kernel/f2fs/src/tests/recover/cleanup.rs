//! A replay that fails part way leaves nothing behind.
//!
//! The failure is injected at the MEDIUM, which is where a real one comes
//! from: every node the replay changes goes into the node mapping and is
//! placed by the checkpoint that closes recovery, so the first write the pass
//! makes is that checkpoint's — and a pass that fails there has already
//! rewritten every node it was going to.
//!
//! What is asserted is that none of that work can reach the medium afterwards.
//! It is asserted on the mappings and the tables rather than on the image,
//! because the image is unchanged either way: the damage a leak does happens
//! at the NEXT flush, whether this mount's or the machine's.

use crate::fault::{Fault, Which};
use alloc::vec;
use crate::opts::Options;
use crate::volume::recover::fixture::{checkpointed, grow_and_fsync};

/// A writable volume whose chain is still standing, ready to be replayed by
/// hand. Declining the roll-forward is what leaves the tail there; the mount
/// would otherwise have replayed it already.
/// # C: O(1 image)
fn with_a_standing_chain() -> crate::volume::Volume<sectors::MemImage> {
    let (mut v, ino, _) = checkpointed(b"f");
    grow_and_fsync(&mut v, ino, 0xC3);
    let bytes = v.into_source().snapshot();
    crate::volume::Volume::mount_with(
        sectors::MemImage::from_bytes(crate::uapi::BLKSIZE as u32, bytes),
        Options { recovery: false, ..Options::defaults() },
        true,
    )
    .expect("remount over the standing chain")
}

/// Fail every write to the medium. The replay's own changes are all deferred,
/// so the first one is the closing checkpoint's.
/// # C: O(1)
fn fail_the_medium(v: &crate::volume::Volume<sectors::MemImage>) {
    v.set_fault(1, 0, Which::RATE).unwrap();
    v.set_fault(0, Fault::WriteIo.bit(), Which::TYPE).unwrap();
}

#[test]
fn a_replay_that_cannot_finish_leaves_no_dirty_node_behind() {
    let mut v = with_a_standing_chain();
    fail_the_medium(&v);
    assert!(v.recover().is_err(), "the injected failure did not reach the replay");
    // The nodes are the whole of what a replay produces, and every one of them
    // was dirty when the checkpoint failed. Left there, this mount's next
    // checkpoint would publish a half-replayed file, and the machine's flusher
    // would write them whether or not this mount is still around.
    assert_eq!(v.dirty_node_pages(), 0, "a failed replay left dirty nodes behind");
}

#[test]
fn a_replay_that_cannot_finish_leaves_no_table_change_behind() {
    let mut v = with_a_standing_chain();
    fail_the_medium(&v);
    assert!(v.recover().is_err());
    // `nat_dirty` beats the journal and the table on every read, so an entry
    // left here points a node id at a block the replay chose and never wrote.
    assert!(v.nat_dirty.is_empty(), "a failed replay left node-table changes behind");
    // The segment table carried live-marks for every block of the chain. Kept,
    // they would hold blocks out of the allocator's reach for the life of the
    // mount and disagree with the medium about how many are free.
    assert!(v.sit.is_none(), "the segment table was kept after a failed replay");
    assert!(v.sit_dirty.is_empty(), "a failed replay left segment-table changes behind");
}

#[test]
fn a_replay_that_cannot_finish_owes_no_checkpoint() {
    let mut v = with_a_standing_chain();
    fail_the_medium(&v);
    assert!(v.recover().is_err());
    // A checkpoint written from here would publish the tables the failure
    // abandoned.
    assert!(!v.dirty, "a failed replay still owes a checkpoint");
}

#[test]
fn a_replay_that_succeeds_is_not_treated_as_a_failure() {
    // The other direction, and the reason it is worth a test of its own: a
    // cleanup that ran on the way out of a SUCCESSFUL pass would throw away
    // the checkpoint's own state and lose the replay it had just completed.
    let mut v = with_a_standing_chain();
    let out = v.recover().expect("the replay must succeed with nothing injected");
    assert!(matches!(out, crate::volume::recover::Recovery::Replayed(_)), "{out:?}");
    let inode = v.read_inode(v.root_ino()).unwrap();
    let e = v.lookup(&inode, v.root_ino(), b"f").expect("the file survived the replay");
    let f = v.read_inode(e.ino).unwrap();
    assert_eq!(f.size, (crate::volume::recover::fixture::BODY + crate::uapi::BLKSIZE) as u64,
               "the replayed block is not in the file");
}

#[test]
fn a_replayed_volume_can_be_mounted_again_without_reusing_the_chain_log() {
    let mut v = with_a_standing_chain();
    let out = v.recover().expect("the replay must succeed");
    assert!(matches!(out, crate::volume::recover::Recovery::Replayed(_)));
    let root = v.read_inode(v.root_ino()).expect("root inode");
    let entry = v.lookup(&root, v.root_ino(), b"f").expect("replayed file");
    let ino = entry.ino;
    let tail = vec![0xD4; crate::uapi::BLKSIZE];
    let size = v.read_inode(ino).expect("replayed inode").size;
    v.write_file(ino, size, &tail).expect("write after replay");
    v.fsync(ino).expect("fsync after replay");

    let image = v.into_source().snapshot();
    let second = crate::volume::Volume::mount_with(
        sectors::MemImage::from_bytes(crate::uapi::BLKSIZE as u32, image),
        crate::opts::Options::defaults(), true,
    ).expect("second mount");
    let root = second.read_inode(second.root_ino()).expect("second root");
    let entry = second.lookup(&root, second.root_ino(), b"f").expect("second file");
    let inode = second.read_inode(entry.ino).expect("second inode");
    let bytes = second.read_whole(&inode, entry.ino).expect("second contents");
    assert_eq!(&bytes[bytes.len() - crate::uapi::BLKSIZE..], &tail[..]);
}
