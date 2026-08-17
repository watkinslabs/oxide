//! The free-id cache, driven against a real volume.
//!
//! The failure this can produce is the worst one the allocator has: handing
//! out a node id something is already using, so one file's node is written
//! over another's. Every check here is a way that could happen.
//!
//! The dangerous case is a table block read from the MEDIUM. The medium is
//! behind: an id this mount has taken, or replayed out of a crash tail, still
//! reads as free there until a checkpoint says otherwise. So a scan of that
//! block believes the wrong thing, and only folding in what the journal and
//! this mount's own unwritten changes say puts it right.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// Every id this mount is holding as free, in the order it would hand them out.
fn free_ids(v: &Volume<MemImage>) -> Vec<u32> { v.free_nids.free_order() }

#[test]
fn no_id_the_cache_holds_free_is_one_a_live_node_is_using() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let mut made = Vec::new();
    for i in 0..12u32 {
        let name = [b'f', b'0' + (i % 10) as u8, b'a' + (i / 10) as u8];
        made.push(v.create(ROOT_INO, &name, &spec(), None).unwrap());
        for held in free_ids(&v) {
            assert!(!made.contains(&held),
                    "id {held} is held free while a node is using it");
        }
    }
}

/// A rebuild after ids have been taken must not put them back. The table block
/// on the medium still calls them free, so the only thing that can say
/// otherwise is what this mount is holding.
#[test]
fn a_rebuild_does_not_offer_back_an_id_this_mount_has_taken() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let mut made = Vec::new();
    for i in 0..6u32 {
        let name = [b'f', b'0' + i as u8];
        made.push(v.create(ROOT_INO, &name, &spec(), None).unwrap());
    }
    v.build_free_nids().unwrap();
    for held in free_ids(&v) {
        assert!(!made.contains(&held), "a rebuild offered back the live id {held}");
    }
}

/// The case the medium cannot help with. A file created and made durable, then
/// a crash: the node is on the medium and the table entry for it is not, so
/// the recovered mount's FIRST table scan reads the id as free while a live
/// inode holds it. Handing it out again gives two inodes one number.
#[test]
fn an_id_recovered_from_a_crash_tail_is_never_handed_out_again() {
    let (mut v, first, _) = crate::volume::recover::fixture::checkpointed(b"a");
    let late = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.write_file(late, 0, &vec![5u8; BLKSIZE]).unwrap();
    v.fsync(late).unwrap();
    // The medium now holds the node; nothing has checkpointed the table.
    let mut v = crate::volume::recover::fixture::crash(v);
    assert!(v.read_inode(late).is_ok(), "the fixture did not recover the late file");
    // Every id the cache is prepared to hand out, after a rebuild that reads
    // the very block the recovered inode lives in.
    v.build_free_nids().unwrap();
    for held in free_ids(&v) {
        assert_ne!(held, late, "the recovered inode's id is being offered as free");
        assert_ne!(held, first, "a checkpointed inode's id is being offered as free");
    }
    // And the allocator agrees: nothing it hands out collides.
    for i in 0..6u32 {
        let name = [b'c', b'0' + i as u8];
        let got = v.create(ROOT_INO, &name, &spec(), None).unwrap();
        assert_ne!(got, late, "the recovered inode's id was handed out");
        assert_ne!(got, first, "a live inode's id was handed out");
    }
}

/// The journal overrides the table in BOTH directions, and the cache has to
/// follow it: an id the journal frees is free whatever the table block says.
#[test]
fn an_id_the_journal_freed_becomes_available_again() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                   crate::opts::Options::defaults(), true).unwrap();
    v.build_free_nids().unwrap();
    assert!(v.nid_is_cached_free(ino), "an id the volume released is not free again");
}

/// The count the report publishes is the count the allocator refuses against,
/// and it moves by exactly one in each direction.
#[test]
fn the_remaining_count_moves_by_one_per_id() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.build_free_nids().unwrap();
    let before = v.free_nid_counts().2;
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert_eq!(v.free_nid_counts().2, before - 1, "creating a file cost more than one id");
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    // The name going parks the inode; the EVICTION is what frees it and
    // gives back what it held. The two are separate events, and a descriptor
    // may sit between them.
    v.evict_inode(ino).unwrap();
    assert_eq!(v.free_nid_counts().2, before, "evicting it did not give the id back");
    assert!(v.nid_is_cached_free(ino));
}
