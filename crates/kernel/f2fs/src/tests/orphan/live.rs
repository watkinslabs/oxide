//! Parking a real inode at its last name and reclaiming it at its eviction.
//!
//! The invariant under test is the one that costs data: losing a name NEVER
//! frees an inode. It goes on the orphan list with its blocks intact and its
//! stored link count at zero, and only the eviction — the last reference, the
//! one point that knows nothing can read it any more — frees it. A volume
//! cannot see who holds a descriptor, so an inode freed here on any reckoning
//! of its own is an inode freed under a reader. Getting this wrong is invisible
//! in memory and only shows against a medium, so every assertion here is
//! against one.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::map::Mapped;
use crate::volume::orphan::block::ORPHANS_PER_BLOCK;
use crate::volume::orphan::block;
use crate::volume::{NewInode, Volume};

pub const NOW: (u64, u32) = (1_800_000_000, 500);

pub fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume with an empty root. # C: O(image bytes)
pub fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// A file holding one full block of real data, so its space is measurable.
/// # C: O(1 block)
pub fn file_with_a_block(v: &mut Volume<MemImage>, name: &[u8]) -> u32 {
    let ino = v.create(ROOT_INO, name, &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![0xAB; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    ino
}

/// Where a file's first block lives. # C: O(depth)
pub fn data_addr(v: &Volume<MemImage>, ino: u32) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block(&inode, ino, 0).unwrap() {
        Mapped::At(a) => a,
        _ => panic!("the fixture file has no block of its own"),
    }
}

/// Take a name away and drop the inode's link for it, which is what `remove`
/// does once the name is gone. # C: O(depth)
fn unlink(v: &mut Volume<MemImage>, name: &[u8]) -> u32 {
    let ino = v.remove_dentry(ROOT_INO, name).unwrap();
    v.drop_nlink(ROOT_INO, ino, false, NOW).unwrap();
    ino
}

// -------------------------------------------------------------- parking

#[test]
fn losing_the_last_name_parks_the_inode_and_frees_nothing() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"gone");
    let addr = data_addr(&v, ino);
    let before = v.valid_inode_count;
    assert_eq!(unlink(&mut v, b"gone"), ino);
    assert!(v.is_orphan(ino));
    assert_eq!(v.orphan_list(), vec![ino]);
    // Still readable, and its block still counted live: a descriptor may hold
    // it, and the volume has no way to know that it does not.
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.links, 0, "the stored link count must reach zero");
    assert!(v.block_is_live(addr).unwrap());
    assert_eq!(v.valid_inode_count, before, "parking must not free the inode");
}

#[test]
fn the_eviction_reclaims_the_parked_inode() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    let addr = data_addr(&v, ino);
    let before = v.valid_inode_count;
    unlink(&mut v, b"held");
    assert_eq!(v.valid_inode_count, before, "parking must not free the inode");
    v.evict_inode(ino).unwrap();
    assert!(!v.is_orphan(ino));
    assert!(v.read_inode(ino).is_err());
    assert!(!v.block_is_live(addr).unwrap());
    assert_eq!(v.valid_inode_count, before - 1);
}

#[test]
fn evicting_a_file_that_still_has_a_name_frees_nothing() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"live");
    let addr = data_addr(&v, ino);
    v.evict_inode(ino).unwrap();
    assert!(v.read_inode(ino).is_ok());
    assert!(v.block_is_live(addr).unwrap());
    assert!(!v.is_orphan(ino));
}

#[test]
fn an_unparked_inode_survives_its_eviction() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    unlink(&mut v, b"held");
    assert!(v.unpark_orphan(ino));
    assert!(!v.unpark_orphan(ino), "unparking twice reports the second as a no-op");
    v.evict_inode(ino).unwrap();
    assert!(v.read_inode(ino).is_ok(), "a name came back, so nothing frees it");
}

#[test]
fn a_removal_is_refused_while_the_list_is_full_and_leaves_the_name_alone() {
    // The reservation is taken before the entry comes out. Taken after, a full
    // list leaves an inode that can be neither parked nor reached, with its
    // blocks still counted live and nothing recording the debt.
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"victim");
    let full = v.max_orphans();
    // The list itself is what has to be full; the numbers on it need not exist.
    for i in 0..full as u32 { v.add_orphan(ROOT_INO + 1_000 + i).unwrap(); }
    assert_eq!(v.remove(ROOT_INO, b"victim", false, NOW).err(), Some(Errno::Enospc));
    let root = v.read_inode(ROOT_INO).unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"victim").unwrap().ino, ino,
               "a refused removal must leave the name where it was");
    assert_eq!(v.read_inode(ino).unwrap().links, 1);
}

#[test]
fn releasing_an_inode_that_was_never_parked_does_nothing() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"live");
    v.release_orphan(ino).unwrap();
    assert!(v.read_inode(ino).is_ok());
}

#[test]
fn a_read_only_mount_parks_nothing() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.add_orphan(9), Err(syscall::errno::Errno::Erofs));
    assert!(v.orphan_list().is_empty());
}

// ------------------------------------------------------------ the list

#[test]
fn the_list_is_reported_in_inode_order() {
    let mut v = vol();
    for ino in [40u32, 7, 19] { v.add_orphan(ino).unwrap(); }
    assert_eq!(v.orphan_list(), vec![7, 19, 40]);
    assert!(v.is_orphan(19));
    assert!(!v.is_orphan(20));
}

#[test]
fn parking_the_same_inode_twice_lists_it_once() {
    let mut v = vol();
    v.add_orphan(11).unwrap();
    v.add_orphan(11).unwrap();
    assert_eq!(v.orphan_list(), vec![11]);
}

#[test]
fn the_pack_reserves_blocks_as_the_list_grows() {
    let mut v = vol();
    assert_eq!(v.orphan_blocks(), 0);
    v.add_orphan(5).unwrap();
    assert_eq!(v.orphan_blocks(), 1);
    for ino in 6..40u32 { v.add_orphan(ino).unwrap(); }
    assert_eq!(v.orphan_blocks(), 1);
    for ino in 100..100 + ORPHANS_PER_BLOCK as u32 { v.add_orphan(ino).unwrap(); }
    assert_eq!(v.orphan_blocks(), 2);
}

#[test]
fn the_flag_word_tracks_the_list() {
    let mut v = vol();
    assert_eq!(v.orphan_flag(CP_ORPHAN_PRESENT_FLAG) & CP_ORPHAN_PRESENT_FLAG, 0);
    v.add_orphan(5).unwrap();
    assert_ne!(v.orphan_flag(0) & CP_ORPHAN_PRESENT_FLAG, 0);
    v.unpark_orphan(5);
    assert_eq!(v.orphan_flag(CP_ORPHAN_PRESENT_FLAG) & CP_ORPHAN_PRESENT_FLAG, 0);
}

#[test]
fn parking_marks_the_volume_for_a_checkpoint() {
    let mut v = vol();
    v.commit().unwrap();
    assert!(!v.is_dirty());
    v.add_orphan(5).unwrap();
    assert!(v.is_dirty(), "a list only in memory is a list a crash loses");
}

#[test]
fn the_cap_is_the_volumes_own_geometry() {
    let v = vol();
    let sb = v.super_block();
    assert_eq!(v.max_orphans(), block::max_orphans(sb.blks_per_seg(), sb.cp_payload));
    assert!(v.max_orphans() > 0);
}

// ----------------------------------------------------- what is written down

#[test]
fn the_list_is_laid_down_where_a_reader_will_look_for_it() {
    let mut v = vol();
    for ino in [21u32, 8, 34] { v.add_orphan(ino).unwrap(); }
    let at = scratch_pack_start(&v) + 1;
    v.write_orphans(at).unwrap();
    let back = block::decode(&v.read_block(at).unwrap()).unwrap();
    assert_eq!(back.inos, vec![8, 21, 34]);
    assert_eq!(back.index, 1);
    assert_eq!(back.count, 1);
}

#[test]
fn a_list_too_long_for_one_block_is_laid_down_across_two() {
    let mut v = vol();
    let n = ORPHANS_PER_BLOCK as u32 + 3;
    for ino in 10..10 + n { v.add_orphan(ino).unwrap(); }
    assert_eq!(v.orphan_blocks(), 2);
    let at = scratch_pack_start(&v) + 1;
    v.write_orphans(at).unwrap();
    let first = block::decode(&v.read_block(at).unwrap()).unwrap();
    let second = block::decode(&v.read_block(at + 1).unwrap()).unwrap();
    assert_eq!(first.inos.len(), ORPHANS_PER_BLOCK);
    assert_eq!(second.inos.len(), 3);
    assert_eq!((first.index, first.count), (1, 2));
    assert_eq!((second.index, second.count), (2, 2));
    let mut all: Vec<u32> = first.inos;
    all.extend_from_slice(&second.inos);
    assert_eq!(all, (10..10 + n).collect::<Vec<u32>>());
}

#[test]
fn an_empty_list_lays_down_nothing() {
    let mut v = vol();
    let at = scratch_pack_start(&v) + 1;
    let before = v.read_block(at).unwrap();
    v.write_orphans(at).unwrap();
    assert_eq!(v.read_block(at).unwrap(), before);
}

/// The first block of the pack that is NOT current, which is scratch space a
/// test may write into without disturbing the mount. # C: O(1)
fn scratch_pack_start(v: &Volume<MemImage>) -> u32 {
    let sb = v.super_block();
    match v.checkpoint().pack {
        crate::checkpoint::Pack::First => sb.cp_blkaddr + sb.blks_per_seg(),
        crate::checkpoint::Pack::Second => sb.cp_blkaddr,
    }
}

#[test]
fn a_name_coming_back_takes_the_inode_off_the_orphan_list() {
    // The shape `linkat` of an unnamed file produces: an inode whose last name
    // is gone, then a new name for it. Left parked, the next checkpoint records
    // it as an orphan and the mount after that frees a file that has a name.
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"tmp", &spec(), None).unwrap();
    v.remove(ROOT_INO, b"tmp", false, NOW).unwrap();
    assert!(v.is_orphan(ino), "the fixture never parked it");
    v.link(ROOT_INO, b"named", ino, NOW).unwrap();
    assert!(!v.is_orphan(ino), "the inode is still parked after its name came back");
}
