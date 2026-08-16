//! Parking a real inode and reclaiming it at the last close.
//!
//! The distinction under test is the one that costs blocks: an inode nothing
//! holds open is freed the moment its last name goes, and an inode something
//! does hold open must survive with its blocks intact and its stored link
//! count at zero. Getting either direction wrong is invisible in memory and
//! only shows against a medium, so every assertion here is against one.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

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

/// Take a name away and drop the inode's last link, which is what `remove`
/// does once the name is gone. # C: O(depth)
fn unlink(v: &mut Volume<MemImage>, name: &[u8]) -> u32 {
    let ino = v.remove_dentry(ROOT_INO, name).unwrap();
    v.drop_last_link(ino, NOW).unwrap();
    ino
}

// -------------------------------------------------------------- parking

#[test]
fn an_open_inode_is_parked_instead_of_freed() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    let addr = data_addr(&v, ino);
    v.open_inode(ino);
    assert_eq!(unlink(&mut v, b"held"), ino);
    assert!(v.is_orphan(ino));
    assert_eq!(v.orphan_list(), vec![ino]);
    // Still readable through the handle, and its block still counted live.
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.links, 0, "the stored link count must reach zero");
    assert!(v.block_is_live(addr).unwrap());
}

#[test]
fn a_closed_inode_is_freed_at_once() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"gone");
    let addr = data_addr(&v, ino);
    let before = v.valid_inode_count;
    assert_eq!(unlink(&mut v, b"gone"), ino);
    assert!(!v.is_orphan(ino));
    assert!(v.orphan_list().is_empty());
    assert!(v.read_inode(ino).is_err());
    assert!(!v.block_is_live(addr).unwrap());
    assert_eq!(v.valid_inode_count, before - 1);
}

#[test]
fn the_last_close_reclaims_the_parked_inode() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    let addr = data_addr(&v, ino);
    let before = v.valid_inode_count;
    v.open_inode(ino);
    unlink(&mut v, b"held");
    assert_eq!(v.valid_inode_count, before, "parking must not free the inode");
    v.close_inode(ino).unwrap();
    assert!(!v.is_orphan(ino));
    assert!(v.read_inode(ino).is_err());
    assert!(!v.block_is_live(addr).unwrap());
    assert_eq!(v.valid_inode_count, before - 1);
}

#[test]
fn a_close_that_is_not_the_last_keeps_the_inode() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    let addr = data_addr(&v, ino);
    v.open_inode(ino);
    v.open_inode(ino);
    unlink(&mut v, b"held");
    v.close_inode(ino).unwrap();
    assert!(v.is_orphan(ino), "one holder is left");
    assert!(v.read_inode(ino).is_ok());
    assert!(v.block_is_live(addr).unwrap());
    v.close_inode(ino).unwrap();
    assert!(!v.is_orphan(ino));
    assert!(v.read_inode(ino).is_err());
    assert!(!v.block_is_live(addr).unwrap());
}

#[test]
fn closing_something_that_was_never_opened_frees_nothing() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"live");
    v.close_inode(ino).unwrap();
    assert!(v.read_inode(ino).is_ok());
    assert!(!v.is_orphan(ino));
}

#[test]
fn an_unparked_inode_survives_its_last_close() {
    let mut v = vol();
    let ino = file_with_a_block(&mut v, b"held");
    v.open_inode(ino);
    unlink(&mut v, b"held");
    assert!(v.unpark_orphan(ino));
    assert!(!v.unpark_orphan(ino), "unparking twice reports the second as a no-op");
    v.close_inode(ino).unwrap();
    assert!(v.read_inode(ino).is_ok(), "a name came back, so nothing frees it");
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
    // The shape `linkat` of an unnamed file produces: an inode something holds
    // open, its last name gone, then a new name for it. Left parked, the next
    // checkpoint records it as an orphan and the mount after that frees a file
    // that has a name.
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"tmp", &spec(), None).unwrap();
    v.open_inode(ino);
    v.remove(ROOT_INO, b"tmp", false, NOW).unwrap();
    assert!(v.is_orphan(ino), "the fixture never parked it");
    v.link(ROOT_INO, b"named", ino, NOW).unwrap();
    assert!(!v.is_orphan(ino), "the inode is still parked after its name came back");
}
