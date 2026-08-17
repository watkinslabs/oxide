//! Setting and removing extended attributes, proved by remounting.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use crate::xattr::Attr;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 0);

fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    (v, ino)
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn get(v: &Volume<MemImage>, ino: u32, name: &str) -> Result<Vec<u8>, Errno> {
    let inode = v.read_inode(ino)?;
    v.get_xattr(&inode, ino, name)
}

fn names(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.list_xattr(&inode, ino).unwrap()
}

#[test]
fn the_encoding_round_trips_through_the_reader() {
    let attrs = alloc::vec![
        Attr { index: XATTR_INDEX_USER, name: b"a".to_vec(), value: b"1".to_vec() },
        Attr { index: XATTR_INDEX_TRUSTED, name: b"bb".to_vec(), value: b"22".to_vec() },
    ];
    let bytes = encode(&attrs);
    assert_eq!(crate::xattr::list(&bytes).unwrap(), attrs);
}

#[test]
fn the_encoding_ends_with_a_terminator() {
    let bytes = encode(&[]);
    assert_eq!(bytes.len(), XATTR_HEADER_SIZE + XATTR_ENTRY_HEADER);
    assert!(crate::xattr::list(&bytes).unwrap().is_empty());
}

#[test]
fn one_attribute_survives_a_remount() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.colour", Some(b"blue"), false, false).unwrap();
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.colour").unwrap(), b"blue".to_vec());
}

#[test]
fn several_attributes_survive_and_list_in_order() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"1"), false, false).unwrap();
    v.set_xattr(ino, "trusted.b", Some(b"2"), false, false).unwrap();
    v.set_xattr(ino, "security.c", Some(b"3"), false, false).unwrap();
    let v = remount(v);
    assert_eq!(names(&v, ino), b"user.a\0trusted.b\0security.c\0".to_vec());
}

#[test]
fn replacing_a_value_keeps_the_others() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"one"), false, false).unwrap();
    v.set_xattr(ino, "user.b", Some(b"two"), false, false).unwrap();
    v.set_xattr(ino, "user.a", Some(b"CHANGED"), false, false).unwrap();
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.a").unwrap(), b"CHANGED".to_vec());
    assert_eq!(get(&v, ino, "user.b").unwrap(), b"two".to_vec());
}

#[test]
fn a_value_growing_moves_the_records_after_it_without_losing_them() {
    // The records are packed with no free list; patching in place would leave
    // a gap that terminates the walk and lose everything past it.
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"x"), false, false).unwrap();
    v.set_xattr(ino, "user.b", Some(b"keep"), false, false).unwrap();
    v.set_xattr(ino, "user.a", Some(&alloc::vec![b'y'; 60]), false, false).unwrap();
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.a").unwrap(), alloc::vec![b'y'; 60]);
    assert_eq!(get(&v, ino, "user.b").unwrap(), b"keep".to_vec());
}

#[test]
fn removing_one_attribute_keeps_the_rest() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"1"), false, false).unwrap();
    v.set_xattr(ino, "user.b", Some(b"2"), false, false).unwrap();
    v.remove_xattr(ino, "user.a").unwrap();
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.a").err(), Some(Errno::Enodata));
    assert_eq!(get(&v, ino, "user.b").unwrap(), b"2".to_vec());
}

#[test]
fn removing_the_last_attribute_leaves_an_empty_list() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"1"), false, false).unwrap();
    v.remove_xattr(ino, "user.a").unwrap();
    let v = remount(v);
    assert!(names(&v, ino).is_empty());
}

#[test]
fn removing_a_name_that_is_not_there_reports_no_data() {
    let (mut v, ino) = with_file();
    assert_eq!(v.remove_xattr(ino, "user.nope").err(), Some(Errno::Enodata));
}

#[test]
fn creating_over_an_existing_name_is_refused() {
    let (mut v, ino) = with_file();
    v.set_xattr(ino, "user.a", Some(b"1"), false, false).unwrap();
    assert_eq!(v.set_xattr(ino, "user.a", Some(b"2"), true, false).err(), Some(Errno::Eexist));
    assert_eq!(get(&v, ino, "user.a").unwrap(), b"1".to_vec());
}

#[test]
fn replacing_a_name_that_is_not_there_is_refused() {
    let (mut v, ino) = with_file();
    assert_eq!(v.set_xattr(ino, "user.a", Some(b"1"), false, true).err(), Some(Errno::Enodata));
}

#[test]
fn asking_to_both_create_and_replace_is_refused() {
    let (mut v, ino) = with_file();
    assert_eq!(v.set_xattr(ino, "user.a", Some(b"1"), true, true).err(), Some(Errno::Einval));
}

#[test]
fn a_name_under_no_known_prefix_is_refused() {
    let (mut v, ino) = with_file();
    assert_eq!(v.set_xattr(ino, "bogus.a", Some(b"1"), false, false).err(),
               Some(Errno::Eopnotsupp));
}

#[test]
fn a_read_only_mount_refuses_to_set_one() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.set_xattr(ROOT_INO, "user.a", Some(b"1"), false, false).err(),
               Some(Errno::Erofs));
}

#[test]
fn a_list_too_long_for_the_inode_spills_into_a_block_and_still_reads_back() {
    let (mut v, ino) = with_file();
    let big = alloc::vec![b'z'; 180];
    v.set_xattr(ino, "user.one", Some(&big), false, false).unwrap();
    v.set_xattr(ino, "user.two", Some(b"tail"), false, false).unwrap();
    assert_ne!(v.read_inode(ino).unwrap().xattr_nid, 0, "no block was allocated");
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.one").unwrap(), big);
    assert_eq!(get(&v, ino, "user.two").unwrap(), b"tail".to_vec());
}

#[test]
fn a_list_that_shrinks_back_gives_up_its_block() {
    let (mut v, ino) = with_file();
    let big = alloc::vec![b'z'; 180];
    v.set_xattr(ino, "user.one", Some(&big), false, false).unwrap();
    v.set_xattr(ino, "user.two", Some(b"tail"), false, false).unwrap();
    let nid = v.read_inode(ino).unwrap().xattr_nid;
    assert_ne!(nid, 0);
    let addr = v.node_addr(nid).unwrap();
    v.remove_xattr(ino, "user.one").unwrap();
    assert_eq!(v.read_inode(ino).unwrap().xattr_nid, 0, "the block was kept");
    assert!(!v.block_is_live(addr).unwrap(), "the block leaked");
    let v = remount(v);
    assert_eq!(get(&v, ino, "user.two").unwrap(), b"tail".to_vec());
}

#[test]
fn a_value_too_large_for_both_halves_is_refused() {
    let (mut v, ino) = with_file();
    let huge = alloc::vec![b'q'; VALID_XATTR_BLOCK_SIZE + 400];
    assert_eq!(v.set_xattr(ino, "user.huge", Some(&huge), false, false).err(),
               Some(Errno::Enospc));
}

#[test]
fn an_attribute_does_not_disturb_the_files_data() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"payload").unwrap();
    v.set_xattr(ino, "user.a", Some(b"1"), false, false).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), b"payload".to_vec());
    assert_eq!(get(&v, ino, "user.a").unwrap(), b"1".to_vec());
}

#[test]
fn an_attribute_block_is_counted_in_the_files_block_count() {
    let (mut v, ino) = with_file();
    let before = v.read_inode(ino).unwrap().blocks;
    let big = alloc::vec![b'z'; 180];
    v.set_xattr(ino, "user.one", Some(&big), false, false).unwrap();
    v.set_xattr(ino, "user.two", Some(b"tail"), false, false).unwrap();
    let v = remount(v);
    assert!(v.read_inode(ino).unwrap().blocks > before);
}

#[test]
fn unlinking_a_file_frees_its_attribute_block() {
    let (mut v, ino) = with_file();
    let big = alloc::vec![b'z'; 180];
    v.set_xattr(ino, "user.one", Some(&big), false, false).unwrap();
    v.set_xattr(ino, "user.two", Some(b"tail"), false, false).unwrap();
    let nid = v.read_inode(ino).unwrap().xattr_nid;
    let addr = v.node_addr(nid).unwrap();
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    assert!(!v.block_is_live(addr).unwrap(), "the attribute block leaked");
}
