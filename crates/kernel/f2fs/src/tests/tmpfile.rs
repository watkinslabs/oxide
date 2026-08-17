//! An inode no name reaches: what it looks like on the medium, and what
//! happens to it when it is named, closed, or left behind by a crash.

use super::*;
use crate::mode::{S_IFDIR, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 500);

fn spec(mode: u16) -> NewInode {
    NewInode { mode, uid: 1000, gid: 1000, rdev: 0, now: NOW }
}

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

fn remount(v: Volume<MemImage>) -> Volume<MemImage> {
    let mut v = v;
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

#[test]
fn a_temporary_file_has_no_name_and_no_links() {
    let mut v = vol();
    let ino = v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.links, 0);
    assert_eq!(inode.mode, S_IFREG | 0o600);
    assert_eq!(inode.pino, ROOT_INO);
    // Nothing in the directory it was created under names it.
    let root = v.read_inode(ROOT_INO).unwrap();
    let named = v.read_dir(&root, ROOT_INO).unwrap();
    assert!(named.iter().all(|e| e.ino != ino), "an unnamed file was found by name");
}

#[test]
fn a_temporary_file_is_parked_so_a_crash_cannot_lose_it() {
    let mut v = vol();
    let ino = v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).unwrap();
    assert!(v.is_orphan(ino));
    // The list is written into the checkpoint, so the next mount reclaims it.
    let v = remount(v);
    assert!(!v.is_orphan(ino), "the mount did not reclaim the parked inode");
    assert_eq!(v.read_inode(ino).err(), Some(Errno::Enoent));
}

#[test]
fn a_temporary_file_can_be_written_and_read_back() {
    let mut v = vol();
    let ino = v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).unwrap();
    v.write_file(ino, 0, b"unnamed bytes").unwrap();
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 13];
    assert_eq!(v.read_file(&inode, ino, 0, &mut buf).unwrap(), 13);
    assert_eq!(&buf, b"unnamed bytes");
}

#[test]
fn naming_a_temporary_file_takes_it_off_the_list() {
    let mut v = vol();
    let ino = v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).unwrap();
    v.write_file(ino, 0, b"kept").unwrap();
    v.link(ROOT_INO, b"named", ino, NOW).unwrap();
    assert!(!v.is_orphan(ino));
    assert_eq!(v.read_inode(ino).unwrap().links, 1);
    let v = remount(v);
    // Named before the checkpoint, so the mount must NOT reclaim it.
    let root = v.read_inode(ROOT_INO).unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"named").unwrap().ino, ino);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(v.read_file(&inode, ino, 0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"kept");
}

#[test]
fn closing_the_last_handle_frees_a_temporary_file() {
    let mut v = vol();
    let inodes_before = v.valid_inode_count;
    let ino = v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).unwrap();
    v.write_file(ino, 0, b"gone soon").unwrap();
    assert_eq!(v.valid_inode_count, inodes_before + 1);
    // The hold the creation took is the last one, so this is the close that
    // frees it — the reclaim does NOT wait for the next mount.
    v.close_inode(ino).unwrap();
    assert!(!v.is_orphan(ino));
    assert_eq!(v.read_inode(ino).err(), Some(Errno::Enoent));
    assert_eq!(v.valid_inode_count, inodes_before);
}

#[test]
fn a_temporary_directory_is_refused() {
    let mut v = vol();
    assert_eq!(v.tmpfile(ROOT_INO, &spec(S_IFDIR | 0o755)).err(), Some(Errno::Eisdir));
}

#[test]
fn a_temporary_file_under_something_that_is_not_a_directory_is_refused() {
    let mut v = vol();
    let f = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.tmpfile(f, &spec(S_IFREG | 0o600)).err(), Some(Errno::Enotdir));
}

#[test]
fn a_read_only_mount_makes_no_temporary_file() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.tmpfile(ROOT_INO, &spec(S_IFREG | 0o600)).err(), Some(Errno::Erofs));
}
