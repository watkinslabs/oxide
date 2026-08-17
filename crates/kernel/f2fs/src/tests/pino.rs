//! The recorded parent, written by every dentry add and proved by REMOUNTING.
//!
//! The field names the directory the newest name for an inode lives in. It is
//! not decoration: a checker reads it, and a roll-forward replay restores a
//! directory entry FROM it, so a stale one puts a file back under a name that is
//! not where the field says. Written at creation only — which is what this did —
//! it goes stale the moment a second name is added or the first one moves.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::{S_IFDIR, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 500);

fn spec(mode: u16) -> NewInode {
    NewInode { mode, uid: 1000, gid: 1000, rdev: 0, now: NOW }
}

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// Commit and mount the bytes again: the field has to be on the MEDIUM, since
/// the replay that reads it runs on a volume nothing has in memory.
/// # C: O(image bytes)
fn remount(v: Volume<MemImage>) -> Volume<MemImage> {
    let mut v = v;
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn pino(v: &Volume<MemImage>, ino: u32) -> u32 { v.read_inode(ino).unwrap().pino }

#[test]
fn a_second_name_in_another_directory_becomes_the_recorded_parent() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    let f = v.create(a, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(pino(&v, f), a, "creation must record the directory it was made in");
    v.link(b, b"g", f, NOW).unwrap();
    assert_eq!(pino(&v, f), b, "the newest name's directory is what the field must say");
    let v = remount(v);
    assert_eq!(pino(&v, f), b, "the field reached memory and not the medium");
}

#[test]
fn a_link_within_one_directory_records_that_directory() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let f = v.create(a, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.link(a, b"second", f, NOW).unwrap();
    assert_eq!(pino(&v, f), a);
    assert_eq!(v.read_inode(f).unwrap().links, 2, "the fixture did not make a hard link");
}

#[test]
fn a_new_directorys_own_two_entries_are_not_names_for_anything() {
    // `.` points at the directory itself and `..` at its parent. Recorded as
    // names, the first makes a directory its own parent and the second makes
    // the PARENT a child of the directory it just gained — the field then sends
    // a checker, and a replay, up a cycle.
    let mut v = vol();
    let root_pino_before = pino(&v, ROOT_INO);
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(pino(&v, a), ROOT_INO, "the new directory's parent is the root");
    assert_eq!(pino(&v, ROOT_INO), root_pino_before,
               "the child's `..` entry was recorded as a name for the root");
    let sub = v.create(a, b"sub", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(pino(&v, sub), a);
    assert_eq!(pino(&v, a), ROOT_INO, "`sub`'s `..` entry overwrote its parent's field");
}

#[test]
fn a_name_landing_in_a_directory_whose_entries_are_inline_records_it_too() {
    // The two layouts are separate code paths and only one of them used to reach
    // the inode at all. A small directory's entries live inside its own inode.
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    assert!(v.read_inode(a).unwrap().inline_dentry(), "the fixture directory is not inline");
    let f = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.link(a, b"named", f, NOW).unwrap();
    assert_eq!(pino(&v, f), a);
}

#[test]
fn a_name_landing_in_a_directory_grown_past_its_inode_records_it_too() {
    // The other layout: enough names to force the directory out of its inode.
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let mut names: Vec<Vec<u8>> = Vec::new();
    for i in 0..200u32 { names.push(alloc::format!("pad{i:04}").into_bytes()); }
    for n in &names { v.create(a, n, &spec(S_IFREG | 0o644), None).unwrap(); }
    assert!(!v.read_inode(a).unwrap().inline_dentry(), "the directory never left its inode");
    let f = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.link(a, b"named", f, NOW).unwrap();
    assert_eq!(pino(&v, f), a);
}

#[test]
fn a_moved_file_records_the_directory_it_moved_into() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(ROOT_INO, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    let f = v.create(a, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    let r = crate::volume::Rename {
        from: a, old: b"f", to: b, new: b"f", flags: 0, owner: (0, 0), now: NOW,
    };
    v.rename(&r).unwrap();
    assert_eq!(pino(&v, f), b);
    // A moved file's field is ALSO marked untrustworthy, because its old name is
    // gone: a replay that rebuilt the entry from the stored name would put the
    // file back under a name nothing has. The two are not alternatives.
    assert!(v.read_inode(f).unwrap().advise & crate::flags::FADVISE_LOST_PINO_BIT != 0,
            "the moved file's recorded name was left presented as trustworthy");
}
