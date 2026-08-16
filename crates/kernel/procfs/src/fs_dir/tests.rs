//! `/proc/fs` registration contract. The tree is process-global, so each test
//! claims a filesystem name of its own.

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::VfsError;

use super::{claim, fs_names, is_claimed, names_in, proc_fs_root, publish_dir, publish_file,
            release, withdraw, ShowFn};

fn body(text: &'static str) -> ShowFn { Arc::new(move || Ok(text.as_bytes().to_vec())) }

fn read_all(path: &str) -> Option<Vec<u8>> {
    let inode = proc_fs_root().lookup_path(path)?;
    let mut buf = [0u8; 256];
    let n = inode.read(0, &mut buf).ok()?;
    Some(buf[..n].to_vec())
}

#[test]
fn proc_fs_is_a_directory_inside_the_procfs_registry() {
    let root = super::proc_fs_root();
    assert_eq!(root.path(), "/fs");
    assert!(crate::reg::proc_reg().lookup_dir("fs").is_some());
}

#[test]
fn a_claim_creates_the_directory_and_is_listed() {
    claim("claimpfs").expect("claim");
    assert!(is_claimed("claimpfs"));
    assert!(fs_names().iter().any(|n| n == "claimpfs"));
    assert!(proc_fs_root().lookup_dir("claimpfs").is_some());
    release("claimpfs").expect("release");
    assert!(!is_claimed("claimpfs"));
    assert!(proc_fs_root().lookup_dir("claimpfs").is_none());
}

#[test]
fn a_second_claim_of_one_name_is_refused() {
    claim("duppfs").expect("first claim");
    assert_eq!(claim("duppfs"), Err(VfsError::Eexist));
    release("duppfs").expect("release");
}

#[test]
fn publishing_into_an_unclaimed_filesystem_is_refused() {
    assert_eq!(publish_dir("neverpfs", "sda"), Err(VfsError::Enoent));
    assert_eq!(publish_file("neverpfs", "", "x", 0o444, body("1\n")), Err(VfsError::Enoent));
}

#[test]
fn a_published_file_is_readable_at_its_path() {
    claim("readpfs").expect("claim");
    publish_file("readpfs", "vda", "disk_map", 0o444, body("SB : 0/1024B\n")).expect("publish");
    assert_eq!(read_all("readpfs/vda/disk_map").as_deref(), Some(&b"SB : 0/1024B\n"[..]));
    release("readpfs").expect("release");
}

#[test]
fn a_withdrawn_mount_directory_leaves_the_others_intact() {
    claim("umountpfs").expect("claim");
    publish_file("umountpfs", "vda", "segment_info", 0o444, body("a\n")).expect("vda");
    publish_file("umountpfs", "vdb", "segment_info", 0o444, body("b\n")).expect("vdb");
    assert_eq!(names_in("umountpfs", "").expect("list"), ["vda", "vdb"]);

    withdraw("umountpfs", "vda").expect("withdraw");

    assert_eq!(names_in("umountpfs", "").expect("list"), ["vdb"]);
    assert!(proc_fs_root().lookup_path("umountpfs/vda/segment_info").is_none());
    assert_eq!(read_all("umountpfs/vdb/segment_info").as_deref(), Some(&b"b\n"[..]));
    release("umountpfs").expect("release");
}

#[test]
fn a_component_that_would_escape_the_filesystem_is_refused() {
    claim("escapepfs").expect("claim");
    assert_eq!(publish_dir("escapepfs", ".."), Err(VfsError::Einval));
    assert_eq!(publish_dir("escapepfs", "a/../b"), Err(VfsError::Einval));
    assert_eq!(publish_file("escapepfs", "", "..", 0o444, body("x")), Err(VfsError::Einval));
    assert_eq!(claim("bad/name"), Err(VfsError::Einval));
    release("escapepfs").expect("release");
}

#[test]
fn withdrawing_the_whole_filesystem_root_is_refused_release_is_the_way() {
    claim("wholepfs").expect("claim");
    assert_eq!(withdraw("wholepfs", ""), Err(VfsError::Einval));
    release("wholepfs").expect("release");
}

#[test]
fn releasing_a_name_nobody_claimed_is_enoent() {
    assert_eq!(release("ghostpfs"), Err(VfsError::Enoent));
}

/// Every published file gets its own inode number: the superblock cache keys
/// on it, so a shared number serves one file's bytes from the other's inode.
#[test]
fn published_files_have_distinct_inode_numbers() {
    claim("inopfs").expect("claim");
    publish_file("inopfs", "vda", "one", 0o444, body("1\n")).expect("one");
    publish_file("inopfs", "vda", "two", 0o444, body("2\n")).expect("two");
    let a = proc_fs_root().lookup_path("inopfs/vda/one").expect("one").ino();
    let b = proc_fs_root().lookup_path("inopfs/vda/two").expect("two").ino();
    assert_ne!(a, b);
    assert!(vfs::pseudo_ino::PROCFS_DYNAMIC.contains(a));
    assert!(vfs::pseudo_ino::PROCFS_DYNAMIC.contains(b));
    release("inopfs").expect("release");
}
