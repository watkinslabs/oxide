//! `/sys/fs` registration contract.
//!
//! The tree these drive is process-global, so each test claims a subsystem
//! name of its own rather than sharing one.

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{KResult, VfsError};

use super::{claim, fs_root, is_claimed, names_in, publish_attr, publish_dir, release,
            subsys_names, withdraw, ShowFn};

fn body(text: &'static str) -> ShowFn { Arc::new(move || Ok(text.as_bytes().to_vec())) }

fn read_all(path: &str) -> Option<Vec<u8>> {
    let inode = fs_root().lookup_path(path)?;
    let mut buf = [0u8; 256];
    let n = inode.read(0, &mut buf).ok()?;
    Some(buf[..n].to_vec())
}

#[test]
fn a_claim_creates_the_directory_and_is_visible_in_the_listing() {
    claim("claimfs").expect("claim");
    assert!(is_claimed("claimfs"));
    assert!(subsys_names().iter().any(|n| n == "claimfs"));
    assert!(fs_root().lookup_dir("claimfs").is_some());
    release("claimfs").expect("release");
    assert!(!is_claimed("claimfs"));
}

#[test]
fn a_second_claim_of_one_name_is_refused() {
    claim("dupfs").expect("first claim");
    assert_eq!(claim("dupfs"), Err(VfsError::Eexist));
    release("dupfs").expect("release");
}

#[test]
fn publishing_into_an_unclaimed_subsystem_is_refused() {
    assert_eq!(publish_dir("neverfs", "sda"), Err(VfsError::Enoent));
    assert_eq!(publish_attr("neverfs", "", "x", 0o444, body("1\n"), None),
               Err(VfsError::Enoent));
}

#[test]
fn a_published_attribute_is_readable_at_its_path() {
    claim("readfs").expect("claim");
    publish_attr("readfs", "vda/stat", "cp_status", 0o444, body("3\n"), None).expect("publish");
    assert_eq!(read_all("readfs/vda/stat/cp_status").as_deref(), Some(&b"3\n"[..]));
    release("readfs").expect("release");
}

#[test]
fn a_withdrawn_mount_directory_leaves_the_subsystem_intact() {
    claim("umountfs").expect("claim");
    publish_attr("umountfs", "vda", "features", 0o444, body("a\n"), None).expect("publish vda");
    publish_attr("umountfs", "vdb", "features", 0o444, body("b\n"), None).expect("publish vdb");
    assert_eq!(names_in("umountfs", "").expect("list"), ["vda", "vdb"]);

    withdraw("umountfs", "vda").expect("withdraw");

    assert_eq!(names_in("umountfs", "").expect("list"), ["vdb"]);
    assert!(fs_root().lookup_path("umountfs/vda/features").is_none());
    assert_eq!(read_all("umountfs/vdb/features").as_deref(), Some(&b"b\n"[..]));
    release("umountfs").expect("release");
}

#[test]
fn withdrawing_the_whole_subsystem_root_is_refused_release_is_the_way() {
    claim("wholefs").expect("claim");
    assert_eq!(withdraw("wholefs", ""), Err(VfsError::Einval));
    release("wholefs").expect("release");
    assert!(fs_root().lookup_dir("wholefs").is_none());
}

#[test]
fn a_component_that_would_escape_the_subsystem_is_refused() {
    claim("escapefs").expect("claim");
    assert_eq!(publish_dir("escapefs", ".."), Err(VfsError::Einval));
    assert_eq!(publish_dir("escapefs", "a/../b"), Err(VfsError::Einval));
    assert_eq!(publish_attr("escapefs", "", "..", 0o444, body("x"), None),
               Err(VfsError::Einval));
    assert_eq!(claim("bad/name"), Err(VfsError::Einval));
    release("escapefs").expect("release");
}

#[test]
fn an_empty_directory_can_be_published_without_attributes() {
    claim("emptyfs").expect("claim");
    publish_dir("emptyfs", "tuning").expect("publish dir");
    assert_eq!(names_in("emptyfs", "tuning").expect("list"), Vec::<alloc::string::String>::new());
    assert!(fs_root().lookup_dir("emptyfs/tuning").is_some());
    release("emptyfs").expect("release");
}

#[test]
fn releasing_a_name_nobody_claimed_is_enoent() {
    let r: KResult<()> = release("ghostfs");
    assert_eq!(r, Err(VfsError::Enoent));
}
