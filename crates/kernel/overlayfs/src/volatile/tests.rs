//! The live-image root composition: an immutable lower layer, a writable
//! upper, and the guarantee that nothing a write does reaches the image.

extern crate alloc;


use vfs::fs::FileSystem;
use vfs::inode_ops::CreateCtx;
use vfs::types::S_IFREG;

use crate::testfs::{layer, lookup, mkfile, mkpath, slurp};

/// A composed root over a lower layer carrying `etc/issue`, plus the two
/// directories a volatile upper layer supplies.
fn composed() -> (vfs::InodeRef, vfs::InodeRef, alloc::sync::Arc<crate::OverlayFs>) {
    let lower = layer(1);
    mkfile(&lower, "etc/issue", b"oxide\n");
    let volatile = layer(2);
    let upper = mkpath(&volatile, "upper");
    let work = mkpath(&volatile, "work");
    let fs = super::volatile_over(lower.clone(), upper.clone(), work)
        .expect("compose a volatile root");
    (lower, upper, fs)
}

#[test]
fn the_composed_root_is_an_overlay_and_is_writable() {
    let (_, _, fs) = composed();
    assert_eq!(fs.name(), crate::FS_NAME);
    assert!(fs.writable());
}

#[test]
fn the_image_is_visible_through_the_composed_root() {
    let (_, _, fs) = composed();
    let issue = lookup(&fs.root_inode(), "etc/issue").expect("etc/issue is visible");
    assert_eq!(slurp(&issue), b"oxide\n".to_vec());
}

#[test]
fn a_new_file_lands_on_the_upper_layer_and_not_on_the_image() {
    let (lower, upper, fs) = composed();
    let etc = fs.root_inode().lookup("etc").expect("etc");
    etc.create_child("machine-id", S_IFREG as u32 | 0o644, &CreateCtx::root())
        .expect("create on a volatile root");
    assert!(lookup(&upper, "etc/machine-id").is_some(), "the write landed on the upper layer");
    assert!(lookup(&lower, "etc/machine-id").is_none(), "the image was not touched");
}

#[test]
fn writing_an_image_file_copies_it_up_and_leaves_the_image_alone() {
    let (lower, upper, fs) = composed();
    let issue = lookup(&fs.root_inode(), "etc/issue").unwrap();
    issue.write(0, b"local").expect("write through the overlay");
    // A write is not a truncate: the copy-up carries the image's bytes first,
    // so what is left past the written range is what the image held.
    assert_eq!(slurp(&lookup(&upper, "etc/issue").expect("copied up")), b"local\n".to_vec());
    assert_eq!(slurp(&lookup(&lower, "etc/issue").unwrap()), b"oxide\n".to_vec());
}

/// The one layer refusal the composition can still make: the option-name
/// disjointness check cannot see through opaque labels, but a layer that is
/// not a directory is refused when it is resolved.
#[test]
fn an_upper_layer_that_is_not_a_directory_is_refused() {
    let lower = layer(1);
    mkfile(&lower, "etc/issue", b"oxide\n");
    let volatile = layer(2);
    let not_a_dir = mkfile(&volatile, "upper", b"");
    let work = mkpath(&volatile, "work");
    assert_eq!(super::volatile_over(lower, not_a_dir, work).err(),
        Some(syscall::errno::Errno::Enotdir));
}
