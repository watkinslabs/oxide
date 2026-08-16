//! The cached shape of an open handle, brought back in line with the medium.
//!
//! A handle keeps only the inode NUMBER, so everything it presents is read
//! fresh — except the length and the block count, which the interface caches
//! on the object it handed out. Those two are what a write and a truncate
//! change underneath it, and they do not move together: converting an inline
//! file out gives it a block without changing a byte of its length.

use vfs::{FileOps, InodeBuilder, InodeOps};

use alloc::sync::Arc;
use alloc::vec;

use crate::mode::S_IFREG;
use crate::mount::node::{apply_shape, blocks_reported};
use crate::mount::ops::F2fsOps;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::NewInode;

const NOW: (u64, u32) = (1_800_000_000, 0);

/// An interface inode carrying the shape `live` has right now.
fn cached(ino: u32, live: &crate::node::Inode) -> vfs::InodeRef {
    let inode_ops: Arc<dyn InodeOps> = Arc::new(F2fsOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(F2fsOps);
    InodeBuilder::new(u64::from(ino), vfs::mk_mode(vfs::FileType::Regular, 0o644), inode_ops,
                      file_ops)
        .size(live.size)
        .blocks(blocks_reported(live.blocks))
        .build()
}

#[test]
fn an_inline_file_converting_out_changes_the_count_without_changing_the_length() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    v.write_file(ino, 0, b"x").unwrap();
    let inline = v.read_inode(ino).unwrap();
    assert!(inline.inline_data(), "the fixture's file is not inline to begin with");
    let handle = cached(ino, &inline);
    assert_eq!(handle.blocks(), 0, "an inline file occupies no block of its own");

    // Past the inline region: the bytes leave the inode for a block.
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    let live = v.read_inode(ino).unwrap();
    assert!(!live.inline_data(), "the file did not convert out");
    apply_shape(&handle, &live);
    assert_eq!(handle.size(), live.size, "the cached length is still the inline one");
    assert!(handle.blocks() > 0, "the cached count still says the file occupies nothing");
    assert_eq!(handle.blocks(), blocks_reported(live.blocks));
}

#[test]
fn shortening_a_file_lowers_the_cached_count_as_well_as_the_length() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 4 * BLKSIZE]).unwrap();
    let grown = v.read_inode(ino).unwrap();
    let handle = cached(ino, &grown);
    let was = handle.blocks();
    assert!(was > 0, "the fixture's file occupies nothing");
    v.truncate_file(ino, 0).unwrap();
    apply_shape(&handle, &v.read_inode(ino).unwrap());
    assert_eq!(handle.size(), 0);
    assert!(handle.blocks() < was, "the cached count survived the truncate");
}
