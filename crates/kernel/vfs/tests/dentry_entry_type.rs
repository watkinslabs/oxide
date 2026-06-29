//! dcache-D13: DCACHE_ENTRY_TYPE — the inode's `S_IFMT` class is stamped into
//! `d_flags` at the moment an inode is associated (`Dentry::new*` / `set_inode`),
//! so the hot path (`d_is_dir` in the walker, `d_is_symlink` before a symlink
//! follow) branches on the dentry WITHOUT read-locking + dereferencing `d_inode`.
//! Mirrors Linux `__d_set_inode_and_type` + the `d_is_*` family.

use std::sync::Arc;

use vfs::{Dentry, FileType, InodeRef};

fn inode(ft: FileType) -> InodeRef {
    vfs::InodeBuilder::new(1, vfs::mk_mode(ft, 0o644), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}
fn dentry(ft: FileType) -> Arc<Dentry> { Dentry::new(None, String::from("x"), inode(ft)) }

#[test]
fn directory_type_is_cached() {
    let d = dentry(FileType::Directory);
    assert!(d.d_is_dir(), "dir dentry caches DIRECTORY type");
    assert!(d.d_can_lookup(), "a directory can be descended into");
    assert!(d.d_is_positive(), "positive dentry");
    assert!(!d.d_is_miss(), "not a miss");
    assert!(!d.d_is_reg() && !d.d_is_symlink() && !d.d_is_special(), "exactly one type");
}

#[test]
fn regular_type_is_cached() {
    let d = dentry(FileType::Regular);
    assert!(d.d_is_reg(), "regular file caches REGULAR type");
    assert!(!d.d_is_dir() && !d.d_can_lookup(), "regular file is not a directory");
}

#[test]
fn symlink_type_is_cached() {
    let d = dentry(FileType::Symlink);
    assert!(d.d_is_symlink(), "symlink caches SYMLINK type");
    assert!(!d.d_is_dir() && !d.d_is_reg() && !d.d_is_special(), "exactly one type");
}

#[test]
fn special_types_fold_to_special() {
    for ft in [FileType::CharDev, FileType::BlockDev, FileType::Fifo, FileType::Socket] {
        let d = dentry(ft);
        assert!(d.d_is_special(), "char/block/fifo/socket fold to SPECIAL");
        assert!(!d.d_is_dir() && !d.d_is_reg() && !d.d_is_symlink(), "exactly one type");
    }
}

#[test]
fn negative_dentry_is_miss_type() {
    let d = Dentry::new_negative(None, String::from("absent"));
    assert!(d.d_is_miss(), "negative dentry caches MISS type");
    assert!(!d.d_is_positive(), "miss is not positive");
    assert!(!d.d_is_dir() && !d.d_is_reg() && !d.d_is_symlink() && !d.d_is_special(), "no concrete type");
}

#[test]
fn set_inode_restamps_type_on_transition() {
    // Negative → directory → negative → regular, type bits follow each flip.
    let d = Dentry::new_negative(None, String::from("flip"));
    assert!(d.d_is_miss(), "starts as miss");

    d.set_inode(Some(inode(FileType::Directory)));
    assert!(d.d_is_dir(), "negative→positive(dir) restamps DIRECTORY type");
    assert!(!d.d_is_miss(), "no longer a miss");

    d.set_inode(None);
    assert!(d.d_is_miss(), "positive→negative restamps MISS type");
    assert!(!d.d_is_dir(), "directory type cleared");

    d.set_inode(Some(inode(FileType::Regular)));
    assert!(d.d_is_reg() && !d.d_is_dir(), "negative→positive(reg) restamps REGULAR type");
}

#[test]
fn type_bits_do_not_clobber_root_flag() {
    // A superblock root that is a directory keeps D_ROOT AND caches DIRECTORY.
    let r = Dentry::new_root(inode(FileType::Directory));
    assert!(r.is_root(), "D_ROOT preserved alongside the type stamp");
    assert!(r.d_is_dir(), "root directory caches DIRECTORY type");
}
