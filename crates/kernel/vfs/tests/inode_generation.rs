//! `Inode::i_generation` (Linux `struct inode::i_generation`). Before this the
//! trait exposed no VFS generation number, so `name_to_handle_at(2)` FIDs and
//! NFS file handles could not pack `(i_ino, i_generation)` to reject a stale
//! handle to a freed-and-recycled inode. This proves: the default is `0` (a
//! pseudo-fs that never recycles a number), and an FS that stamps a generation
//! reports it verbatim.

use vfs::inode::InodeBuilder;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef};

/// Inode that stamps an on-disk generation (ext4-style).
fn gen_file(ino: u64, generation: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .generation(generation).build()
}

/// Inode with no generation (the builder default).
fn plain() -> InodeRef {
    InodeBuilder::new(9, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Default `i_generation()` is `0` (pseudo-fs that never recycles a no.).
#[test]
fn default_generation_zero() {
    assert_eq!(plain().i_generation(), 0);
}

/// A backend that stores a generation reports it verbatim — the value a FID
/// packs alongside `i_ino` to detect a recycled inode.
#[test]
fn stored_generation_reported() {
    let f = gen_file(12, 0xDEAD_BEEF);
    assert_eq!(f.i_generation(), 0xDEAD_BEEF);
    // Distinct generations distinguish two inodes that reuse one number across
    // delete+reallocate — the whole point of the field.
    let g = gen_file(12, 0x0000_0001);
    assert_eq!(f.ino(), g.ino());
    assert_ne!(f.i_generation(), g.i_generation());
}
