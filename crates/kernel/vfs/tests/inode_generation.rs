//! `Inode::i_generation` (Linux `struct inode::i_generation`). Before this the
//! trait exposed no VFS generation number, so `name_to_handle_at(2)` FIDs and
//! NFS file handles could not pack `(i_ino, i_generation)` to reject a stale
//! handle to a freed-and-recycled inode. This proves: the default is `0` (a
//! pseudo-fs that never recycles a number), and an FS that stamps a generation
//! reports it verbatim.

use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Inode that stamps an on-disk generation (ext4-style).
struct GenFile { ino: u64, gen: u32 }
impl Inode for GenFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn i_generation(&self) -> u32 { self.gen }
}

/// Inode with no generation (the trait default).
struct Plain;
impl Inode for Plain {
    fn ino(&self) -> vfs::Ino { 9 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Trait default `i_generation()` is `0` (pseudo-fs that never recycles a no.).
#[test]
fn default_generation_zero() {
    assert_eq!(Plain.i_generation(), 0);
}

/// A backend that stores a generation reports it verbatim — the value a FID
/// packs alongside `i_ino` to detect a recycled inode.
#[test]
fn stored_generation_reported() {
    let f = GenFile { ino: 12, gen: 0xDEAD_BEEF };
    assert_eq!(f.i_generation(), 0xDEAD_BEEF);
    // Distinct generations distinguish two inodes that reuse one number across
    // delete+reallocate — the whole point of the field.
    let g = GenFile { ino: 12, gen: 0x0000_0001 };
    assert_eq!(f.ino(), g.ino());
    assert_ne!(f.i_generation(), g.i_generation());
}
