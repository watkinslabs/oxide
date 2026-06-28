//! `Inode::i_flags` + S_IMMUTABLE write-deny in the default `permission`
//! op (Linux `inode_permission`: "Nobody gets write access to an immutable
//! file" — checked BEFORE the DAC class check, so not even CAP_DAC_OVERRIDE
//! bypasses it). Synthetic inodes carrying explicit flags — no real FS.

use std::sync::Arc;

use vfs::inode::{Inode, S_APPEND, S_IMMUTABLE};
use vfs::{Cred, FileType, InodeRef, VfsError};
use vfs::{MAY_EXEC, MAY_READ, MAY_WRITE};

/// Regular file, world-rwx perm, owned by uid 0, with a settable `i_flags`.
struct FlagFile { flags: u32 }
impl Inode for FlagFile {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o777) }
    fn uid(&self) -> Option<u32> { Some(0) }
    fn gid(&self) -> Option<u32> { Some(0) }
    fn i_flags(&self) -> u32 { self.flags }
}
fn file(flags: u32) -> InodeRef { Arc::new(FlagFile { flags }) }

/// Default `i_flags()` is 0 for an inode that doesn't override it.
#[test]
fn default_i_flags_zero() {
    struct Plain;
    impl Inode for Plain {
        fn ino(&self) -> vfs::Ino { 9 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { 0 }
        fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
    }
    assert_eq!(Plain.i_flags(), 0);
}

/// S_IMMUTABLE denies a write request with EPERM even though the mode bits
/// (0o777, owner) would otherwise grant it.
#[test]
fn immutable_denies_write() {
    let inode = file(S_IMMUTABLE);
    let cred = Cred::root();
    assert_eq!(inode.permission(MAY_WRITE, &cred), Err(VfsError::Eperm));
    // read + exec still allowed — immutable only blocks writes.
    assert_eq!(inode.permission(MAY_READ, &cred), Ok(()));
    assert_eq!(inode.permission(MAY_EXEC, &cred), Ok(()));
    // a combined read+write request is still rejected.
    assert_eq!(inode.permission(MAY_READ | MAY_WRITE, &cred), Err(VfsError::Eperm));
}

/// CAP_DAC_OVERRIDE (root) does NOT bypass S_IMMUTABLE on writes (Linux
/// enforces the immutable check before the DAC-override class check).
#[test]
fn immutable_not_bypassed_by_dac_override() {
    let inode = file(S_IMMUTABLE);
    let mut cred = Cred::root();
    cred.uid = 1000; // non-owner
    assert!(cred.cap_dac_override);
    assert_eq!(inode.permission(MAY_WRITE, &cred), Err(VfsError::Eperm));
}

/// Without S_IMMUTABLE the same write request is granted by the mode bits.
#[test]
fn writable_without_immutable() {
    let inode = file(0);
    let cred = Cred::root();
    assert_eq!(inode.permission(MAY_WRITE, &cred), Ok(()));
    // S_APPEND alone does not block writes at the permission layer
    // (append enforcement is an open-path concern, not `permission`).
    let ap = file(S_APPEND);
    assert_eq!(ap.permission(MAY_WRITE, &cred), Ok(()));
}
