//! `Inode::i_flags` + S_IMMUTABLE write-deny in the default `permission`
//! op (Linux `inode_permission`: "Nobody gets write access to an immutable
//! file" — checked BEFORE the DAC class check, so not even CAP_DAC_OVERRIDE
//! bypasses it). Synthetic inodes carrying explicit flags — no real FS.

use vfs::inode::{InodeBuilder, S_APPEND, S_IMMUTABLE};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, InodeRef, VfsError};
use vfs::{MAY_EXEC, MAY_READ, MAY_WRITE};

/// Regular file, world-rwx perm, owned by uid 0, with an explicit `i_flags`.
fn file(flags: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o777), default_inode_ops(), default_file_ops())
        .owner(0, 0).i_flags(flags).build()
}

/// Default `i_flags()` is 0 for an inode that sets no flags.
#[test]
fn default_i_flags_zero() {
    let plain = InodeBuilder::new(9, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build();
    assert_eq!(plain.i_flags(), 0);
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
