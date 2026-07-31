// Hardlink gates. Linux splits these across two call sites and the split is
// load-bearing for error ordering: `may_linkat` runs at the syscall layer
// right after the cross-mount `EXDEV` test, while the rest run inside
// `vfs_link` AFTER the destination's `may_create`. So a caller that is denied
// by the hardlink-protection sysctl sees `EPERM` even when the source is also
// at its link ceiling, and even when the destination directory is unwritable.

use core::sync::atomic::Ordering;
use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_READ, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};
use super::may_create::{id_representable, may_create};
use super::permission::inode_permission;

const PROTECTED_HARDLINKS: bool = true;

/// Linux `safe_hardlink_source`: non-owner hardlinks are only safe for regular
/// files that are not setuid, not executable-setgid, and readable+writable by
/// the caller. # C: O(ngroups)
fn safe_hardlink_source(inode: &InodeRef, cred: &Cred) -> bool {
    let mode = inode.i_mode();
    if !matches!(inode.file_type(), FileType::Regular) { return false; }
    if mode & S_ISUID != 0 { return false; }
    if (mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) { return false; }
    inode_permission(inode, MAY_READ | MAY_WRITE, cred).is_ok()
}

/// Linux `may_linkat` — the hardlink-protection gate, run at the syscall layer
/// immediately after the cross-mount `EXDEV` test and BEFORE the destination
/// directory's create permission. An unrepresentable source owner is
/// `EOVERFLOW`; otherwise the source owner (or CAP_FOWNER) may link freely and
/// everyone else needs a "safe" source. # C: O(ngroups)
pub fn may_linkat(src: &InodeRef, cred: &Cred) -> KResult<()> {
    if !id_representable(src.uid().unwrap_or(0)) || !id_representable(src.gid().unwrap_or(0)) {
        return Err(VfsError::Eoverflow);
    }
    if !PROTECTED_HARDLINKS { return Ok(()); }
    if cred.uid == src.uid().unwrap_or(0) || cred.cap_fowner { return Ok(()); }
    if safe_hardlink_source(src, cred) { return Ok(()); }
    Err(VfsError::Eperm)
}

/// The source-side half of Linux `vfs_link`, run AFTER the destination's
/// `may_create`: append-only / immutable sources refuse new names, an
/// unrepresentable owner cannot have its link count rewritten, a directory is
/// never hardlinkable, an already-unlinked inode has no name to copy
/// (`ENOENT`, unless it is an `O_TMPFILE` inode awaiting its first name), and
/// the filesystem's `s_max_links` ceiling is `EMLINK`. # C: O(1)
pub fn may_link_source(src: &InodeRef, _cred: &Cred) -> KResult<()> {
    if src.i_flags() & (crate::inode::S_APPEND | crate::inode::S_IMMUTABLE) != 0 {
        return Err(VfsError::Eperm);
    }
    if !id_representable(src.uid().unwrap_or(0)) || !id_representable(src.gid().unwrap_or(0)) {
        return Err(VfsError::Eperm);
    }
    if matches!(src.file_type(), FileType::Directory) { return Err(VfsError::Eperm); }
    if src.nlink() == 0 && src.i_state() & crate::inode::I_LINKABLE == 0 {
        return Err(VfsError::Enoent);
    }
    let max = src.i_sb().map(|sb| sb.s_max_links.load(Ordering::Relaxed)).unwrap_or(0);
    if max != 0 && src.nlink() >= max { return Err(VfsError::Emlink); }
    Ok(())
}

/// Combined destination+source hardlink gate for hosted VFS callers that are
/// not modeling syscall-level `filename_create()` / `EXDEV` ordering. Keeps
/// Linux's relative order: `may_linkat` → destination `may_create` → the
/// `vfs_link` source checks. # C: O(ngroups)
pub fn may_link(parent: &InodeRef, src: &InodeRef, cred: &Cred) -> KResult<()> {
    may_linkat(src, cred)?;
    may_create(parent, cred)?;
    may_link_source(src, cred)
}
