//! The inode and file operations of a mounted volume.
//!
//! One vector serves both: every operation needs the same two things, the
//! inode this object was built from and the volume's lock.
//!
//! The mutating operations refuse before they touch anything when the mount
//! is read-only, rather than failing partway through: a create that had
//! already allocated an inode when it discovered it could not write would
//! leave the volume with an unreachable one.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::xattr::XattrError;
use vfs::idmap::Idmap;
use vfs::setattr::{Iattr, ATTR_ATIME, ATTR_GID, ATTR_MODE, ATTR_MTIME, ATTR_SIZE, ATTR_UID};
use vfs::{CreateCtx, DirContext, FileType, FileOps, Inode, InodeOps, InodeRef, KResult,
          VfsError};

use crate::flags::*;
use crate::mode;

use super::node::{node_inode, F2fsNode};
use super::prepare;
use super::write::{mk_mode, mknod_type, now};
use super::errno_to_vfs;

/// The operations, for every inode of this filesystem.
pub struct F2fsOps;

impl F2fsOps {
    /// The node behind an inode. # C: O(1)
    pub(super) fn node(inode: &Inode) -> KResult<&F2fsNode> {
        inode.private::<F2fsNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode, and the directory as it is now.
    /// # C: O(1 block)
    fn dir_of(inode: &Inode) -> KResult<(&F2fsNode, crate::Inode)> {
        let node = Self::node(inode)?;
        let live = node.live()?;
        if mode::file_type(live.mode) != FileType::Directory { return Err(VfsError::Enotdir); }
        Ok((node, live))
    }

    /// The node behind a directory inode, refusing early when the mount
    /// cannot write. # C: O(1)
    fn writable_dir(inode: &Inode) -> KResult<&F2fsNode> {
        let (node, _) = Self::dir_of(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        Ok(node)
    }

    /// Whether the name being moved names a directory, and what — if anything
    /// — sits at the destination. Read BEFORE the rename, because afterwards
    /// neither name resolves to what it did.
    /// # C: O(depth) blocks
    fn shapes(node: &F2fsNode, old_name: &str, target: &F2fsNode, new_name: &str)
        -> (bool, Option<bool>) {
        let v = node.fs.volume.lock();
        let is_dir = |ino: u32| {
            v.read_inode(ino).map(|i| mode::file_type(i.mode) == FileType::Directory)
                .unwrap_or(false)
        };
        let moved = v.read_inode(node.ino).ok()
            .and_then(|d| v.lookup(&d, node.ino, old_name.as_bytes()).ok())
            .map(|h| is_dir(h.ino))
            .unwrap_or(false);
        let victim = v.read_inode(target.ino).ok()
            .and_then(|d| v.lookup(&d, target.ino, new_name.as_bytes()).ok())
            .map(|h| is_dir(h.ino));
        (moved, victim)
    }

    /// Make something under `inode`, with the owner the caller's context
    /// names. # C: O(depth) blocks
    fn make(inode: &Inode, name: &str, ftype: FileType, perm: u32, rdev: u32,
            body: Option<&[u8]>, ctx: &CreateCtx, named: bool) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        // The umask is applied by `inherited` and not here: it is a property of
        // the caller, not of the medium — and it is only ever consulted when the
        // parent has no default ACL to inherit, which is what `inherit` decides.
        // That is why `prepare` below is handed a zero umask.
        let kind = match ftype {
            FileType::Directory => vfs::posix_acl::NewKind::Dir,
            FileType::Symlink   => vfs::posix_acl::NewKind::Symlink,
            _                   => vfs::posix_acl::NewKind::Other,
        };
        let (uid, gid, prepared) = prepare::owner_mode(inode, ftype, perm as u16, ctx);
        let got = prepare::inherited(node, &dir, prepared, ctx.umask, kind)?;
        let child = node.fs.make(node.ino, name, mk_mode(ftype, u32::from(got.mode)),
                                 uid, gid, rdev, body, named)?;
        if got.access.is_some() || got.default.is_some() {
            prepare::store_inherited(node, Self::node(&child)?.ino, &got)?;
        }
        Ok(child)
    }

}

#[path = "inode_ops.rs"]
mod inode_ops;
#[path = "file_ops.rs"]
mod file_ops;

/// A stored type byte as the interface's type.
///
/// An unknown byte presents as a regular file rather than being dropped: the
/// entry exists and hiding it would make the name unreachable, while the
/// inode it points at states its own real type.
/// # C: O(1)
pub fn vfs_type(ft: u8) -> FileType {
    match ft {
        FT_DIR => FileType::Directory,
        FT_CHRDEV => FileType::CharDev,
        FT_BLKDEV => FileType::BlockDev,
        FT_FIFO => FileType::Fifo,
        FT_SOCK => FileType::Socket,
        FT_SYMLINK => FileType::Symlink,
        _ => FileType::Regular,
    }
}

/// # C: O(1)
pub(crate) fn xattr_errno(e: syscall::errno::Errno) -> XattrError {
    match e {
        syscall::errno::Errno::Enodata => XattrError::NotFound,
        syscall::errno::Errno::Eopnotsupp => XattrError::NotSup,
        syscall::errno::Errno::Eexist => XattrError::Exists,
        other => XattrError::Fs(errno_to_vfs(other)),
    }
}

/// The zero-terminated name list as separate names. # C: O(bytes)
pub fn split_names(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[cfg(test)]
#[path = "../tests/ops.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/acl_ops.rs"]
mod acl_tests;
/// Enforcement: a stored ACL deciding a permission check.
#[cfg(test)]
#[path = "../tests/acl_enforce.rs"]
mod acl_enforce_tests;
/// The owner ids and mode a create records, ahead of the ACL work.
#[cfg(test)]
#[path = "../tests/create_owner.rs"]
mod create_owner_tests;
/// The namespace operations, driven through the interface's own vtable.
#[cfg(test)]
#[path = "../tests/opsnamei.rs"]
mod namei_tests;
/// What an OPEN owes, driven through a real handle.
#[cfg(test)]
#[path = "../tests/openhook.rs"]
mod open_tests;
