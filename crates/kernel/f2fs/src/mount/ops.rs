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

use syscall::errno::Errno;
use vfs::xattr::XattrError;
use vfs::idmap::Idmap;
use vfs::namei::RENAME_NOREPLACE;
use vfs::setattr::{Iattr, ATTR_ATIME, ATTR_GID, ATTR_MODE, ATTR_MTIME, ATTR_SIZE, ATTR_UID};
use vfs::{CreateCtx, DirContext, FileType, FileOps, Inode, InodeOps, InodeRef, KResult,
          VfsError};

use crate::flags::*;
use crate::mode;

use super::node::{node_inode, F2fsNode};
use super::write::{mk_mode, mknod_type, now};
use super::errno_to_vfs;

/// The operations, for every inode of this filesystem.
pub struct F2fsOps;

impl F2fsOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&F2fsNode> {
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

    /// Make something under `inode`, with the owner the caller's context
    /// names. # C: O(depth) blocks
    fn make(inode: &Inode, name: &str, ftype: FileType, perm: u32, rdev: u32,
            body: Option<&[u8]>, ctx: &CreateCtx, named: bool) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        // The umask is applied here and not in the volume: it is a property of
        // the caller, not of the medium — and it is only ever consulted when the
        // parent has no default ACL to inherit, which is what `inherit` decides.
        let kind = match ftype {
            FileType::Directory => vfs::posix_acl::NewKind::Dir,
            FileType::Symlink   => vfs::posix_acl::NewKind::Symlink,
            _                   => vfs::posix_acl::NewKind::Other,
        };
        let got = Self::inherited(node, &dir, perm as u16, ctx.umask, kind)?;
        let child = node.fs.make(node.ino, name, mk_mode(ftype, u32::from(got.mode)),
                                 ctx.fsuid(), ctx.fsgid(), rdev, body, named)?;
        if got.access.is_some() || got.default.is_some() {
            Self::store_inherited(node, Self::node(&child)?.ino, &got)?;
        }
        Ok(child)
    }

    /// The parent's default ACL, folded with the requested mode and the umask
    /// into what the new object gets.
    ///
    /// Kept out of line: the attribute region it reads is assembled in a buffer
    /// the size of a block, and a create already spends most of the kernel stack
    /// on the write path below it. # C: O(region bytes)
    #[inline(never)]
    fn inherited(node: &F2fsNode, dir: &crate::Inode, perm: u16, umask: u16,
                 kind: vfs::posix_acl::NewKind) -> KResult<crate::acl::Inherited> {
        let (enabled, parent) = {
            let v = node.fs.volume.lock();
            let enabled = v.options().acl;
            let parent = if enabled && kind != vfs::posix_acl::NewKind::Symlink {
                match v.get_xattr(dir, node.ino, crate::acl::name_default()) {
                    Ok(bytes) => Some(bytes),
                    Err(Errno::Enodata) | Err(Errno::Eopnotsupp) => None,
                    Err(e) => return Err(errno_to_vfs(e)),
                }
            } else {
                None
            };
            (enabled, parent)
        };
        crate::acl::inherit(parent.as_deref(), perm, umask, kind, enabled).map_err(errno_to_vfs)
    }

    /// Put the inherited ACLs on the object once it exists, the default one
    /// first. Out of line for the same reason as `inherited`. # C: O(region bytes)
    #[inline(never)]
    fn store_inherited(node: &F2fsNode, ino: u32, got: &crate::acl::Inherited) -> KResult<()> {
        for (name, value) in [(crate::acl::name_default(), &got.default),
                              (crate::acl::name_access(),  &got.access)] {
            let Some(bytes) = value else { continue };
            node.fs.volume_now().set_xattr(ino, name, Some(bytes), false, false)
                .map_err(errno_to_vfs)?;
        }
        Ok(())
    }
}

impl InodeOps for F2fsOps {
    /// The generic ioctl stage's file-attribute pair, which is where the flag
    /// commands land for every filesystem. # C: O(1 block)
    fn fileattr_get(&self, inode: &Inode) -> KResult<vfs::FileAttr> {
        crate::ioctl::vfs::fileattr_get(inode)
    }

    fn fileattr_set(&self, inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
        crate::ioctl::vfs::fileattr_set(inode, fa)
    }

    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = {
            let v = node.fs.volume.lock();
            v.lookup(&dir, node.ino, name.as_bytes()).map_err(errno_to_vfs)?
        };
        node_inode(Arc::clone(&node.fs), hit.ino)
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok((node, dir)) = Self::dir_of(inode) else { return true };
        let v = node.fs.volume.lock();
        v.dir_is_empty(&dir, node.ino).unwrap_or(false)
    }

    fn create(&self, inode: &Inode, name: &str, mode_bits: u32, ctx: &CreateCtx)
        -> KResult<InodeRef> {
        Self::make(inode, name, FileType::Regular, mode_bits, 0, None, ctx, true)
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode_bits: u32, ctx: &CreateCtx)
        -> KResult<InodeRef> {
        Self::make(inode, name, FileType::Directory, mode_bits, 0, None, ctx, false)
    }

    fn mknod(&self, inode: &Inode, name: &str, mode_bits: u16, rdev: u32, ctx: &CreateCtx)
        -> KResult<()> {
        let ftype = mknod_type(u32::from(mode_bits))?;
        let rdev = if matches!(ftype, FileType::CharDev | FileType::BlockDev) { rdev } else { 0 };
        Self::make(inode, name, ftype, u32::from(mode_bits), rdev, None, ctx, false)?;
        Ok(())
    }

    /// A link's target is its CONTENT, so it is created with the target as the
    /// file's initial bytes rather than through a field of its own.
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &CreateCtx) -> KResult<()> {
        if target.is_empty() || target.len() > crate::limits::MAX_SYMLINK_BYTES {
            return Err(VfsError::Enametoolong);
        }
        Self::make(inode, name, FileType::Symlink, 0o777, 0, Some(target), ctx, false)?;
        Ok(())
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &CreateCtx)
        -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        let other = Self::node(target)?;
        if !Arc::ptr_eq(&node.fs, &other.fs) { return Err(VfsError::Exdev); }
        node.fs.link(node.ino, name, other.ino)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        node.fs.remove(node.ino, name, false)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        node.fs.remove(node.ino, name, true)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        let (target, _) = Self::dir_of(new_dir)?;
        // Both directories are on one volume by construction: a rename across
        // filesystems never reaches a backend.
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        node.fs.rename(node.ino, old_name, target.ino, new_name, flags & RENAME_NOREPLACE != 0)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        if mode::file_type(node.live()?.mode) == FileType::Directory {
            return Err(VfsError::Eisdir);
        }
        node.fs.truncate(node.ino, len)?;
        node.restat(inode)
    }

    /// The stored fields are changed on the medium and then on the cached
    /// inode; doing only the latter would lose every change at unmount.
    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        let node = Self::node(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        if ia.valid & ATTR_SIZE != 0 { node.fs.truncate(node.ino, ia.size)?; }
        let mode_bits = if ia.valid & ATTR_MODE != 0 { Some(ia.mode) } else { None };
        let owner = if ia.valid & (ATTR_UID | ATTR_GID) != 0 {
            let uid = if ia.valid & ATTR_UID != 0 { ia.uid } else { inode.uid().unwrap_or(0) };
            let gid = if ia.valid & ATTR_GID != 0 { ia.gid } else { inode.gid().unwrap_or(0) };
            Some((uid, gid))
        } else {
            None
        };
        if mode_bits.is_some() || owner.is_some() {
            node.fs.volume_now().set_attr(node.ino, mode_bits, owner, now())
                .map_err(errno_to_vfs)?;
        }
        if ia.valid & (ATTR_ATIME | ATTR_MTIME) != 0 {
            let stamp = |t: vfs::timespec::Timespec64| (t.sec.max(0) as u64, t.nsec);
            node.fs.volume_now().set_times(node.ino, stamp(ia.atime), stamp(ia.mtime))
                .map_err(errno_to_vfs)?;
        }
        vfs::setattr::simple_setattr(inode, idmap, ia)?;
        // A size change moves the block count too, and by a different amount:
        // shortening a file frees the nodes that held its tail as well as the
        // blocks themselves.
        if ia.valid & ATTR_SIZE != 0 { node.restat(inode)?; }
        Ok(())
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        if !node.fs.is_writable() { return Err(XattrError::Fs(VfsError::Erofs)); }
        // The two ACL names are stored as this filesystem's own record, so the
        // interchange blob the caller handed over is converted before it lands.
        let value = if crate::acl::is_acl_name(name) {
            crate::acl::disk_from_xattr(&value).map_err(xattr_errno)?
        } else {
            value
        };
        node.fs
            .volume
            .lock()
            .set_xattr(node.ino, name, Some(&value), create, replace)
            .map_err(xattr_errno)
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        if !node.fs.is_writable() { return Err(XattrError::Fs(VfsError::Erofs)); }
        node.fs.volume_now().remove_xattr(node.ino, name).map_err(xattr_errno)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let node = Self::node(inode)?;
        let live = node.live()?;
        if mode::file_type(live.mode) != FileType::Symlink { return Err(VfsError::Einval); }
        let v = node.fs.volume.lock();
        v.read_link(&live, node.ino).map_err(errno_to_vfs)
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        let live = node.live().map_err(XattrError::Fs)?;
        let stored = {
            let v = node.fs.volume.lock();
            v.get_xattr(&live, node.ino, name).map_err(xattr_errno)?
        };
        if crate::acl::is_acl_name(name) {
            return crate::acl::xattr_from_disk(&stored).map_err(xattr_errno);
        }
        Ok(stored)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        let live = node.live().map_err(XattrError::Fs)?;
        let bytes = {
            let v = node.fs.volume.lock();
            v.list_xattr(&live, node.ino).map_err(xattr_errno)?
        };
        Ok(split_names(&bytes))
    }
}

impl FileOps for F2fsOps {
    /// The typed ioctl stage: the version, label and trim commands the
    /// interface carries for every filesystem. This filesystem's OWN commands
    /// do not come through here — they carry their own numbers and reach
    /// `ioctl::vfs::raw` with those untouched.
    /// # C: command-dependent
    fn unlocked_ioctl(&self, file: &vfs::File, _idmap: &Idmap, cred: &vfs::Cred,
                      cmd: vfs::FileIoctlCmd) -> KResult<vfs::FileIoctlReply> {
        crate::ioctl::vfs::unlocked_ioctl(file, cred, cmd)
    }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = F2fsOps::node(inode)?;
        let live = node.live()?;
        if mode::file_type(live.mode) == FileType::Directory { return Err(VfsError::Eisdir); }
        let v = node.fs.volume.lock();
        v.read_file(&live, node.ino, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = F2fsOps::node(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        if mode::file_type(node.live()?.mode) == FileType::Directory {
            return Err(VfsError::Eisdir);
        }
        // A short write is reported as short, not as a failure and not as a
        // full one: the caller resumes from where it stopped, which is the
        // only way a write that ran out of space part way can be completed.
        let n = node.fs.write(node.ino, off, buf)?;
        node.restat(inode)?;
        Ok(n)
    }

    /// Make one file durable.
    ///
    /// Writes here reach the medium out of place but are not REFERENCED until
    /// something names them, so reporting success without writing would tell a
    /// caller its data is safe when a crash would lose it. What names them is
    /// the volume's decision: a chain of the file's own node blocks where the
    /// state allows a later mount to replay it, and a whole checkpoint where
    /// it does not. Answering every call with a checkpoint is honest but makes
    /// one file's durability cost the whole volume's.
    fn fsync(&self, file: &vfs::File, datasync: bool) -> KResult<()> {
        let inode = file.inode();
        match inode.file_type() {
            FileType::Regular | FileType::Directory => {}
            _ => return Err(VfsError::Einval),
        }
        let node = F2fsOps::node(inode)?;
        if !node.fs.is_writable() { return Ok(()); }
        node.fs.sync_file(node.ino, datasync)
    }

    /// This filesystem STORES `.` and `..` as ordinary entries, so the
    /// listing already carries them. Leaving this at its default would have
    /// the interface synthesise a second pair on top, and every directory
    /// would list both names twice.
    fn iterate_emits_dots(&self) -> bool { true }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let (node, dir) = F2fsOps::dir_of(inode)?;
        let entries = {
            let v = node.fs.volume.lock();
            v.read_dir(&dir, node.ino).map_err(errno_to_vfs)?
        };
        // This filesystem STORES `.` and `..` as ordinary entries, so they are
        // emitted from the listing rather than synthesised: synthesising them
        // on top of the stored pair would report each twice.
        for (i, e) in entries.iter().enumerate() {
            let slot = i as u64;
            if ctx.pos > slot { continue; }
            let name = alloc::string::String::from_utf8_lossy(&e.name);
            if !ctx.emit(&name, u64::from(e.ino), vfs_type(e.file_type), slot + 1) { break; }
        }
        Ok(())
    }
}

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
