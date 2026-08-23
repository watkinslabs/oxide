//! The inode and file operations of a mounted exFAT volume.
//!
//! One vector serves both, because on this filesystem an inode and an open
//! file need exactly the same three things: the entry set the inode came from,
//! the directory that set sits in, and the volume's lock.
//!
//! There is deliberately no `link`. exFAT has no link count and no way to name
//! one file twice — a second name would be a second set claiming the same
//! first cluster, which every checker reports as cross-linked — so the slot is
//! left at its default, which answers `EPERM`, exactly as a filesystem without
//! the operation does. `symlink`, `mknod` and `tmpfile` are absent for the
//! same reason.

use alloc::sync::Arc;

use vfs::{CreateCtx, DirContext, FileOps, FileType, Inode, InodeOps, InodeRef, KResult,
          VfsError};
use vfs::setattr::{Iattr, ATTR_GID, ATTR_UID};
use vfs::uapi::FALLOC_FL_KEEP_SIZE;

use crate::ident::{self, Position};
use crate::volume::{DirEntry, DirHandle};

use super::node::{node_inode, ExfatNode};
use super::{errno_to_vfs, now};
use crate::attrs::attrs_for_mode;
use crate::time::{from_unix, truncate_atime, without_centiseconds};

/// The operations, for every inode of this filesystem.
pub struct ExfatOps;

impl ExfatOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&ExfatNode> {
        inode.private::<ExfatNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode, and the handle to operate in it.
    /// # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<(&ExfatNode, DirHandle)> {
        let node = Self::node(inode)?;
        let dir = node.as_dir().ok_or(VfsError::Enotdir)?;
        Ok((node, dir))
    }

    /// Build the inode for an entry found in `home`. # C: O(1)
    fn child(node: &ExfatNode, home: &DirHandle, hit: DirEntry) -> InodeRef {
        node_inode(Arc::clone(&node.fs), Some(hit), home.clone())
    }

    /// Attach removed allocations to the exact victim inode. # C: O(1)
    fn defer_removed(node: &ExfatNode, inode: &InodeRef, chains: alloc::vec::Vec<crate::chain::Chain>)
        -> KResult<()> {
        let victim = inode.private::<ExfatNode>().ok_or(VfsError::Einval)?;
        if !Arc::ptr_eq(&node.fs, &victim.fs) { return Err(VfsError::Exdev); }
        victim.defer_release(chains);
        inode.set_nlink(0);
        Ok(())
    }
}

impl InodeOps for ExfatOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = {
            let v = node.fs.volume.lock();
            let chain = v.dir_chain(&dir).map_err(errno_to_vfs)?;
            v.find_entry(&chain, name).map_err(errno_to_vfs)?
        };
        Ok(Self::child(node, &dir, hit))
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok((node, dir)) = Self::dir_of(inode) else { return true };
        let v = node.fs.volume.lock();
        let Ok(chain) = v.dir_chain(&dir) else { return false };
        v.dir_is_empty(&chain).unwrap_or(false)
    }

    /// `mode` and the umask are read and discarded: this filesystem stores no
    /// permission bits, and what an entry presents with is the mount's
    /// `fmask=`/`dmask=` answer rather than anything the creator asked for.
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx)
        -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_file(&dir, name, now()).map_err(errno_to_vfs)?;
        Ok(Self::child(node, &dir, hit))
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_dir(&dir, name, now()).map_err(errno_to_vfs)?;
        Ok(Self::child(node, &dir, hit))
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        node.fs.volume.lock().rmdir(&dir, name, now()).map_err(errno_to_vfs)
    }

    fn rmdir_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let chains = v.rmdir_name(&dir, name, now()).map_err(errno_to_vfs)?;
        drop(v);
        Self::defer_removed(node, victim, chains)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        node.fs.volume.lock().unlink(&dir, name, now()).map_err(errno_to_vfs)
    }

    fn unlink_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let chains = v.unlink_name(&dir, name, now()).map_err(errno_to_vfs)?;
        drop(v);
        Self::defer_removed(node, victim, chains)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let (node, from) = Self::dir_of(inode)?;
        let (target, to) = Self::dir_of(new_dir)?;
        // Both directories are on one volume by construction: a rename across
        // filesystems never reaches a backend.
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        node.fs.volume.lock().rename(&from, old_name, &to, new_name, flags, now())
            .map_err(errno_to_vfs)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        let mut entry = node.entry().ok_or(VfsError::Eisdir)?;
        node.fs.volume.lock().truncate_file(&mut entry, len, now()).map_err(errno_to_vfs)?;
        node.set_entry(entry);
        inode.set_size(len);
        Ok(())
    }

    fn fallocate(&self, inode: &Inode, mode: u32, offset: u64, len: u64) -> KResult<()> {
        if mode & !FALLOC_FL_KEEP_SIZE != 0 { return Err(VfsError::Eopnotsupp); }
        let node = Self::node(inode)?;
        let mut entry = node.entry().ok_or(VfsError::Eisdir)?;
        let end = offset.checked_add(len).ok_or(VfsError::Einval)?;
        if mode & FALLOC_FL_KEEP_SIZE != 0 {
            node.fs.volume.lock().preallocate_file(&mut entry, offset, len, now())
                .map_err(errno_to_vfs)?;
            node.set_entry(entry);
        } else if end > inode.size() {
            node.fs.volume.lock().truncate_file(&mut entry, end, now())
                .map_err(errno_to_vfs)?;
            node.set_entry(entry);
            inode.set_size(end);
        }
        Ok(())
    }

    /// Persist the representable mode and timestamps in the exact exFAT entry
    /// set this inode came from. Ownership remains mount-synthesized because
    /// exFAT stores no uid/gid fields. # C: O(set bytes)
    fn setattr(&self, inode: &Inode, idmap: &vfs::Idmap, ia: &Iattr) -> KResult<()> {
        let node = Self::node(inode)?;
        let mut entry = node.entry().ok_or(VfsError::Eisdir)?;
        let v = node.fs.volume.lock();
        if !v.writable() { return Err(VfsError::Erofs); }
        let opts = *v.options();
        let uid = if ia.valid & ATTR_UID != 0 { idmap.map_in_uid(ia.uid) } else { opts.uid };
        let gid = if ia.valid & ATTR_GID != 0 { idmap.map_in_gid(ia.gid) } else { opts.gid };
        if uid != opts.uid || gid != opts.gid { return Err(VfsError::Eperm); }
        vfs::simple_setattr(inode, idmap, ia)?;
        entry.set.file.attr = attrs_for_mode(entry.set.file.attr, inode.perm().unwrap_or(0));
        let access = truncate_atime(inode.atime().unwrap_or_default());
        let modify = inode.mtime().unwrap_or_default();
        entry.set.file.access = from_unix(access);
        entry.set.file.modify = without_centiseconds(from_unix(modify));
        v.write_entry_set(&entry).map_err(errno_to_vfs)
    }

    /// exFAT's `allow_utime=` is the same non-owner exception as Linux FAT:
    /// it is checked before generic VFS `setattr_prepare`, while owner and
    /// CAP_FOWNER callers retain the ordinary VFS path.
    fn allow_set_time(&self, inode: &Inode, idmap: &vfs::Idmap, cred: &vfs::Cred) -> bool {
        let node = match Self::node(inode) { Ok(node) => node, Err(_) => return false };
        let v = node.fs.volume.lock();
        let owner = vfs::inode::inode_owner_or_capable(idmap, inode, cred);
        let group = cred.in_group(idmap.map_out_gid(inode.gid().unwrap_or(0)));
        v.options().allows_non_owner_utime(owner, group)
    }
}

impl FileOps for ExfatOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = ExfatOps::node(inode)?;
        let entry = node.entry().ok_or(VfsError::Eisdir)?;
        node.fs.volume.lock().read_file(&entry, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = ExfatOps::node(inode)?;
        // The set's own offset came with the inode, so the write lands on the
        // set this inode IS rather than on whichever set a fresh search finds.
        let mut entry = node.entry().ok_or(VfsError::Eisdir)?;
        let size = node.fs.volume.lock().write_file(&mut entry, off, buf, now())
            .map_err(errno_to_vfs)?;
        node.set_entry(entry);
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let (node, dir) = ExfatOps::dir_of(inode)?;
        let entries = {
            let v = node.fs.volume.lock();
            let chain = v.dir_chain(&dir).map_err(errno_to_vfs)?;
            v.read_dir(&chain).map_err(errno_to_vfs)?
        };
        // exFAT stores no `.` or `..` entries at all — unlike FAT, where a
        // subdirectory carries both — so they are emitted here or a listing
        // has neither.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        for (i, entry) in entries.iter().enumerate() {
            let slot = i as u64 + 2;
            if ctx.pos > slot { continue; }
            let pos = Position {
                dir_cluster: entry.dir.dir,
                entry_index: ident::index_of_offset(entry.set.offset),
            };
            let ino = ident::inode_number(&pos);
            let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
            if !ctx.emit(&entry.name, ino, ftype, slot + 1) { break; }
        }
        Ok(())
    }
}
