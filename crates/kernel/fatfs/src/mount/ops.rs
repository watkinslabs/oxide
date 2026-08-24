//! The inode and file operations of a mounted FAT volume.
//!
//! One vector serves both, because on this filesystem an inode and an open
//! file need exactly the same three things: the record the inode came from,
//! the directory that record sits in, and the volume's lock.
//!
//! There is deliberately no `link`. FAT has no link count and no way to name
//! one file twice — a second name would be a second record claiming the same
//! first cluster, which every checker reports as cross-linked — so the slot is
//! left at its default, which answers `EPERM`, exactly as a filesystem without
//! the operation does. `symlink`, `mknod` and `tmpfile` are absent for the
//! same reason.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{CreateCtx, DirContext, FileIoctlCmd, FileIoctlReply, FileOps, FileType, Inode,
          InodeOps, InodeRef, KResult, VfsError};
use vfs::inode::{inode_owner_or_capable, FileAttr, FS_CASEFOLD_FL, FS_IMMUTABLE_FL,
                 FS_XFLAG_CASEFOLD, FS_XFLAG_IMMUTABLE, S_IMMUTABLE};
use vfs::setattr::{Iattr, ATTR_GID, ATTR_UID};
use vfs::uapi::FALLOC_FL_KEEP_SIZE;

use crate::ident::{self, DirLocation};
use crate::namei::dir_is_empty;
use crate::dirent::Record;
use crate::attrs::make_attrs;
use crate::time::{from_unix, truncate_atime, truncate_mtime};
use crate::volume::{DirEntry, DirHandle};

use super::node::{node_inode, FatNode};
use super::{errno_to_vfs, now_for};

/// The operations, for every inode of this filesystem.
pub struct FatOps;

impl FatOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&FatNode> {
        inode.private::<FatNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode, and the handle to operate in it.
    /// # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<(&FatNode, DirHandle)> {
        let node = Self::node(inode)?;
        let dir = node.as_dir().ok_or(VfsError::Enotdir)?;
        Ok((node, dir))
    }

    /// The directory contents an inode names, or `ENOTDIR`. # C: O(dir bytes)
    fn entries(node: &FatNode) -> KResult<Vec<DirEntry>> {
        let dir = node.as_dir().ok_or(VfsError::Enotdir)?;
        node.fs.volume.lock().read_dir(dir.cluster).map_err(errno_to_vfs)
    }

    /// Build the inode for an entry found in `parent`. # C: O(cluster bytes)
    fn child(node: &FatNode, dir: &DirHandle, hit: &DirEntry) -> InodeRef {
        let location = ident::location_of(&hit.entry, &node.location);
        node_inode(Arc::clone(&node.fs), Some(hit.entry), location, dir.cluster, hit.slot,
                   hit.nr_slots)
    }

    /// Attach a removed chain to the exact victim inode the path walk resolved.
    /// # C: O(1)
    fn defer_removed(node: &FatNode, inode: &InodeRef, cluster: u32) -> KResult<()> {
        let victim = inode.private::<FatNode>().ok_or(VfsError::Einval)?;
        if !Arc::ptr_eq(&node.fs, &victim.fs) { return Err(VfsError::Exdev); }
        victim.defer_release(cluster);
        inode.set_nlink(0);
        Ok(())
    }
}

impl InodeOps for FatOps {
    fn fileattr_get(&self, inode: &Inode) -> KResult<FileAttr> {
        let node = Self::node(inode)?;
        let v = node.fs.volume.lock();
        let mut fa = vfs::fileattr::fileattr_fill_flags(0);
        if !v.options().case_sensitive() {
            fa.flags |= FS_CASEFOLD_FL;
            fa.fsx_xflags |= FS_XFLAG_CASEFOLD;
        }
        if v.options().sys_immutable && node.entry.as_ref().is_some_and(|e| e.attr & crate::dirent::ATTR_SYS != 0) {
            fa.flags |= FS_IMMUTABLE_FL;
            fa.fsx_xflags |= FS_XFLAG_IMMUTABLE;
        }
        Ok(fa)
    }

    fn fileattr_set(&self, inode: &Inode, fa: &FileAttr) -> KResult<()> {
        let node = Self::node(inode)?;
        if fa.flags & !(FS_CASEFOLD_FL | FS_IMMUTABLE_FL) != 0
            || fa.fsx_xflags & !(FS_XFLAG_CASEFOLD | FS_XFLAG_IMMUTABLE) != 0
        { return Err(VfsError::Eopnotsupp); }
        let v = node.fs.volume.lock();
        if (fa.flags & FS_CASEFOLD_FL != 0) != !v.options().case_sensitive() {
            return Err(VfsError::Eopnotsupp);
        }
        let Some(mut entry) = node.current_entry() else { return Err(VfsError::Einval); };
        if !v.writable() { return Err(VfsError::Erofs); }
        if v.options().sys_immutable {
            if fa.flags & FS_IMMUTABLE_FL != 0 { entry.attr |= crate::dirent::ATTR_SYS; }
            else { entry.attr &= !crate::dirent::ATTR_SYS; }
        } else if fa.flags & FS_IMMUTABLE_FL != 0 { return Err(VfsError::Eperm); }
        let raw = v.read_dir_record(node.container(), node.slot).map_err(errno_to_vfs)?;
        let mut record = Record::parse(&raw).ok_or(VfsError::Eio)?;
        record.short.attr = entry.attr;
        v.write_dir_record(node.container(), node.slot, &record.encode()).map_err(errno_to_vfs)?;
        if entry.attr & crate::dirent::ATTR_SYS != 0 { inode.set_i_flags(inode.i_flags() | S_IMMUTABLE); }
        else { inode.set_i_flags(inode.i_flags() & !S_IMMUTABLE); }
        Ok(())
    }

    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().find_entry(&dir, name).map_err(errno_to_vfs)?;
        Ok(Self::child(node, &dir, &hit))
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok((node, dir)) = Self::dir_of(inode) else { return true };
        let v = node.fs.volume.lock();
        let Ok(bytes) = v.directory_bytes(dir.cluster) else { return false };
        dir_is_empty(&bytes)
    }

    /// `mode` and the umask are read and discarded: this filesystem stores no
    /// permission bits, and what an entry presents with is the mount's
    /// `fmask=`/`dmask=` answer rather than anything the creator asked for.
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let hit = v.create_file(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Ok(Self::child(node, &dir, &hit))
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let hit = v.create_dir(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Ok(Self::child(node, &dir, &hit))
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.rmdir(&dir, name, now).map_err(errno_to_vfs)
    }

    fn rmdir_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let cluster = v.rmdir_name(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Self::defer_removed(node, victim, cluster)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.unlink(&dir, name, now).map_err(errno_to_vfs)
    }

    fn unlink_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        let (node, dir) = Self::dir_of(inode)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let cluster = v.unlink_name(&dir, name, now).map_err(errno_to_vfs)?;
        drop(v);
        Self::defer_removed(node, victim, cluster)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let (node, from) = Self::dir_of(inode)?;
        let (target, to) = Self::dir_of(new_dir)?;
        // Both directories are on one volume by construction: a rename across
        // filesystems never reaches a backend.
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        v.rename(&from, old_name, &to, new_name, flags, now).map_err(errno_to_vfs)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        let entry = node.current_entry().ok_or(VfsError::Eisdir)?;
        let hit = DirEntry { name: String::new(), entry, slot: node.slot, nr_slots: node.nr_slots };
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let mut cache = node.cache.lock();
        v.truncate_file_cached(node.container(), &hit, &mut cache, len, now)
            .map_err(errno_to_vfs)?;
        drop(cache);
        drop(v);
        inode.set_size(len);
        Ok(())
    }

    fn fallocate(&self, inode: &Inode, mode: u32, offset: u64, len: u64) -> KResult<()> {
        if mode & !FALLOC_FL_KEEP_SIZE != 0 { return Err(VfsError::Eopnotsupp); }
        let node = Self::node(inode)?;
        let entry = node.current_entry().ok_or(VfsError::Eisdir)?;
        let hit = DirEntry { name: String::new(), entry, slot: node.slot, nr_slots: node.nr_slots };
        let end = offset.checked_add(len).ok_or(VfsError::Einval)?;
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let mut cache = node.cache.lock();
        if mode & FALLOC_FL_KEEP_SIZE != 0 {
            let first = v.preallocate_file_cached(node.container(), &hit, &mut cache,
                                                   offset, len, now).map_err(errno_to_vfs)?;
            node.set_current_cluster(first);
        } else if end > inode.size() {
            v.truncate_file_cached(node.container(), &hit, &mut cache, end, now)
                .map_err(errno_to_vfs)?;
            inode.set_size(end);
        }
        Ok(())
    }

    /// Persist the attributes FAT can represent in the exact short record
    /// this inode was resolved from.  FAT has no stored owner, so chown is
    /// valid only when it keeps the mount's synthesized uid/gid; the VFS
    /// preparation layer has already performed the caller authorization.
    /// # C: O(cluster bytes)
    fn setattr(&self, inode: &Inode, idmap: &vfs::Idmap, ia: &Iattr) -> KResult<()> {
        let node = Self::node(inode)?;
        let entry = node.current_entry().ok_or(VfsError::Eisdir)?;
        let v = node.fs.volume.lock();
        if !v.writable() { return Err(VfsError::Erofs); }
        let opts = *v.options();
        let uid = if ia.valid & ATTR_UID != 0 { idmap.map_in_uid(ia.uid) } else { opts.uid };
        let gid = if ia.valid & ATTR_GID != 0 { idmap.map_in_gid(ia.gid) } else { opts.gid };
        if uid != opts.uid || gid != opts.gid {
            // Linux's quiet option preserves the historical FAT ABI: an
            // ownership change the medium cannot represent succeeds without
            // changing the synthesized owner.
            if opts.quiet { return Ok(()); }
            return Err(VfsError::Eperm);
        }

        // Size and in-core metadata changes use the normal VFS owner.  FAT's
        // on-disk update below is deliberately after this call so a combined
        // truncate+chmod follows the same ordering as other filesystems.
        vfs::simple_setattr(inode, idmap, ia)?;

        let raw = v.read_dir_record(node.container(), node.slot).map_err(errno_to_vfs)?;
        let mut record = Record::parse(&raw).ok_or(VfsError::Eio)?;
        let mode = inode.perm().unwrap_or(0);
        record.short.attr = make_attrs(entry.is_dir(), mode, record.short.attr);
        let atime = inode.atime().unwrap_or_default();
        let mtime = inode.mtime().unwrap_or_default();
        let atime = truncate_atime(&opts.time, atime);
        let mtime = truncate_mtime(mtime);
        record.times.access_date = from_unix(&opts.time, atime).date;
        record.times.modify = from_unix(&opts.time, mtime);
        v.write_dir_record(node.container(), node.slot, &record.encode()).map_err(errno_to_vfs)
    }
}

impl FileOps for FatOps {
    fn unlocked_ioctl(&self, file: &vfs::File, idmap: &vfs::Idmap, cred: &vfs::Cred,
                      cmd: FileIoctlCmd) -> KResult<FileIoctlReply> {
        let inode = file.inode();
        let node = Self::node(inode)?;
        match cmd {
            FileIoctlCmd::FatGetAttributes => {
                let attr = node.entry.as_ref().map_or(crate::dirent::ATTR_DIR, |e| e.attr);
                Ok(FileIoctlReply::U32(u32::from(attr)))
            }
            FileIoctlCmd::FatSetAttributes { attr, cap_linux_immutable } => {
                if !inode_owner_or_capable(idmap, inode, cred) { return Err(VfsError::Eperm); }
                let is_dir = inode.file_type() == FileType::Directory;
                let mut attr = (attr as u8) & !(crate::dirent::ATTR_VOLUME | crate::dirent::ATTR_DIR);
                if is_dir { attr |= crate::dirent::ATTR_DIR; }
                let old = node.entry.as_ref().map_or(crate::dirent::ATTR_DIR, |e| e.attr);
                if old & crate::dirent::ATTR_VOLUME != 0 { attr |= crate::dirent::ATTR_VOLUME; }
                if (attr | old) & crate::dirent::ATTR_SYS != 0 && !cap_linux_immutable
                    && node.fs.options().sys_immutable { return Err(VfsError::Eperm); }
                let Some(mut entry) = node.current_entry() else {
                    return if attr == crate::dirent::ATTR_DIR { Ok(FileIoctlReply::Done) }
                    else { Err(VfsError::Einval) };
                };
                let v = node.fs.volume.lock();
                if !v.writable() { return Err(VfsError::Erofs); }
                let raw = v.read_dir_record(node.container(), node.slot).map_err(errno_to_vfs)?;
                let mut record = Record::parse(&raw).ok_or(VfsError::Eio)?;
                record.short.attr = attr;
                entry.attr = attr;
                v.write_dir_record(node.container(), node.slot, &record.encode()).map_err(errno_to_vfs)?;
                inode.set_perm(crate::attrs::make_mode(attr, &entry.raw_name, v.options()))?;
                if node.fs.options().sys_immutable {
                    if attr & crate::dirent::ATTR_SYS != 0 { inode.set_i_flags(inode.i_flags() | S_IMMUTABLE); }
                    else { inode.set_i_flags(inode.i_flags() & !S_IMMUTABLE); }
                }
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::FatReadDir { short_only } => {
                if inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
                let entries = Self::entries(node)?;
                let mut out = [0u8; 560];
                let pos = file.pos();
                let v = node.fs.volume.lock();
                if pos == 0 {
                    fill_fat_dirent(&mut out[..280], b".", 1, inode.ino());
                    file.set_pos(1);
                    return Ok(FileIoctlReply::Bytes(out, 560));
                }
                if pos == 1 {
                    fill_fat_dirent(&mut out[..280], b"..", 2, inode.ino());
                    file.set_pos(2);
                    return Ok(FileIoctlReply::Bytes(out, 560));
                }
                let scan_pos = if pos <= 2 { 0 } else { pos };
                for entry in entries {
                    if entry.group_start() < scan_pos { continue; }
                    let cluster = node.as_dir().and_then(|d| d.cluster);
                    let raw = v.read_dir_record(cluster, entry.slot).map_err(errno_to_vfs)?;
                    let short = v.short_name_for(&raw, &entry.entry);
                    let long = entry.name.as_str();
                    let ino = crate::ident::inode_number(
                        &crate::ident::location_of(&entry.entry, &node.location), Some(&entry.entry));
                    fill_fat_dirent(&mut out[..280], short.as_bytes(), entry.next_pos(), ino);
                    if !short_only && long != short {
                        fill_fat_dirent(&mut out[280..], long.as_bytes(), entry.next_pos(), ino);
                    }
                    file.set_pos(entry.next_pos());
                    return Ok(FileIoctlReply::Bytes(out, 560));
                }
                Err(VfsError::Enoent)
            }
            _ => Err(VfsError::Enotty),
        }
    }

    fn on_flush(&self, inode: &Inode) -> KResult<()> {
        let node = FatOps::node(inode)?;
        let v = node.fs.volume.lock();
        if v.options().flush && v.writable() {
            v.flush_device().map_err(errno_to_vfs)?;
        }
        Ok(())
    }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = FatOps::node(inode)?;
        let entry = node.current_entry().ok_or(VfsError::Eisdir)?;
        let v = node.fs.volume.lock();
        let mut cache = node.cache.lock();
        v.read_file_cached(&entry, &mut cache, off, buf).map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = FatOps::node(inode)?;
        let entry = node.current_entry().ok_or(VfsError::Eisdir)?;
        // The name is not re-resolved: the record's own slot came with the
        // inode, so the write lands on the record this inode IS.
        let hit = DirEntry { name: String::new(), entry, slot: node.slot, nr_slots: node.nr_slots };
        let mut v = node.fs.volume.lock();
        let now = now_for(v.options());
        let mut cache = node.cache.lock();
        let size = v.write_file_cached(node.container(), &hit, &mut cache, off, buf, now)
            .map_err(errno_to_vfs)?;
        drop(cache);
        drop(v);
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = FatOps::node(inode)?;
        let entries = FatOps::entries(node)?;
        // `.` and `..` are ordinary entries on a FAT subdirectory but absent
        // from the root, so they are emitted here rather than trusted from the
        // medium — a root listing must still carry them.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        // Cursors 0/1 belong to the synthetic dots; 2 means the first medium
        // record. Every later cursor is the medium's canonical byte offset.
        let pos = if ctx.pos <= 2 { 0 } else { ctx.pos };
        for entry in &entries {
            if pos > entry.group_start() { continue; }
            // The medium's own dot entries would duplicate the two above.
            if entry.name == "." || entry.name == ".." { continue; }
            let location = ident::location_of(&entry.entry, &node.location);
            let ino = ident::inode_number(&location, Some(&entry.entry));
            let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
            if !ctx.emit(&entry.name, ino, ftype, entry.next_pos()) { break; }
        }
        Ok(())
    }
}

fn fill_fat_dirent(out: &mut [u8], name: &[u8], off: u64, ino: u64) {
    out.fill(0);
    out[..8].copy_from_slice(&ino.to_ne_bytes());
    out[8..16].copy_from_slice(&off.to_ne_bytes());
    let len = core::cmp::min(name.len(), 255);
    out[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
    out[18..18 + len].copy_from_slice(&name[..len]);
}

/// Whether an inode names a directory this filesystem can read. Kept as a
/// function so the location rule has one owner. # C: O(1)
pub fn is_directory(location: &DirLocation) -> bool {
    !matches!(location, DirLocation::Entry { .. })
}

#[cfg(test)]
mod tests {
    use super::fill_fat_dirent;

    #[test]
    fn fat_ioctl_dirent_uses_linux_native_offsets() {
        let mut bytes = [0u8; 280];
        fill_fat_dirent(&mut bytes, b"SHORT.TXT", 0x1122_3344, 0x5566_7788);
        assert_eq!(u64::from_ne_bytes(bytes[..8].try_into().unwrap()), 0x5566_7788);
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 0x1122_3344);
        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 9);
        assert_eq!(&bytes[18..27], b"SHORT.TXT");
        assert!(bytes[27..].iter().all(|b| *b == 0));
    }
}
