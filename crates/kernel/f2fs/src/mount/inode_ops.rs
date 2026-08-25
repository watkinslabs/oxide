use super::*;

impl InodeOps for F2fsOps {
    fn swapfile_backing(&self, inode: &InodeRef)
        -> KResult<Option<alloc::sync::Arc<dyn core::any::Any + Send + Sync>>> {
        let node = Self::node(inode)?;
        let map = node.fs.volume_now().swap_activate(node.ino, u64::MAX)
            .map_err(errno_to_vfs)?;
        let device = match crate::swap::device::F2fsSwapDevice::new(
            node.fs.clone(), node.ino, map) {
            Ok(device) => device,
            Err(error) => {
                let _ = node.fs.volume_now().swap_deactivate(node.ino);
                return Err(match error {
                    block::BlockError::Einval => VfsError::Einval,
                    _ => VfsError::Eio,
                });
            }
        };
        let uuid = node.fs.volume.lock().super_block().uuid;
        let id = u64::from_le_bytes(uuid[..8].try_into().unwrap_or([0; 8]));
        let name = alloc::format!("f2fs:{id}:{ino}", ino = node.ino);
        let raw_device = node.fs.swap_devices()[0].clone();
        Ok(Some(alloc::sync::Arc::new(pmm::swap::SwapFileBacking {
            name,
            device: alloc::sync::Arc::new(device),
            resume_device: None,
            resume_pages: alloc::vec::Vec::new(),
            raw_device,
        })))
    }

    /// Expose the volume's validated fs-verity descriptor to union filesystems
    /// without creating a second digest implementation. # C: O(descriptor + chain)
    fn verity_digest(&self, inode: &Inode) -> KResult<Option<(u8, Vec<u8>)>> {
        let node = Self::node(inode)?;
        let live = node.live()?;
        if !live.verity() { return Ok(None); }
        let info = node.fs.volume.lock().verity_info(&live, node.ino).map_err(errno_to_vfs)?;
        Ok(Some((info.params.hash_alg, info.file_digest)))
    }

    /// `file_update_time` for buffered and shared-mapping writes. The inode
    /// stamp is persisted by the same volume owner that serves setattr and
    /// fallocate, so mapped writes cannot create a second timestamp truth.
    /// # C: O(1 block)
    fn update_time(&self, inode: &Inode, now: vfs::Timespec64, flags: u32) -> KResult<()> {
        let node = Self::node(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        vfs::generic_update_time(inode, now, flags)?;
        if flags & (vfs::S_MTIME | vfs::S_CTIME) != 0 {
            let stamp = (now.sec.max(0) as u64, now.nsec);
            node.fs.volume_now().stamp_modified(node.ino, stamp).map_err(errno_to_vfs)?;
        }
        Ok(())
    }

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
        node.fs.volume.lock().crypt_check_link(node.ino, other.ino)
            .map_err(errno_to_vfs)?;
        node.fs.link(node.ino, name, other.ino)?;
        // The count on the medium moved, and the cached one has to move with
        // it: a temporary file that has just been given its first name would
        // otherwise keep reporting no links, which is what tells a caller the
        // file disappears when the handle does.
        target.inc_nlink();
        Ok(())
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        node.fs.remove(node.ino, name, false)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        node.fs.remove(node.ino, name, true)
    }

    /// The flags reach the volume UNREDUCED. An exchange or a whiteout narrowed
    /// to "replace or not" on the way down reports success for an operation
    /// that did not happen, and the caller's next step assumes it did.
    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              ctx: &CreateCtx) -> KResult<()> {
        let node = Self::writable_dir(inode)?;
        let (target, _) = Self::dir_of(new_dir)?;
        // Both directories are on one volume by construction: a rename across
        // filesystems never reaches a backend.
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        // What the two directories will be worth AFTERWARDS is decided from
        // what they hold NOW: a directory arriving in a parent brings its own
        // second entry with it, and a directory leaving takes one away.
        let (moved_is_dir, victim_is_dir) = Self::shapes(node, old_name, target, new_name);
        let same_parent = node.ino == target.ino;
        node.fs.volume.lock().crypt_check_rename(node.ino, old_name.as_bytes(), target.ino,
                                                 new_name.as_bytes(), flags)
            .map_err(errno_to_vfs)?;
        // The identity is the CALLER's, and only a whiteout reads it: the
        // marker a whiteout rename leaves behind is a new inode and belongs to
        // whoever asked for the rename.
        node.fs.rename(node.ino, old_name, target.ino, new_name, flags,
                       (ctx.fsuid(), ctx.fsgid()))?;
        // The counts on the medium moved above; these are the CACHED ones the
        // same `stat` reads without going back to the medium.
        if flags & vfs::namei::RENAME_EXCHANGE != 0 {
            if !same_parent && moved_is_dir != victim_is_dir.unwrap_or(false) {
                if moved_is_dir { inode.drop_nlink(); new_dir.inc_nlink(); }
                else { new_dir.drop_nlink(); inode.inc_nlink(); }
            }
        } else if moved_is_dir {
            // A replaced directory surrendered the destination's incoming link
            // as it was removed, so the destination already balances the
            // arriving one and only the source parent drops.
            if victim_is_dir.is_some() { inode.drop_nlink(); }
            else if !same_parent { inode.drop_nlink(); new_dir.inc_nlink(); }
        }
        Ok(())
    }

    /// A file with no name, which the volume keeps on the same orphan list an
    /// unlink of an open file uses.
    fn tmpfile(&self, inode: &Inode, mode_bits: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let (node, dir) = Self::dir_of(inode)?;
        if !node.fs.is_writable() { return Err(VfsError::Erofs); }
        // A file with no name is still a file created in this directory: it takes
        // the same owner preparation and the same inherited ACL as a named one,
        // because a later `linkat` gives it a name without revisiting either.
        let (uid, gid, prepared) =
            prepare::owner_mode(inode, FileType::Regular, mode_bits as u16, ctx);
        let got = prepare::inherited(node, &dir, prepared, ctx.umask,
                                     vfs::posix_acl::NewKind::Other)?;
        let child = node.fs.tmpfile(node.ino, mk_mode(FileType::Regular, u32::from(got.mode)),
                                    uid, gid)?;
        if got.access.is_some() || got.default.is_some() {
            prepare::store_inherited(node, Self::node(&child)?.ino, &got)?;
        }
        Ok(child)
    }

    /// `f2fs_fallocate`. The mode word arrives raw: the generic layer vets the
    /// COMBINATION, and every refusal that depends on this volume's or this
    /// file's state is `mount::falloc`'s. # C: O(blocks the range covers)
    fn fallocate(&self, inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
        super::super::falloc::fallocate(inode, mode, off, len)
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
        // A mode change has to reach the ACL as well as `i_mode`, or a `chmod`
        // that narrows access would narrow only what `ls -l` prints.
        if ia.valid & ATTR_MODE != 0 { prepare::acl_chmod(inode)?; }
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
