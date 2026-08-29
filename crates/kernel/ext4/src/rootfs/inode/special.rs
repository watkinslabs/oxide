use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use vfs::file_ops::{FileIoctlCmd, FileIoctlReply, FileOps};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{InodeOps, mk_mode};
use vfs::{DirContext, FileType, Inode, InodeRef, KResult, VfsError};

use super::data::{Ext4StatData, ext4_file_ino, get_inode_xattr, remove_inode_xattr, set_inode_xattr};
use super::ids::ext4_wrap_ino;
use super::super::state::RootfsState;

/// `inode_operations` for any non-regular ext4 inode. Namespace ops gate on
/// the stored `FileType` (a non-directory rejects `lookup`/`mkdir`/... with
/// `Enotdir`, a non-symlink rejects `readlink` with `Einval`), matching the
/// old per-impl guards. Shared (ZST). # C: O(1)
pub(crate) struct Ext4StatInodeOps;

impl Ext4StatInodeOps {
    fn data(inode: &Inode) -> KResult<&Ext4StatData> {
        inode.private::<Ext4StatData>().ok_or(VfsError::Eio)
    }

    /// The VFS delete path has already resolved the victim under the parent's
    /// exclusive i_rwsem. Reuse that identity when it belongs to this mount,
    /// just as ext4's `->unlink`/`->rmdir` receives the dentry-selected inode.
    /// Name-only callers retain the authoritative directory lookup fallback.
    fn victim_ino(d: &Ext4StatData, victim: &InodeRef) -> Option<u32> {
        let (st, ino) = super::data::ext4_state_of(victim)?;
        Arc::ptr_eq(&st.mount, &d.st.mount).then_some(ino)
    }

    fn create_impl(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx,
                   check_existing: bool) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if check_existing && d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, 0);
        let acl = crate::acl::inherit(inode, m, ctx.umask, vfs::posix_acl::NewKind::Other)?;
        super::super::quota::charge_new_inode(&d.st, d.ino, acl.mode, uid, gid)?;
        // The canonical VFS inode is the same parent image that lookup used.
        // Pass it through the Linux-shaped create owner when available; a
        // non-canonical helper inode has no safe lifetime/invalidator and uses
        // the ordinary mount entry point instead.
        let parent_raw = if d.canonical { d.mutation_parent(inode) } else { None };
        let created = match parent_raw.as_ref() {
            Some(parent) => d.st.mount.create_file_inode_with_acl_parent(
                parent, name.as_bytes(), acl.mode & 0o7777, uid, gid, &acl),
            None => d.st.mount.create_file_inode_with_acl(
                d.ino, name.as_bytes(), acl.mode & 0o7777, uid, gid, &acl),
        };
        let (ino, node) = match created {
            Ok(v) => v,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, acl.mode, uid, gid);
                return Err(super::regular::fs_err(&d.st, e));
            }
        };
        d.st.forget_created_ino(ino);
        d.refresh_namespace_size(inode);
        Ok(d.st.wrap_created_file(ino, &node))
    }

    fn mkdir_impl(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx,
                  check_existing: bool) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if !super::links::dir_link_headroom(inode.nlink()) {
            let pdir = d.st.mount.read_inode(d.ino).map_err(super::regular::vfs_error_from_mount)?;
            if super::links::dir_link_max_reached(
                pdir.links_count, pdir.i_flags, d.st.mount.sb.feature_ro_compat) {
                return Err(VfsError::Emlink);
            }
        }
        if check_existing && d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o1777, vfs::types::S_IFDIR, ctx.cred, 0);
        let acl = crate::acl::inherit(inode, m, ctx.umask, vfs::posix_acl::NewKind::Dir)?;
        super::super::quota::charge_new_inode(&d.st, d.ino, acl.mode, uid, gid)?;
        let parent_raw = if d.canonical { d.mutation_parent(inode) } else { None };
        let created = match parent_raw.as_ref() {
            Some(parent) => d.st.mount.create_dir_inode_with_acl_parent(
                parent, name.as_bytes(), acl.mode & 0o7777, uid, gid, &acl),
            None => d.st.mount.create_dir_inode_with_acl(
                d.ino, name.as_bytes(), acl.mode & 0o7777, uid, gid, &acl),
        };
        let (ino, node) = match created {
            Ok(v) => v,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, acl.mode, uid, gid);
                return Err(super::regular::fs_err(&d.st, e));
            }
        };
        // Linux ext4_mkdir increments both the serialized parent and the live
        // VFS inode while the parent's exclusive i_rwsem is held. Keep the
        // parsed ext4 image used by later creates/lookups in step as well.
        inode.inc_nlink();
        if let Some(parent) = parent_raw.as_ref() {
            let mut current = parent.clone();
            current.links_count = current.links_count.saturating_add(1);
            d.publish_raw(current);
        } else {
            d.invalidate_raw();
        }
        d.refresh_namespace_size(inode);
        d.st.forget_created_ino(ino);
        Ok(d.st.wrap_created_any(ino, &node))
    }

    fn rmdir_impl(&self, inode: &Inode, name: &str, victim: Option<&InodeRef>) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = victim.and_then(|v| Self::victim_ino(d, v))
            .or_else(|| d.st.lookup_child_ino(d.ino, name))
            .ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if !i.is_dir() { return Err(VfsError::Enotdir); }
        if !super::rename::ext4_empty_dir(mount, &i) { return Err(VfsError::Enotempty); }
        super::super::quota::release_existing_inode_usage(&d.st, &i)?;
        if let Err(e) = mount.run_journaled_deferred(|m| m.rmdir(d.ino, name.as_bytes())) {
            let _ = super::super::quota::rollback_existing_inode_release(&d.st, &i);
            return Err(super::regular::vfs_error_from_mount(e));
        }
        super::super::quota::drop_existing_inode_dquots(&d.st, target);
        if let Some(sb) = d.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(target)) { victim.set_nlink(0); }
        }
        inode.drop_nlink();
        // Unlinking a child does not change this directory's lookup geometry:
        // i_size, i_flags, and the inode generation remain valid. Keep the
        // Linux-shaped in-core directory image; the changed dir block is read
        // from the metadata cache/shadow on the next lookup.
        Ok(())
    }

    fn unlink_impl(&self, inode: &Inode, name: &str, victim: Option<&InodeRef>) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = victim.and_then(|v| Self::victim_ino(d, v))
            .or_else(|| d.st.lookup_child_ino(d.ino, name))
            .ok_or(VfsError::Enoent)?;
        if let Some(victim) = victim {
            // `vfs_unlink` already resolved this inode and ran the type gate;
            // Linux ext4 does not reread it merely to rediscover S_ISDIR.
            if victim.file_type() == FileType::Directory { return Err(VfsError::Eisdir); }
        } else if mount.read_inode(target).map_err(|_| VfsError::Eio)?.is_dir() {
            // Direct name-only callers have no resolved victim to trust.
            return Err(VfsError::Eisdir);
        }
        let out = mount.run_journaled_deferred(|m| m.unlink(d.ino, name.as_bytes()))
            .map_err(super::regular::vfs_error_from_mount)?;
        d.st.after_unlink(out)?;
        // Removing a name changes contents, not the directory inode fields
        // used to select and verify its lookup blocks. Retain the parsed
        // in-core image as Linux does; the metadata block itself is coherent
        // through the mount cache/shadow owner.
        Ok(())
    }
}

impl InodeOps for Ext4StatInodeOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let raw = d.raw.lock().clone();
        // The snapshot belongs to the mounted inode identity. Standalone
        // path-helper users can run before VFS publishes a superblock, when
        // each wrapper is necessarily a fresh object and its snapshot cannot
        // be invalidated by another wrapper's namespace mutation.
        let cached = d.canonical
            && d.raw_valid.load(core::sync::atomic::Ordering::Acquire)
            && raw.size == inode.size()
            && raw.i_flags == d.raw_flags.load(core::sync::atomic::Ordering::Relaxed);
        #[cfg(feature = "debug-resolve-cost")]
        let _dir_lookup_cost = vfs::resolve_cost::ext4_dir_lookup();
        let child = if cached {
            let start = d.dir_start_lookup.load(core::sync::atomic::Ordering::Relaxed);
            let found = d.st.mount.lookup_in_dir_hint(&raw, name.as_bytes(), start);
            if let Ok((_, block)) = found {
                d.dir_start_lookup.store(block, core::sync::atomic::Ordering::Relaxed);
            }
            found.map(|(ino, _)| ino)
        } else {
            let (fresh, child) = d.st.lookup_child_ino_with_inode(d.ino, name)
                .map_err(|e| if matches!(e, crate::MountError::NotFound) {
                    VfsError::Enoent
                } else { super::regular::vfs_error_from_mount(e) })?;
            d.publish_raw(fresh);
            Ok(child)
        }.map_err(|e| if matches!(e, crate::MountError::NotFound) {
            VfsError::Enoent
        } else { super::regular::vfs_error_from_mount(e) })?;
        #[cfg(feature = "debug-resolve-cost")]
        drop(_dir_lookup_cost);
        #[cfg(feature = "debug-resolve-cost")]
        let _inode_wrap_cost = vfs::resolve_cost::ext4_inode_wrap();
        let result = d.st.wrap_any_ino(child).ok_or(VfsError::Enoent);
        #[cfg(feature = "debug-resolve-cost")]
        drop(_inode_wrap_cost);
        result
    }

    /// `ext4_getattr` for the non-regular inodes (directories, symlinks, device
    /// nodes): the same on-disk attribute report as the regular-file path.
    /// # C: O(1) + one inode read
    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap,
               request_mask: u32, query_flags: u32) -> vfs::getattr::Kstat
    {
        let _ = (request_mask, query_flags);
        let mut k = vfs::getattr::generic_fillattr(inode, idmap);
        if let Some(d) = inode.private::<Ext4StatData>() {
            // Same as the regular-file arm: the block count and the flags word
            // are in memory, and `ext4_getattr` reads no block to answer a stat.
            let raw = d.raw_flags.load(core::sync::atomic::Ordering::Relaxed);
            let (a, mask) = crate::inode::flags::statx_attributes(raw);
            k.attributes |= a;
            k.attributes_mask |= mask;
        }
        k
    }

    fn setattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, ia: &vfs::Iattr) -> KResult<()> {
        super::meta::ext4_setattr(inode, idmap, ia)
    }

    /// `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` on a directory / special inode.
    /// # C: O(1) [+ 1 journaled write on set]
    fn fileattr_get(&self, inode: &Inode) -> KResult<vfs::FileAttr> {
        super::meta::ext4_fileattr_get(inode)
    }
    fn fileattr_set(&self, inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
        super::meta::ext4_fileattr_set(inode, fa)
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, vfs::XattrError> {
        get_inode_xattr(inode, name)
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        set_inode_xattr(inode, name, value, create, replace)
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        remove_inode_xattr(inode, name)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, vfs::XattrError> {
        super::data::list_inode_xattrs(inode)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Symlink) { return Err(VfsError::Einval); }
        let mount = &d.st.mount;
        let cached = d.raw_valid.load(core::sync::atomic::Ordering::Acquire);
        let i = if cached {
            d.raw.lock().clone()
        } else {
            Arc::new(mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?)
        };
        if let Some(b) = i.fast_symlink_target() { return Ok(b.to_vec()); }
        let blk = mount.read_file_block(&i, 0).map_err(|_| VfsError::Eio)?;
        let n = (d.size as usize).min(blk.len());
        Ok(blk[..n].to_vec())
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        self.mkdir_impl(inode, name, mode, ctx, true)
    }

    fn mkdir_unchecked(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        self.mkdir_impl(inode, name, mode, ctx, false)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        self.rmdir_impl(inode, name, None)
    }

    fn rmdir_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        self.rmdir_impl(inode, name, Some(victim))
    }

    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        self.create_impl(inode, name, mode, ctx, true)
    }

    fn create_unchecked(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        self.create_impl(inode, name, mode, ctx, false)
    }

    fn tmpfile(&self, inode: &Inode, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, 0);
        let acl = crate::acl::inherit(inode, m, ctx.umask, vfs::posix_acl::NewKind::Other)?;
        super::super::quota::charge_new_inode(&d.st, d.ino, acl.mode, uid, gid)?;
        let (ino, node) = match d.st.mount.create_anonymous_inode_with_acl(
            d.ino, acl.mode & 0o7777, uid, gid, &acl) {
            Ok(v) => v,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, acl.mode, uid, gid);
                return Err(super::regular::fs_err(&d.st, e));
            }
        };
        d.st.orphan_insert(ino);
        d.st.forget_created_ino(ino);
        Ok(d.st.wrap_created_file(ino, &node))
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        self.unlink_impl(inode, name, None)
    }

    fn unlink_with_victim(&self, inode: &Inode, name: &str, victim: &InodeRef) -> KResult<()> {
        self.unlink_impl(inode, name, Some(victim))
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if target.file_type() == FileType::Directory { return Err(VfsError::Eperm); }
        let ino = ext4_file_ino(target).ok_or(VfsError::Exdev)?;
        let src = d.st.mount.read_inode(ino).map_err(super::regular::vfs_error_from_mount)?;
        if src.is_dir() { return Err(VfsError::Eperm); }
        // `ext4_link`'s own ceiling — ext4 publishes no `s_max_links`, so the
        // generic `vfs_link` ceiling never fires and this is the only one.
        if super::links::link_max_reached(src.links_count) { return Err(VfsError::Emlink); }
        match d.st.lookup_child_ino_result(d.ino, name) {
            Ok(_) => return Err(VfsError::Eexist),
            Err(crate::MountError::NotFound) => {}
            Err(e) => return Err(super::regular::vfs_error_from_mount(e)),
        }
        super::super::ops::project_inherit_allows_child(&d.st.mount, d.ino, ino)?;
        // Hardlinking a chardev/blockdev/FIFO/socket must plant ITS type, not
        // a blanket DT_REG that is then wrong on disk forever.
        let ftype = super::super::ops::dirent_dt(&src);
        let name_b = name.as_bytes();
        d.st.mount.run_journaled_deferred(|m| {
            m.dir_link_in_transaction(d.ino, name_b, ino, ftype)?;
            m.adjust_nlink(ino, 1)?;
            m.orphan_del(ino)?;
            Ok(())
        }).map_err(super::regular::vfs_error_from_mount)?;
        d.st.orphan_remove(ino);
        target.inc_nlink();
        d.invalidate_raw();
        // `ext4_append()` may have grown this directory. Publish the live
        // VFS i_size as well as invalidating the lookup image; Linux updates
        // both fields on the same in-core directory inode.
        d.refresh_namespace_size(inode);
        Ok(())
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx) -> KResult<()> {
        self.symlink_impl(inode, name, target, ctx, true)
    }

    fn symlink_unchecked(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx) -> KResult<()> {
        self.symlink_impl(inode, name, target, ctx, false)
    }

    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx) -> KResult<()> {
        self.mknod_impl(inode, name, mode, rdev, ctx, true)
    }

    fn mknod_unchecked(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx) -> KResult<()> {
        self.mknod_impl(inode, name, mode, rdev, ctx, false)
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32, _ctx: &vfs::CreateCtx)
        -> KResult<()>
    {
        super::rename::ext4_rename2(inode, old_name, new_dir, new_name, flags)
    }
}

impl Ext4StatInodeOps {
    fn symlink_impl(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx,
                    check_existing: bool) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if check_existing && d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid) = vfs::prepare_symlink_owner(ctx.idmap, inode, ctx.cred);
        let mode = vfs::types::S_IFLNK | 0o777;
        super::super::quota::charge_new_inode(&d.st, d.ino, mode, uid, gid)?;
        let parent_raw = d.mutation_parent(inode);
        let created = match parent_raw.as_ref() {
            Some(parent) => d.st.mount.create_symlink_with_parent(
                parent, name.as_bytes(), target, uid, gid),
            None => d.st.mount.create_symlink(d.ino, name.as_bytes(), target, uid, gid),
        };
        let ino = match created {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, mode, uid, gid);
                return Err(super::regular::vfs_error_from_mount(e));
            }
        };
        d.st.forget_created_ino(ino);
        d.refresh_namespace_size(inode);
        Ok(())
    }

    fn mknod_impl(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx,
                  check_existing: bool) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if check_existing && d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode,
            mode, mode, ctx.cred, 0);
        let acl = crate::acl::inherit(inode, m, ctx.umask, vfs::posix_acl::NewKind::Other)?;
        super::super::quota::charge_new_inode(&d.st, d.ino, acl.mode, uid, gid)?;
        let parent_raw = d.mutation_parent(inode);
        let created = match parent_raw.as_ref() {
            Some(parent) => d.st.mount.create_mknod_with_acl_parent(
                parent, name.as_bytes(), acl.mode, rdev, uid, gid, &acl),
            None => d.st.mount.create_mknod_with_acl(
                d.ino, name.as_bytes(), acl.mode, rdev, uid, gid, &acl),
        };
        let ino = match created {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, acl.mode, uid, gid);
                return Err(super::regular::fs_err(&d.st, e));
            }
        };
        d.st.forget_created_ino(ino);
        d.refresh_namespace_size(inode);
        Ok(())
    }
}

/// `file_operations` for a non-regular ext4 inode: `iterate`/readdir for a
/// directory, the `S_IFMT` default (`EISDIR`/`EINVAL`) otherwise. Shared
/// (ZST). # C: O(1)
pub(crate) struct Ext4StatFileOps;

fn ext4_dirent_name(name: &[u8]) -> alloc::string::String {
    vfs::path_from_bytes(name)
}

impl FileOps for Ext4StatFileOps {
    /// `ext4_sync_file` — Linux installs the same `fsync` slot on
    /// `ext4_dir_operations`, so `fsync(dirfd)` commits the directory's
    /// metadata rather than silently succeeding. # C: O(journal tx)
    fn fsync(&self, file: &vfs::File, datasync: bool) -> KResult<()> {
        super::regular::ext4_sync_file(file.inode(), datasync)
    }

    fn unlocked_ioctl(
        &self,
        file: &vfs::File,
        idmap: &vfs::idmap::Idmap,
        cred: &vfs::Cred,
        cmd: FileIoctlCmd,
    ) -> KResult<FileIoctlReply> {
        match cmd {
            FileIoctlCmd::GetVersion =>
                Ok(FileIoctlReply::U32(super::meta::ext4_getversion(file.inode())?)),
            FileIoctlCmd::SetVersionPrepare => {
                super::meta::ext4_setversion_prepare(file.inode(), idmap, cred)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::SetVersion(gen) => {
                super::meta::ext4_setversion(file.inode(), gen)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::GetFsLabel =>
                Ok(FileIoctlReply::Label(super::meta::ext4_getfslabel(file.inode())?)),
            FileIoctlCmd::SetFsLabelPrepare(cap) => {
                super::meta::ext4_setfslabel_prepare(cap)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::SetFsLabel(label) => {
                super::meta::ext4_setfslabel(file.inode(), label)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::FitTrimPrepare(cap) => {
                super::meta::ext4_fitrim_prepare(cap)?;
                Ok(FileIoctlReply::Done)
            }
            FileIoctlCmd::FitTrim { start, len, minlen } => {
                super::meta::ext4_fitrim(start, len, minlen)?;
                Ok(FileIoctlReply::Done)
            }
            _ => Err(VfsError::Enotty),
        }
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        // Directory size can grow during namespace mutation; until the
        // mutation owner publishes that size into the cached image, re-read
        // it so readdir cannot omit a newly allocated directory block.
        let dir_inode = mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?;
        let bs = mount.sb.block_size as u64;
        // `EXT4_FEATURE_INCOMPAT_FILETYPE` is what makes byte 7 of a directory
        // record a `d_type`. On an ext2-style image without it that byte is the
        // high half of `name_len` (always 0 for a name <= 255), so reading it
        // unconditionally reports DT_UNKNOWN-as-DT_REG for EVERY entry,
        // subdirectories included.
        let has_filetype = (mount.sb.feature_incompat & crate::superblock::INCOMPAT_FILETYPE) != 0;
        // Linux `ext4_readdir`: `ctx->pos` is a BYTE OFFSET into the directory
        // file, advanced by each record's `rec_len`. An ordinal counter instead
        // would (a) shift every following cookie when an entry is inserted or
        // removed, breaking `telldir`/`seekdir` and any paginated `getdents`
        // that races a create/unlink, and (b) force a rescan from block 0 on
        // every call — O(N^2) for one full listing of a large directory.
        let mut pos = ctx.pos;
        while pos < dir_inode.size {
            let blk_idx = (pos / bs) as u32;
            #[cfg(feature = "debug-getdents")]
            ctx.debug_set_backend_block(vfs::DirDebugBackend::Ext4, blk_idx);
            // An unreadable block must NOT look like end-of-directory: Linux
            // propagates the error and the caller keeps whatever was packed.
            let blk = mount.read_file_block(&dir_inode, blk_idx).map_err(|_| VfsError::Eio)?;
            let base = blk_idx as u64 * bs;
            let mut off = (pos - base) as usize;
            while off < blk.len() {
                // A corrupt `rec_len` must surface, not silently truncate the
                // listing into something userspace reads as end-of-directory.
                let (e, next) = crate::dir::next_entry(&blk, off).map_err(|_| VfsError::Eio)?;
                let cookie = base + next as u64;
                if e.inode != 0 {
                    let name = ext4_dirent_name(e.name);
                    if !name.is_empty() {
                        let dt = crate::dir::dirent_dtype(has_filetype, e.file_type);
                        // `d_ino` must be the SAME number `stat` reports. Every
                        // ext4 VFS inode is built with `ext4_wrap_ino`, so the
                        // raw on-disk number here disagreed with `st_ino` on
                        // every entry — which breaks `find -inum`, `getcwd(3)`'s
                        // `..`-walk fallback, and tar/rsync hardlink detection,
                        // all of which compare the two.
                        let d_ino = super::ids::ext4_wrap_ino(e.inode);
                        if !ctx.emit_dt(&name, d_ino, dt, cookie) { return Ok(()); }
                    }
                }
                off = next;
            }
            pos = base + bs;
        }
        ctx.pos = dir_inode.size;
        Ok(())
    }

    fn iterate_emits_dots(&self) -> bool { true }
}

/// Build a stat/dir/symlink/dev `vfs::Inode` for ext4 inode `ino`. The
/// captured on-disk metadata (`ft`/`perm`/`size`/`nlink`/`rdev`) is read by
/// the caller before the `iget` build closure. `rdev` is only meaningful for
/// CHR/BLK nodes (generic_fillattr reads it for those types only). # C: O(1)
pub(crate) fn build_stat_inode(
    st: Arc<RootfsState>, ino: u32, ft: FileType, perm: u16, size: u64, nlink: u32, rdev: u32,
    uid: u32, gid: u32, projid: u32, times: crate::timestamp::InodeTimes, generation: u32,
    raw_flags: u32, blocks: u64, raw: Arc<crate::inode::Inode>,
) -> InodeRef {
    let canonical = st.i_sb().is_some();
    let fast_link = raw.fast_symlink_target().map(|link| link.to_vec().into_boxed_slice());
    let data = Arc::new(Ext4StatData { st, ino, ft, size, canonical,
        raw_flags: core::sync::atomic::AtomicU32::new(raw_flags),
        raw: ::sync::Spinlock::new(raw),
        raw_valid: core::sync::atomic::AtomicBool::new(true),
        dir_start_lookup: core::sync::atomic::AtomicU32::new(0),
        xattrs: super::data::Ext4XattrState::new(), });
    let weak_sb = data.st.sb.lock().clone();
    let xattrs = vfs::SimpleXattrs::new();
    // Linux `init_special_inode` gives an on-disk `S_IFIFO` the pipe fops, and
    // `fifo_open` attaches an `i_pipe` whose `rd_wait`/`wr_wait` are the poll
    // queues — independent of the backing filesystem. A FIFO
    // that lives on ext4 must therefore carry a subscriber list exactly like
    // `vfs::make_fifo_inode` and the tmpfs one; without it `fs::pipe`'s
    // `inode.poll_subscribers()` is `None` at every notify site and a
    // poll/epoll waiter on the FIFO subscribes to nothing.
    let mut b = InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(ft, perm),
                      Arc::new(Ext4StatInodeOps), Arc::new(Ext4StatFileOps));
    if ft == FileType::Directory
        && raw_flags & crate::inode::flags::EXT4_CASEFOLD_FL != 0
    { b = b.i_flags(vfs::inode::S_CASEFOLD); }
    if vfs::special_inode_needs_poll_subs(ft) { b = b.poll_subs(vfs::PollSubscribers::new()); }
    // Linux publishes a valid fast symlink body as inode->i_link. Keep the
    // immutable inline bytes on the VFS inode, but only after the ext4 layout
    // predicate has excluded inline-data inodes.
    if let Some(link) = fast_link { b = b.link(link); }
    b = b
        .sb(weak_sb)
        .size(size)
        .blocks(blocks)
        .nlink(nlink)
        .rdev(rdev)
        .owner(uid, gid)
        .projid(projid)
        .generation(generation)
        .times(times.atime, times.mtime, times.ctime)
        .xattrs(xattrs)
        .private(data);
    // Only an inode whose extra region reaches `i_crtime` reports STATX_BTIME
    // (Linux `ext4_getattr`); leaving it unset is how the VFS says "absent".
    if let Some(bt) = times.btime { b = b.btime(bt); }
    b.build()
}

#[cfg(test)]
mod tests {
    use super::ext4_dirent_name;

    #[test]
    fn ext4_dirent_name_preserves_non_utf8_bytes() {
        let raw = b"dir-\xff-entry";
        let name = ext4_dirent_name(raw);
        assert_eq!(vfs::path_into_bytes(&name), raw);
    }
}
