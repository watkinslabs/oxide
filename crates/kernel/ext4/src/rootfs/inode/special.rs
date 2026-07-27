use alloc::sync::Arc;
use alloc::vec::Vec;

use block::types::InodeId;
use vfs::file_ops::{FileIoctlCmd, FileIoctlReply, FileOps};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{InodeOps, mk_mode};
use vfs::{DirContext, FileType, Inode, InodeRef, KResult, VfsError};

use super::data::{Ext4StatData, ext4_file_ino, remove_inode_xattr, set_inode_xattr};
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
}

impl InodeOps for Ext4StatInodeOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let child = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        d.st.wrap_any_ino(child).ok_or(VfsError::Enoent)
    }

    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap);
        if let Some(d) = inode.private::<Ext4StatData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
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

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        set_inode_xattr(inode, name, value, create, replace)
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        remove_inode_xattr(inode, name)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Symlink) { return Err(VfsError::Einval); }
        let mount = &d.st.mount;
        let i = mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?;
        if let Some(b) = i.fast_symlink_target() { return Ok(b.to_vec()); }
        let blk = mount.read_file_block(&i, 0).map_err(|_| VfsError::Eio)?;
        let n = (d.size as usize).min(blk.len());
        Ok(blk[..n].to_vec())
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o1777, vfs::types::S_IFDIR, ctx.cred, ctx.umask);
        super::super::quota::charge_new_inode(&d.st, d.ino, m, uid, gid)?;
        let ino = match d.st.mount.create_dir(d.ino, name.as_bytes(), m & 0o7777, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, m, uid, gid);
                return Err(super::regular::vfs_error_from_mount(e));
            }
        };
        d.st.forget_created_ino(ino);
        d.st.wrap_any_ino(ino).ok_or(VfsError::Eio)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if !i.is_dir() { return Err(VfsError::Enotdir); }
        if !super::rename::ext4_empty_dir(mount, &i) { return Err(VfsError::Enotempty); }
        // On-disk: free the victim's blocks, clear its inode, drop used-dirs,
        // and decrement the parent's link count (ext4_rmdir). Replaces the old
        // dirent-remove + inode-bit-free that leaked the dir's data blocks and
        // never persisted the parent nlink drop.
        super::super::quota::release_existing_inode_usage(&d.st, &i)?;
        if let Err(e) = mount.run_journaled(|m| m.rmdir(d.ino, name.as_bytes())) {
            let _ = super::super::quota::rollback_existing_inode_release(&d.st, &i);
            return Err(super::regular::vfs_error_from_mount(e));
        }
        super::super::quota::drop_existing_inode_dquots(&d.st, target);
        if let Some(sb) = d.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(target)) { victim.set_nlink(0); }
        }
        inode.drop_nlink();
        Ok(())
    }

    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, ctx.umask);
        super::super::quota::charge_new_inode(&d.st, d.ino, m, uid, gid)?;
        let ino = match d.st.mount.create_file(d.ino, name.as_bytes(), m & 0o7777, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, m, uid, gid);
                return Err(super::regular::vfs_error_from_mount(e));
            }
        };
        d.st.forget_created_ino(ino);
        d.st.wrap_file(ino).ok_or(VfsError::Eio)
    }

    fn tmpfile(&self, inode: &Inode, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, ctx.umask);
        super::super::quota::charge_new_inode(&d.st, d.ino, m, uid, gid)?;
        let ino = match d.st.mount.create_anonymous_as(d.ino, m & 0o7777, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, m, uid, gid);
                return Err(super::regular::vfs_error_from_mount(e));
            }
        };
        d.st.orphan_insert(ino);
        d.st.forget_created_ino(ino);
        d.st.wrap_file(ino).ok_or(VfsError::Eio)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if i.is_dir() { return Err(VfsError::Eisdir); }
        let final_link = i.links_count <= 1;
        if final_link { super::super::quota::release_existing_inode_usage(&d.st, &i)?; }
        if let Err(e) = mount.run_journaled(|m| m.unlink(d.ino, name.as_bytes())) {
            if final_link { let _ = super::super::quota::rollback_existing_inode_release(&d.st, &i); }
            return Err(super::regular::vfs_error_from_mount(e));
        }
        if final_link { super::super::quota::drop_existing_inode_dquots(&d.st, target); }
        d.st.page_cache.invalidate(InodeId(target as u64));
        if let Some(sb) = d.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(target)) { victim.drop_link(); }
        }
        Ok(())
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if target.file_type() == FileType::Directory { return Err(VfsError::Eperm); }
        let ino = ext4_file_ino(target).ok_or(VfsError::Exdev)?;
        let src = d.st.mount.read_inode(ino).map_err(super::regular::vfs_error_from_mount)?;
        if src.is_dir() { return Err(VfsError::Eperm); }
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
        d.st.mount.run_journaled(|m| {
            m.dir_link(d.ino, name_b, ino, ftype)?;
            m.adjust_nlink(ino, 1)?;
            m.orphan_del(ino)?;
            Ok(())
        }).map_err(super::regular::vfs_error_from_mount)?;
        d.st.orphan_remove(ino);
        d.st.page_cache.invalidate(InodeId(ino as u64));
        target.inc_nlink();
        Ok(())
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid) = vfs::prepare_symlink_owner(ctx.idmap, inode, ctx.cred);
        let mode = vfs::types::S_IFLNK | 0o777;
        super::super::quota::charge_new_inode(&d.st, d.ino, mode, uid, gid)?;
        let ino = match d.st.mount.create_symlink(d.ino, name.as_bytes(), target, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, mode, uid, gid);
                return Err(super::regular::vfs_error_from_mount(e));
            }
        };
        d.st.forget_created_ino(ino);
        Ok(())
    }

    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let (uid, gid, mode) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode,
            mode, mode, ctx.cred, ctx.umask);
        super::super::quota::charge_new_inode(&d.st, d.ino, mode, uid, gid)?;
        let ino = match d.st.mount.create_mknod(d.ino, name.as_bytes(), mode, rdev, uid, gid) {
            Ok(ino) => ino,
            Err(_) => {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, d.ino, mode, uid, gid);
                return Err(VfsError::Eio);
            }
        };
        d.st.forget_created_ino(ino);
        Ok(())
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32, _ctx: &vfs::CreateCtx)
        -> KResult<()>
    {
        super::rename::ext4_rename2(inode, old_name, new_dir, new_name, flags)
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
    fn fsync(&self, file: &vfs::File, _datasync: bool) -> KResult<()> {
        super::regular::ext4_sync_file(file.inode())
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
        }
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
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
                        if !ctx.emit_dt(&name, e.inode as u64, dt, cookie) { return Ok(()); }
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
    uid: u32, gid: u32, projid: u32, times: (u64, u64, u64, u64),
) -> InodeRef {
    let data = Arc::new(Ext4StatData { st, ino, ft, size });
    let weak_sb = data.st.sb.lock().clone();
    let xattrs = vfs::SimpleXattrs::new();
    data.st.mount.load_xattrs(ino, &xattrs);
    let blocks = data.st.mount.read_inode(ino).map(|i| i.i_blocks as u64).unwrap_or(0);
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(ft, perm),
                      Arc::new(Ext4StatInodeOps), Arc::new(Ext4StatFileOps))
        .sb(weak_sb)
        .size(size)
        .blocks(blocks)
        .nlink(nlink)
        .rdev(rdev)
        .owner(uid, gid)
        .projid(projid)
        .times(times.0, times.1, times.2)
        .btime(times.3)
        .xattrs(xattrs)
        .private(data)
        .build()
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
