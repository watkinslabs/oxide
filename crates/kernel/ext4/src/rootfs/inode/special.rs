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
        let bs = mount.sb.block_size as u64;
        let nblocks = ((i.size + bs - 1) / bs) as u32;
        for blk_idx in 0..nblocks {
            let Ok(blk) = mount.read_file_block(&i, blk_idx) else { break };
            let mut nonempty = false;
            let _ = crate::iter_active(&blk, |e| {
                if e.name.is_empty() || e.name == b"." || e.name == b".." { return true; }
                nonempty = true;
                false
            });
            if nonempty { return Err(VfsError::Enotempty); }
        }
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
        let ftype = if src.is_link() { crate::DT_LNK } else { crate::DT_REG };
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
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let nd = new_dir.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
        if !matches!(nd.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if !Arc::ptr_eq(&d.st, &nd.st) { return Err(VfsError::Exdev); }
        let (from_p, to_p) = (d.ino, nd.ino);
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(from_p, old_name).ok_or(VfsError::Enoent)?;
        if from_p == to_p && old_name == new_name && flags & vfs::namei::RENAME_EXCHANGE == 0 { return Ok(()); }
        let dest_victim = d.st.lookup_child_ino(to_p, new_name);
        super::super::ops::project_inherit_allows_child(mount, to_p, target)?;
        if flags & vfs::namei::RENAME_EXCHANGE != 0 {
            let bino = dest_victim.ok_or(VfsError::Enoent)?;
            super::super::ops::project_inherit_allows_child(mount, from_p, bino)?;
            if from_p == to_p && old_name == new_name { return Ok(()); }
            let src = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
            let dst = mount.read_inode(bino).map_err(|_| VfsError::Eio)?;
            let (from_name, to_name) = (old_name.as_bytes(), new_name.as_bytes());
            return mount.run_journaled(|m| {
                m.dir_unlink(from_p, from_name)?;
                m.dir_unlink(to_p, to_name)?;
                m.dir_link(from_p, from_name, bino, super::super::ops::dirent_dt(&dst))?;
                m.dir_link(to_p, to_name, target, super::super::ops::dirent_dt(&src))?;
                Ok(())
            }).map_err(|_| VfsError::Eio);
        }
        let src = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        let ftype = super::super::ops::dirent_dt(&src);
        let (from_name, to_name) = (old_name.as_bytes(), new_name.as_bytes());
        let dest_is_dir = dest_victim
            .and_then(|v| mount.read_inode(v).ok())
            .map(|i| i.is_dir())
            .unwrap_or(false);
        let dest_raw = dest_victim.and_then(|v| mount.read_inode(v).ok());
        const WHITEOUT_MODE: u16 = crate::inode::S_IFCHR;
        let whiteout = flags & vfs::namei::RENAME_WHITEOUT != 0;
        let dest_quota_released = dest_raw.as_ref().map_or(Ok(false),
            |raw| super::super::quota::pre_release_existing_inode_if_final(&d.st, raw))?;
        if whiteout {
            if let Err(e) = super::super::quota::charge_new_inode(&d.st, from_p, WHITEOUT_MODE, 0, 0) {
                if dest_quota_released { if let Some(raw) = dest_raw.as_ref() { let _ = super::super::quota::rollback_existing_inode_release(&d.st, raw); } }
                return Err(e);
            }
        }
        let rename = mount.run_journaled(|m| {
            if dest_victim.is_some() {
                if dest_is_dir { m.rmdir(to_p, to_name)?; } else { m.unlink(to_p, to_name)?; }
            }
            m.dir_link(to_p, to_name, target, ftype)?;
            m.dir_unlink(from_p, from_name)?;
            if whiteout { m.create_mknod(from_p, from_name, WHITEOUT_MODE, 0, 0, 0)?; }
            Ok(())
        });
        if let Err(e) = rename {
            mount.refresh_cached_meta();
            if whiteout {
                let _ = super::super::quota::rollback_new_inode_charge(&d.st, from_p, WHITEOUT_MODE, 0, 0);
            }
            if dest_quota_released { if let Some(raw) = dest_raw.as_ref() { let _ = super::super::quota::rollback_existing_inode_release(&d.st, raw); } }
            return Err(super::regular::vfs_error_from_mount(e));
        }
        if let Some(victim_ino) = dest_victim {
            if let Some(sb) = d.st.i_sb() {
                if let Some(victim) = sb.ilookup(ext4_wrap_ino(victim_ino)) {
                    if dest_is_dir { victim.set_nlink(0); } else { victim.drop_link(); }
                }
            }
            if dest_quota_released { super::super::quota::drop_existing_inode_dquots(&d.st, victim_ino); }
        }
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
        let off = ctx.pos;
        let mut idx: u64 = 0;
        let bs = mount.sb.block_size as u64;
        let nblocks = ((dir_inode.size + bs - 1) / bs) as u32;
        let mut keep_going = true;
        for blk_idx in 0..nblocks {
            if !keep_going { break; }
            #[cfg(feature = "debug-getdents")]
            ctx.debug_set_backend_block(DEBUG_GETDENTS_EXT4_BACKEND, blk_idx);
            let Ok(blk) = mount.read_file_block(&dir_inode, blk_idx) else { break };
            let _ = crate::iter_active(&blk, |e| {
                let name = ext4_dirent_name(e.name);
                if name.is_empty() { return true; }
                idx += 1;
                if idx <= off { return true; }
                let ft = match e.file_type {
                    1 => FileType::Regular,
                    2 => FileType::Directory,
                    3 => FileType::CharDev,
                    4 => FileType::BlockDev,
                    5 => FileType::Fifo,
                    6 => FileType::Socket,
                    7 => FileType::Symlink,
                    _ => FileType::Regular,
                };
                let keep = ctx.emit(&name, e.inode as u64, ft, idx);
                if !keep { keep_going = false; }
                keep
            });
        }
        Ok(())
    }
}

#[cfg(feature = "debug-getdents")]
const DEBUG_GETDENTS_EXT4_BACKEND: &[u8] = b"ext4";

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
