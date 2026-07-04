use alloc::sync::Arc;
use alloc::vec::Vec;

use block::types::InodeId;
use vfs::file_ops::FileOps;
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{InodeOps, mk_mode};
use vfs::{DirContext, FileType, Inode, InodeRef, KResult, VfsError};

use super::data::{Ext4StatData, ext4_file_ino, persist_inode_xattrs};
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

    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, overlay: Option<vfs::inode_times::InodeTimes>)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap, overlay);
        if let Some(d) = inode.private::<Ext4StatData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
        }
        k
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.set(name, value, create, replace)?;
        persist_inode_xattrs(inode);
        Ok(())
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.remove(name)?;
        persist_inode_xattrs(inode);
        Ok(())
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
        let perm = ctx.apply_umask(mode) as u16;
        d.st.mount.create_dir(d.ino, name.as_bytes(), perm, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        let child = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Eio)?;
        d.st.wrap_any_ino(child).ok_or(VfsError::Eio)
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
        mount.dir_unlink(d.ino, name.as_bytes()).map_err(|_| VfsError::Eio)?;
        let _ = mount.free_inode(target);
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
        let perm = ctx.apply_umask(mode) as u16;
        let ino = d.st.mount.create_file(d.ino, name.as_bytes(), perm, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        d.st.wrap_file(ino).ok_or(VfsError::Eio)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if i.is_dir() { return Err(VfsError::Eisdir); }
        mount.unlink(d.ino, name.as_bytes()).map_err(|_| VfsError::Eio)?;
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
        let src = d.st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
        if src.is_dir() { return Err(VfsError::Eperm); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ftype = if src.is_link() { crate::DT_LNK } else { crate::DT_REG };
        let name_b = name.as_bytes();
        d.st.mount.run_journaled(|m| {
            m.dir_link(d.ino, name_b, ino, ftype)?;
            m.adjust_nlink(ino, 1)?;
            m.orphan_del(ino)?;
            Ok(())
        }).map_err(|_| VfsError::Eio)?;
        d.st.orphan_remove(ino);
        d.st.page_cache.invalidate(InodeId(ino as u64));
        target.inc_nlink();
        Ok(())
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ino = d.st.mount.create_symlink(d.ino, name.as_bytes(), target, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let mode = (mode & crate::inode::S_IFMT) | (ctx.apply_umask((mode & 0o7777) as u32) as u16);
        let ino = d.st.mount.create_mknod(d.ino, name.as_bytes(), mode, rdev, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32, _ctx: &vfs::CreateCtx)
        -> KResult<()>
    {
        if flags & (vfs::namei::RENAME_EXCHANGE | vfs::namei::RENAME_WHITEOUT) != 0 {
            return Err(VfsError::Einval);
        }
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let nd = new_dir.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
        if !matches!(nd.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if !Arc::ptr_eq(&d.st, &nd.st) { return Err(VfsError::Exdev); }
        let (from_p, to_p) = (d.ino, nd.ino);
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(from_p, old_name).ok_or(VfsError::Enoent)?;
        let src = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        let ftype = if src.is_dir() { crate::DT_DIR } else if src.is_link() { crate::DT_LNK } else { crate::DT_REG };
        let (from_name, to_name) = (old_name.as_bytes(), new_name.as_bytes());
        let dest_victim = d.st.lookup_child_ino(to_p, new_name);
        let dest_is_dir = dest_victim
            .and_then(|v| mount.read_inode(v).ok())
            .map(|i| i.is_dir())
            .unwrap_or(false);
        mount.run_journaled(|m| {
            if dest_victim.is_some() { let _ = m.dir_unlink(to_p, to_name); }
            m.dir_link(to_p, to_name, target, ftype)?;
            m.dir_unlink(from_p, from_name)?;
            Ok(())
        }).map_err(|_| VfsError::Eio)?;
        if let Some(victim_ino) = dest_victim {
            if let Some(sb) = d.st.i_sb() {
                if let Some(victim) = sb.ilookup(ext4_wrap_ino(victim_ino)) {
                    if dest_is_dir { victim.set_nlink(0); } else { victim.drop_link(); }
                }
            }
        }
        Ok(())
    }
}

/// `file_operations` for a non-regular ext4 inode: `iterate`/readdir for a
/// directory, the `S_IFMT` default (`EISDIR`/`EINVAL`) otherwise. Shared
/// (ZST). # C: O(1)
pub(crate) struct Ext4StatFileOps;

impl FileOps for Ext4StatFileOps {
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
            let Ok(blk) = mount.read_file_block(&dir_inode, blk_idx) else { break };
            let _ = crate::iter_active(&blk, |e| {
                let name = match core::str::from_utf8(e.name) {
                    Ok(s) => s, Err(_) => return true,
                };
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
                let keep = ctx.emit(name, e.inode as u64, ft, idx);
                if !keep { keep_going = false; }
                keep
            });
        }
        Ok(())
    }
}

/// Build a stat/dir/symlink/dev `vfs::Inode` for ext4 inode `ino`. The
/// captured on-disk metadata (`ft`/`perm`/`size`/`nlink`/`rdev`) is read by
/// the caller before the `iget` build closure. `rdev` is only meaningful for
/// CHR/BLK nodes (generic_fillattr reads it for those types only). # C: O(1)
pub(crate) fn build_stat_inode(
    st: Arc<RootfsState>, ino: u32, ft: FileType, perm: u16, size: u64, nlink: u32, rdev: u32, uid: u32, gid: u32,
) -> InodeRef {
    let data = Arc::new(Ext4StatData { st, ino, ft, size });
    let weak_sb = data.st.sb.lock().clone();
    let xattrs = vfs::SimpleXattrs::new();
    data.st.mount.load_xattrs(ino, &xattrs);
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(ft, perm),
                      Arc::new(Ext4StatInodeOps), Arc::new(Ext4StatFileOps))
        .sb(weak_sb)
        .size(size)
        .nlink(nlink)
        .rdev(rdev)
        .owner(uid, gid)
        .xattrs(xattrs)
        .private(data)
        .build()
}
