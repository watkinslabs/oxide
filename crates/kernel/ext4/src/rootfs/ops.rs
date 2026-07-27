use alloc::sync::Arc;

mod mountfs;

use block::types::InodeId;
use super::inode::{build_file_inode, build_stat_inode, ext4_wrap_ino};
use super::state::RootfsState;

pub use mountfs::{Ext4Mount, Ext4SuperOps};

/// ext4 dirent `file_type` byte for an inode's `S_IFMT` (Linux
/// `ext4_type_by_mode` / `fs/ext4/dir.c`). Used by the atomic
/// exchange/whiteout dirent rewrites so a swapped char/block/fifo/sock
/// entry keeps its correct `d_type`, not a blanket `DT_REG`. # C: O(1)
pub(crate) fn dirent_dt(i: &crate::Inode) -> u8 {
    match i.mode & crate::inode::S_IFMT {
        crate::inode::S_IFDIR  => crate::dir::DT_DIR,
        crate::inode::S_IFLNK  => crate::dir::DT_LNK,
        crate::inode::S_IFCHR  => crate::dir::DT_CHR,
        crate::inode::S_IFBLK  => crate::dir::DT_BLK,
        crate::inode::S_IFIFO  => crate::dir::DT_FIFO,
        crate::inode::S_IFSOCK => crate::dir::DT_SOCK,
        _                      => crate::dir::DT_REG,
    }
}

/// Linux ext4 `PROJINHERIT` boundary check: hardlink/rename into a project
/// inheriting directory requires the moved inode's project id to match the
/// destination directory, otherwise `-EXDEV`. # C: O(1) inode reads
pub(crate) fn project_inherit_allows_child(
    mount: &crate::Mount,
    parent_ino: u32,
    child_ino: u32,
) -> Result<(), vfs::VfsError> {
    let parent = mount.read_inode(parent_ino).map_err(|_| vfs::VfsError::Eio)?;
    if parent.i_flags & vfs::inode::FS_PROJINHERIT_FL == 0 { return Ok(()); }
    let child = mount.read_inode(child_ino).map_err(|_| vfs::VfsError::Eio)?;
    if parent.i_projid == child.i_projid { Ok(()) } else { Err(vfs::VfsError::Exdev) }
}

fn namei_error_from_mount(e: crate::MountError) -> vfs::VfsError {
    match e {
        crate::MountError::NotFound | crate::MountError::Dir(crate::dir::DirError::NotFound) => vfs::VfsError::Enoent,
        crate::MountError::NotDir => vfs::VfsError::Enotdir,
        crate::MountError::NoSpace | crate::MountError::DirFull
            | crate::MountError::Dir(crate::dir::DirError::Full) => vfs::VfsError::Enospc,
        crate::MountError::Inode(crate::InodeError::BadLen)
            | crate::MountError::Dir(crate::dir::DirError::BadNameLen)
            | crate::MountError::UnsupportedFeature => vfs::VfsError::Einval,
        crate::MountError::Quota(e) => e,
        _ => vfs::VfsError::Eio,
    }
}

impl RootfsState {
    /// A freshly allocated ext4 inode number may have a stale VFS inode-cache
    /// slot from a prior unlinked object with the same ino. Drop it before
    /// wrapping the new on-disk type, or `iget` can return the old FileType.
    /// # C: O(log N_ino)
    pub(crate) fn forget_created_ino(&self, ino: u32) {
        self.page_cache.invalidate(InodeId(ino as u64));
        if let Some(sb) = self.i_sb() { sb.iforget(ext4_wrap_ino(ino)); }
    }

    /// Wrap `ino` (any type): regular → writeable file inode; else
    /// stat-only inode. Both carry `self` (via `i_private`) so ops route
    /// through this mount.
    /// # C: O(1) inode read
    pub fn wrap_any_ino(self: &Arc<Self>, ino: u32) -> Option<vfs::InodeRef> {
        let inode = self.mount.read_inode(ino).ok()?;
        if inode.is_reg() { return self.wrap_file(ino); }
        // Map every ext4 `S_IFMT` type to its VFS `FileType` (not just
        // dir/link → Regular): a char/block node must surface as CharDev/
        // BlockDev so `getattr` reports `st_rdev`, and FIFO/SOCK so stat's
        // mode type-bits are correct.
        let ft = match inode.mode & crate::inode::S_IFMT {
            crate::inode::S_IFDIR  => vfs::FileType::Directory,
            crate::inode::S_IFLNK  => vfs::FileType::Symlink,
            crate::inode::S_IFCHR  => vfs::FileType::CharDev,
            crate::inode::S_IFBLK  => vfs::FileType::BlockDev,
            crate::inode::S_IFIFO  => vfs::FileType::Fifo,
            crate::inode::S_IFSOCK => vfs::FileType::Socket,
            _                     => vfs::FileType::Regular,
        };
        let size = inode.size as u64;
        let perm = inode.mode & 0o7777;
        // `st_rdev` is only meaningful for CHR/BLK; ext4 stores it inline.
        let rdev = if matches!(ft, vfs::FileType::CharDev | vfs::FileType::BlockDev) { inode.rdev() } else { 0 };
        let nlink = inode.links_count as u32;
        let (uid, gid, projid) = (inode.uid, inode.gid, inode.i_projid);
        let times = (inode.atime_ns, inode.mtime_ns, inode.ctime_ns, inode.crtime_ns);
        let st = self.clone();
        let build = move || build_stat_inode(st, ino, ft, perm, size, nlink, rdev, uid, gid, projid, times);
        // Route through the SB inode cache so a repeated lookup of the same ino
        // returns the SAME `Arc` (shared inode identity, Linux `iget`). Before
        // the SB is back-stamped (during `fs.root()`) build directly.
        Some(match self.i_sb() {
            Some(sb) => sb.iget(ext4_wrap_ino(ino), build),
            None => build(),
        })
    }

    /// Wrap regular-file `ino` in a deferred-bytes file inode.
    /// # C: O(1) inode read
    pub fn wrap_file(self: &Arc<Self>, ino: u32) -> Option<vfs::InodeRef> {
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        let size = inode.size;
        let mode = inode.mode;
        let (uid, gid, projid) = (inode.uid, inode.gid, inode.i_projid);
        let times = (inode.atime_ns, inode.mtime_ns, inode.ctime_ns, inode.crtime_ns);
        let nlink = inode.links_count as u32;
        let st = self.clone();
        let build = move || build_file_inode(st, ino, mode, size, nlink, uid, gid, projid, times);
        // Shared identity via the SB inode cache (Linux `iget`).
        Some(match self.i_sb() {
            Some(sb) => sb.iget(ext4_wrap_ino(ino), build),
            None => build(),
        })
    }

    /// Resolve `path` to a stat tuple for any file type.
    /// # C: O(path components × dir size)
    pub fn stat_path(&self, path: &[u8]) -> Option<(u32, vfs::FileType, u64)> {
        let ino = self.mount.lookup_path(path).ok()?;
        let inode = self.mount.read_inode(ino).ok()?;
        let ft = if inode.is_dir() { vfs::FileType::Directory }
                 else if inode.is_reg() { vfs::FileType::Regular }
                 else if inode.is_link() { vfs::FileType::Symlink }
                 else { vfs::FileType::Regular };
        Some((ino, ft, inode.size as u64))
    }

    /// Wrap any-type inode at `path` (stat consumers).
    /// # C: O(path components)
    pub fn lookup_inode_any(self: &Arc<Self>, path: &[u8]) -> Option<vfs::InodeRef> {
        let ino = self.lookup_path(path)?;
        self.wrap_any_ino(ino)
    }

    /// Wrap regular file at `path` (open path).
    /// # C: O(path components)
    pub fn lookup_inode(self: &Arc<Self>, path: &[u8]) -> Option<vfs::InodeRef> {
        let ino = self.mount.lookup_path(path).ok()?;
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        self.wrap_file(ino)
    }

    fn parent_inode<'a>(&self, path: &'a [u8]) -> Option<(u32, &'a [u8])> {
        let (parent, name) = split_parent_and_name(path)?;
        let pino = self.mount.lookup_path(parent).ok()?;
        Some((pino, name))
    }

    /// Create regular file at `path`.
    /// # C: O(N parent entries)
    pub fn create_at(self: &Arc<Self>, path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> {
        let (pino, name) = self.parent_inode(path)?;
        let parent = self.wrap_any_ino(pino)?;
        let ctx = vfs::CreateCtx::root();
        let (uid, gid, mode) = vfs::prepare_create_owner_mode(ctx.idmap, &parent, mode_perm,
            0o7777, vfs::types::S_IFREG, ctx.cred, ctx.umask);
        super::quota::charge_new_inode(self, pino, mode, uid, gid).ok()?;
        let new_ino = match self.mount.create_file(pino, name, mode & 0o7777, uid, gid) {
            Ok(ino) => ino,
            Err(_) => {
                let _ = super::quota::rollback_new_inode_charge(self, pino, mode, uid, gid);
                return None;
            }
        };
        self.forget_created_ino(new_ino);
        self.wrap_file(new_ino)
    }

    /// Create anonymous (O_TMPFILE) file in `dir_path`; tracked orphan.
    /// # C: O(1) inode alloc + 1 I/O
    pub fn create_anonymous_at(self: &Arc<Self>, dir_path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> {
        let dir_ino = self.mount.lookup_path(dir_path).ok()?;
        let mode = vfs::S_IFREG as u16 | (mode_perm & 0o7777);
        super::quota::charge_new_inode(self, dir_ino, mode, 0, 0).ok()?;
        let new_ino = match self.mount.create_anonymous(dir_ino, mode_perm) {
            Ok(ino) => ino,
            Err(_) => {
                let _ = super::quota::rollback_new_inode_charge(self, dir_ino, mode, 0, 0);
                return None;
            }
        };
        self.orphan_insert(new_ino);
        self.forget_created_ino(new_ino);
        self.wrap_file(new_ino)
    }

    /// Free orphan inode (nlink==0).
    /// # C: O(N_extents) block-free + 1 inode-free
    pub fn free_orphan_inode(&self, ino: u32) -> Result<(), vfs::VfsError> {
        let raw = self.mount.read_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
        if raw.links_count != 0 { return Ok(()); }
        self.mount.free_orphan_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
        let quota = super::quota::release_existing_inode_retry(self, ino, &raw);
        self.page_cache.invalidate(InodeId(ino as u64));
        quota
    }

    /// Link an existing inode under `link_path` (linkat AT_EMPTY_PATH).
    /// # C: O(N parent entries)
    pub fn link_inode_at(&self, ino: u32, link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let inode = self.mount.read_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eperm); }
        let ftype = dirent_dt(&inode);
        let (parent_ino, name_owned) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        if self.mount.lookup_path(link_path).is_ok() { return Err(vfs::VfsError::Eexist); }
        project_inherit_allows_child(&self.mount, parent_ino, ino)?;
        let name: alloc::vec::Vec<u8> = name_owned.to_vec();
        self.mount.run_journaled(|m| {
            m.dir_link(parent_ino, &name, ino, ftype)?;
            m.adjust_nlink(ino, 1)?;
            // The inode now has a name → off the on-disk orphan list
            // (Linux `ext4_orphan_del` in `ext4_link`/`ext4_tmpfile` linkat).
            m.orphan_del(ino)?;
            Ok(())
        }).map_err(namei_error_from_mount)?;
        self.orphan_remove(ino);
        Ok(())
    }

    /// # C: O(N parent entries) + (free blocks if last link)
    pub fn unlink_at(&self, path: &[u8]) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        let target = self.mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eisdir); }
        let final_link = inode.links_count <= 1;
        if final_link { super::quota::release_existing_inode_usage(self, &inode)?; }
        let name = name.to_vec();
        if let Err(e) = self.mount.run_journaled(|m| m.unlink(pino, &name)) {
            if final_link { let _ = super::quota::rollback_existing_inode_release(self, &inode); }
            return Err(namei_error_from_mount(e));
        }
        if final_link { super::quota::drop_existing_inode_dquots(self, target); }
        self.page_cache.invalidate(InodeId(target as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn symlink_at(self: &Arc<Self>, target: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        if self.mount.lookup_path(link_path).is_ok() { return Err(vfs::VfsError::Eexist); }
        let parent = self.wrap_any_ino(pino).ok_or(vfs::VfsError::Eio)?;
        let ctx = vfs::CreateCtx::root();
        let (uid, gid) = vfs::prepare_symlink_owner(ctx.idmap, &parent, ctx.cred);
        let mode = vfs::types::S_IFLNK | 0o777;
        super::quota::charge_new_inode(self, pino, mode, uid, gid)?;
        let new_ino = match self.mount.create_symlink(pino, name, target, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::quota::rollback_new_inode_charge(self, pino, mode, uid, gid);
                return Err(namei_error_from_mount(e));
            }
        };
        self.forget_created_ino(new_ino);
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mknod_at(self: &Arc<Self>, path: &[u8], mode: u16, rdev: u32) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        if self.mount.lookup_path(path).is_ok() { return Err(vfs::VfsError::Eexist); }
        let parent = self.wrap_any_ino(pino).ok_or(vfs::VfsError::Eio)?;
        let ctx = vfs::CreateCtx::root();
        let (uid, gid, mode) = vfs::prepare_create_owner_mode(ctx.idmap, &parent, mode,
            mode, mode, ctx.cred, ctx.umask);
        super::quota::charge_new_inode(self, pino, mode, uid, gid)?;
        let new_ino = match self.mount.create_mknod(pino, name, mode, rdev, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::quota::rollback_new_inode_charge(self, pino, mode, uid, gid);
                return Err(namei_error_from_mount(e));
            }
        };
        self.forget_created_ino(new_ino);
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mkdir_at(self: &Arc<Self>, path: &[u8], mode_perm: u16) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        if self.mount.lookup_path(path).is_ok() { return Err(vfs::VfsError::Eexist); }
        let parent = self.wrap_any_ino(pino).ok_or(vfs::VfsError::Eio)?;
        let ctx = vfs::CreateCtx::root();
        let (uid, gid, mode) = vfs::prepare_create_owner_mode(ctx.idmap, &parent, mode_perm,
            0o1777, vfs::types::S_IFDIR, ctx.cred, ctx.umask);
        super::quota::charge_new_inode(self, pino, mode, uid, gid)?;
        let new_ino = match self.mount.create_dir(pino, name, mode & 0o7777, uid, gid) {
            Ok(ino) => ino,
            Err(e) => {
                let _ = super::quota::rollback_new_inode_charge(self, pino, mode, uid, gid);
                return Err(namei_error_from_mount(e));
            }
        };
        self.forget_created_ino(new_ino);
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn rmdir_at(&self, path: &[u8]) -> Result<(), vfs::VfsError> {
        let target = self.mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if !inode.is_dir() { return Err(vfs::VfsError::Enotdir); }
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        super::quota::release_existing_inode_usage(self, &inode)?;
        let name = name.to_vec();
        if let Err(e) = self.mount.run_journaled(|m| m.rmdir(pino, &name)) {
            let _ = super::quota::rollback_existing_inode_release(self, &inode);
            return Err(namei_error_from_mount(e));
        }
        super::quota::drop_existing_inode_dquots(self, target);
        Ok(())
    }

    /// Hardlink `target_path` → `link_path`.
    /// # C: O(N parent entries)
    pub fn link_at(&self, target_path: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let target = self.mount.lookup_path(target_path).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eperm); }
        let (parent_ino, name_owned) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        if self.mount.lookup_path(link_path).is_ok() { return Err(vfs::VfsError::Eexist); }
        project_inherit_allows_child(&self.mount, parent_ino, target)?;
        let name: alloc::vec::Vec<u8> = name_owned.to_vec();
        let ftype = dirent_dt(&inode);
        self.mount.run_journaled(|m| {
            m.dir_link(parent_ino, &name, target, ftype)?;
            m.adjust_nlink(target, 1)?;
            Ok(())
        }).map_err(namei_error_from_mount)
    }

    /// Resolve the two pathnames of a path-based rename into the object
    /// identities the shared `ext4_rename2` core consumes. # C: O(path)
    fn rename_sides_at<'a>(&'a self, from: &[u8], to: &[u8])
        -> Result<(super::inode::RenameSides<'a>, alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), vfs::VfsError>
    {
        let target = self.mount.lookup_path(from).map_err(|_| vfs::VfsError::Enoent)?;
        let (from_p, from_name) = self.parent_inode(from).ok_or(vfs::VfsError::Enoent)?;
        let from_name = from_name.to_vec();
        let (to_p, to_name) = self.parent_inode(to).ok_or(vfs::VfsError::Enoent)?;
        let to_name = to_name.to_vec();
        let dest_victim = self.mount.lookup_path(to).ok();
        Ok((super::inode::RenameSides { st: self, from_p, to_p, target, dest_victim }, from_name, to_name))
    }

    /// Plain path-based rename. Shares `ext4_rename2`'s body with the
    /// `i_op->rename` entry, so ENOTEMPTY, the `..` repoint, the parent
    /// `i_links_count` fixups and the timestamp stamps cannot diverge between
    /// the two callers. # C: O(N parent entries) + 1 journaled tx
    pub fn rename_at(&self, from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
        let (s, from_name, to_name) = self.rename_sides_at(from, to)?;
        super::inode::rename_sides(&s, &from_name, &to_name, 0)
    }

    /// `RENAME_EXCHANGE` (Linux `ext4_cross_rename`): swap the two existing
    /// entries ATOMICALLY in ONE journaled transaction — both names point at
    /// each other's inode after, neither inode's own link count moves, and a
    /// cross-parent swap repoints each directory's `..` and shifts the parent
    /// link counts by `ext4_update_dir_count`'s delta.
    /// # C: O(N parent entries) + 1 journaled tx
    pub fn exchange_at(&self, a: &[u8], b: &[u8]) -> Result<(), vfs::VfsError> {
        let (s, aname, bname) = self.rename_sides_at(a, b)?;
        if s.dest_victim.is_none() { return Err(vfs::VfsError::Enoent); }
        super::inode::rename_sides(&s, &aname, &bname, vfs::namei::RENAME_EXCHANGE)
    }

    /// `RENAME_WHITEOUT` (the overlayfs lower-layer-delete primitive): rename
    /// `from`→`to` AND plant a whiteout at the vacated source — a character
    /// device with rdev 0:0 (`S_IFCHR | 0`), owner root — ATOMICALLY in ONE
    /// journaled transaction. # C: O(N parent entries) + 1 journaled tx
    pub fn whiteout_at(&self, from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
        let (s, from_name, to_name) = self.rename_sides_at(from, to)?;
        super::inode::rename_sides(&s, &from_name, &to_name, vfs::namei::RENAME_WHITEOUT)
    }
}

/// Split `/a/b/c` into (`/a/b`, `c`). None for paths without a basename.
fn split_parent_and_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.is_empty() || path[0] != b'/' { return None; }
    let pos = path.iter().rposition(|&c| c == b'/')?;
    let parent = if pos == 0 { &path[..1] } else { &path[..pos] };
    let name   = &path[pos + 1..];
    if name.is_empty() { return None; }
    Some((parent, name))
}
