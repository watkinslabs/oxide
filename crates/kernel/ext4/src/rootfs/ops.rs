// Per-mount inode-wrapping + namei helpers (create/unlink/symlink/
// link/rename) on `RootfsState`. Split from `state.rs` to stay under
// the 1000-line file cap; same `RootfsState` type.

use alloc::sync::Arc;

use block::types::InodeId;
use super::inode::{build_file_inode, build_stat_inode, ext4_file_ino, ext4_wrap_ino};
use super::state::RootfsState;

impl RootfsState {
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
        let nlink = if inode.links_count != 0 { inode.links_count as u32 }
                    else if matches!(ft, vfs::FileType::Directory) { 2 } else { 1 };
        let (uid, gid) = (inode.uid, inode.gid);
        let st = self.clone();
        let build = move || build_stat_inode(st, ino, ft, perm, size, nlink, rdev, uid, gid);
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
        let (uid, gid) = (inode.uid, inode.gid);
        let nlink = if inode.links_count != 0 { inode.links_count as u32 } else { 1 };
        let st = self.clone();
        let build = move || build_file_inode(st, ino, mode, size, nlink, uid, gid);
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
        let new_ino = self.mount.create_file(pino, name, mode_perm, 0, 0).ok()?;
        self.page_cache.invalidate(InodeId(new_ino as u64));
        self.wrap_file(new_ino)
    }

    /// Create anonymous (O_TMPFILE) file in `dir_path`; tracked orphan.
    /// # C: O(1) inode alloc + 1 I/O
    pub fn create_anonymous_at(self: &Arc<Self>, dir_path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> {
        let dir_ino = self.mount.lookup_path(dir_path).ok()?;
        let new_ino = self.mount.create_anonymous(dir_ino, mode_perm).ok()?;
        self.orphan_insert(new_ino);
        self.page_cache.invalidate(InodeId(new_ino as u64));
        self.wrap_file(new_ino)
    }

    /// Free orphan inode (nlink==0).
    /// # C: O(N_extents) block-free + 1 inode-free
    pub fn free_orphan_inode(&self, ino: u32) -> Result<(), vfs::VfsError> {
        self.mount.free_orphan_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    /// Link an existing inode under `link_path` (linkat AT_EMPTY_PATH).
    /// # C: O(N parent entries)
    pub fn link_inode_at(&self, ino: u32, link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let inode = self.mount.read_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eperm); }
        let ftype = if inode.is_link() { crate::DT_LNK } else { crate::DT_REG };
        let (parent_ino, name_owned) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        let name: alloc::vec::Vec<u8> = name_owned.to_vec();
        self.mount.run_journaled(|m| {
            m.dir_link(parent_ino, &name, ino, ftype)?;
            m.adjust_nlink(ino, 1)?;
            // The inode now has a name → off the on-disk orphan list
            // (Linux `ext4_orphan_del` in `ext4_link`/`ext4_tmpfile` linkat).
            m.orphan_del(ino)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)?;
        self.orphan_remove(ino);
        Ok(())
    }

    /// # C: O(N parent entries) + (free blocks if last link)
    pub fn unlink_at(&self, path: &[u8]) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        let target = self.mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
        self.mount.unlink(pino, name).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(target as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn symlink_at(&self, target: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        let new_ino = self.mount.create_symlink(pino, name, target, 0, 0).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(new_ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mknod_at(&self, path: &[u8], mode: u16, rdev: u32) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        let new_ino = self.mount.create_mknod(pino, name, mode, rdev, 0, 0).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(new_ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mkdir_at(&self, path: &[u8], mode_perm: u16) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        self.mount.create_dir(pino, name, mode_perm, 0, 0).map_err(|_| vfs::VfsError::Eio)?;
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn rmdir_at(&self, path: &[u8]) -> Result<(), vfs::VfsError> {
        let target = self.mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if !inode.is_dir() { return Err(vfs::VfsError::Enotdir); }
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        self.mount.dir_unlink(pino, name).map_err(|_| vfs::VfsError::Eio)?;
        let _ = self.mount.free_inode(target);
        Ok(())
    }

    /// Hardlink `target_path` → `link_path`.
    /// # C: O(N parent entries)
    pub fn link_at(&self, target_path: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
        let target = self.mount.lookup_path(target_path).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eperm); }
        let (parent_ino, name_owned) = self.parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
        let name: alloc::vec::Vec<u8> = name_owned.to_vec();
        let ftype = if inode.is_link() { crate::DT_LNK } else { crate::DT_REG };
        self.mount.run_journaled(|m| {
            m.dir_link(parent_ino, &name, target, ftype)?;
            m.adjust_nlink(target, 1)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)
    }

    /// # C: O(1)
    pub fn rename_at(&self, from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
        let target = self.mount.lookup_path(from).map_err(|_| vfs::VfsError::Enoent)?;
        let inode = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        let (from_p, from_name_owned) = self.parent_inode(from).ok_or(vfs::VfsError::Enoent)?;
        let from_name: alloc::vec::Vec<u8> = from_name_owned.to_vec();
        let (to_p, to_name_owned) = self.parent_inode(to).ok_or(vfs::VfsError::Enoent)?;
        let to_name: alloc::vec::Vec<u8> = to_name_owned.to_vec();
        let ftype = if inode.is_dir() { crate::DT_DIR } else if inode.is_link() { crate::DT_LNK } else { crate::DT_REG };
        // Replaced destination (plain rename = non-EXCHANGE; RENAME_EXCHANGE
        // routes through `exchange`, which only ever renames into a vacated temp
        // name, so it never reaches this overwrite path). Capture the victim's
        // ino + dir-ness before the dir entry is removed so its in-memory nlink
        // can be dropped after (Linux `vfs_rename`: the replaced inode loses its
        // link).
        let dest_victim = self.mount.lookup_path(to).ok();
        let dest_is_dir = dest_victim
            .and_then(|v| self.mount.read_inode(v).ok())
            .map(|i| i.is_dir())
            .unwrap_or(false);
        self.mount.run_journaled(|m| {
            if dest_victim.is_some() { let _ = m.dir_unlink(to_p, &to_name); }
            m.dir_link(to_p, &to_name, target, ftype)?;
            m.dir_unlink(from_p, &from_name)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)?;
        // In-memory nlink authority (mirror `unlink`): the dcache `d_unlink` no
        // longer touches nlink, so the FS drops the CACHED victim's link here. A
        // directory target is fully unlinked (clear to 0: it loses both its `.`
        // self-link and its parent's reference). Uncached → nothing to drop.
        if let Some(victim_ino) = dest_victim {
            if let Some(sb) = self.i_sb() {
                if let Some(victim) = sb.ilookup(ext4_wrap_ino(victim_ino)) {
                    if dest_is_dir { victim.set_nlink(0); } else { victim.drop_link(); }
                }
            }
        }
        Ok(())
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

/// `super_operations` for an ext4 mount (Linux `ext4_statfs`): live on-disk
/// block/inode accounting read from the per-mount `RootfsState`. Installed as
/// the SB's `s_op` by `FileSystem::super_ops`, replacing the generic
/// `FsBackedSuperOps` (which reported only `f_type`/`f_bsize`).
pub struct Ext4SuperOps { st: Arc<RootfsState> }

impl Ext4SuperOps {
    /// # C: O(1)
    pub fn new(st: Arc<RootfsState>) -> Self { Self { st } }
}

impl vfs::SuperOps for Ext4SuperOps {
    /// Report this mount's real totals (parsed superblock) + live free
    /// counters (`state_free_blocks`/`state_free_inodes`, which mirror
    /// `s_free_blocks_count`/`s_free_inodes_count`). `f_fsid` is left 0 →
    /// `SuperBlock::statfs` fills it from `s_dev`. # C: O(1)
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> {
        let m = &self.st.mount;
        let free_blocks = m.state_free_blocks();
        let free_inodes = m.state_free_inodes() as u64;
        Ok(vfs::SbStatFs {
            f_type:   crate::EXT4_SUPER_MAGIC as u64,
            f_bsize:  m.sb.block_size,
            f_blocks: m.sb.blocks_count_lo as u64,
            f_bfree:  free_blocks,
            f_bavail: free_blocks,
            f_files:  m.sb.inodes_count as u64,
            f_ffree:  free_inodes,
            f_fsid:   0,
            f_flags:  0, // per-MOUNT ST_* filled at the syscall layer (calculate_f_flags)
        })
    }

    /// `sync_fs` (Linux `ext4_sync_fs`): the journal commits each
    /// `run_journaled` transaction synchronously, so there is no open
    /// transaction to force — push any pending tx, then barrier the backing
    /// device so committed metadata is durable. # C: O(1) + 1 device flush
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        self.st.mount.flush_pending_tx().map_err(|_| vfs::VfsError::Eio)?;
        self.st.mount.dev.flush().map_err(|_| vfs::VfsError::Eio)?;
        Ok(())
    }

    /// `freeze_fs` (Linux `ext4_freeze`, FIFREEZE): writers are already
    /// blocked by the VFS `freeze_super` (B155); flush + barrier the journal
    /// to leave a consistent on-disk image, then mark the mount frozen so a
    /// double freeze is rejected at the VFS layer. # C: O(1) + 1 device flush
    fn freeze_fs(&self) -> vfs::KResult<()> {
        self.sync_fs(true)?;
        self.st.frozen.store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// `thaw_fs`/`unfreeze_fs` (Linux `ext4_unfreeze`, FITHAW): resume normal
    /// operation. # C: O(1)
    fn thaw_fs(&self) -> vfs::KResult<()> {
        self.st.frozen.store(false, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}

/// FileSystem instance over a single, non-root ext4 mount. Carries its
/// own `RootfsState`; all methods route through `self.st` — the
/// de-singletonised counterpart to the root `Ext4RootfsFs`. Built via
/// `Ext4Mount::open`; boot wiring (kmain) adopts it in a later stage.
pub struct Ext4Mount { pub(super) st: Arc<RootfsState> }

impl Ext4Mount {
    /// Open `dev` as an independent ext4 mount instance.
    /// # C: O(N_groups + 1024)
    pub fn open(dev: Arc<dyn block::BlockDevice>) -> block::types::KResult<Arc<Self>> {
        let st = RootfsState::open(dev)?;
        Ok(Arc::new(Self { st }))
    }
    /// Borrow this instance's per-mount state (tests / introspection).
    /// # C: O(1)
    pub fn state(&self) -> &Arc<RootfsState> { &self.st }
}

impl vfs::fs::FileSystem for Ext4Mount {
    fn name(&self) -> &str { "ext4" }
    fn magic(&self) -> u64 { crate::EXT4_SUPER_MAGIC as u64 }
    /// ext4 is block-device backed (Linux `FS_REQUIRES_DEV`): drives the D23
    /// new-mount-API source check + `/proc/filesystems` (no `nodev`). # C: O(1)
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    /// On-disk `s_blocksize` (`1024 << s_log_block_size`). # C: O(1)
    fn block_size(&self) -> u32 { self.st.mount.sb.block_size }
    /// Install live ext4 statfs accounting as this SB's `s_op`. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(Ext4SuperOps::new(self.st.clone())))
    }
    fn root(&self) -> Option<vfs::InodeRef> { self.st.wrap_any_ino(2) }
    /// Back-stamp the SB into this mount's own state (Linux `s_fs_info ↔ sb`).
    /// # C: O(1)
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) { self.st.set_sb(sb); }
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        self.st.create_at(path.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enoent)
    }
    fn create_anonymous(&self, dir: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        self.st.create_anonymous_at(dir.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enospc)
    }
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> { self.st.unlink_at(path.as_bytes()) }
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        self.st.link_at(target.as_bytes(), link.as_bytes())
    }
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let ino = ext4_file_ino(&inode).ok_or(vfs::VfsError::Exdev)?;
        self.st.link_inode_at(ino, link.as_bytes())
    }
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        self.st.rename_at(from.as_bytes(), to.as_bytes())
    }
}

impl core::ops::Drop for Ext4Mount {
    /// On unmount, reclaim any still-orphan O_TMPFILE inodes whose last
    /// fd already closed but whose free was deferred — bounded by this
    /// mount's own orphan set, never the root's.
    /// # C: O(N orphans)
    fn drop(&mut self) {
        let orphans: alloc::vec::Vec<u32> = self.st.orphans.lock().drain(..).collect();
        for ino in orphans {
            if let Ok(inode) = self.st.mount.read_inode(ino) {
                if inode.links_count == 0 { let _ = self.st.mount.free_orphan_inode(ino); }
            }
        }
    }
}
