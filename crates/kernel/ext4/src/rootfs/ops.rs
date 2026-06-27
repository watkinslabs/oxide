// Per-mount inode-wrapping + namei helpers (create/unlink/symlink/
// link/rename) on `RootfsState`. Split from `state.rs` to stay under
// the 1000-line file cap; same `RootfsState` type.

use alloc::sync::Arc;

use block::types::InodeId;
use ::sync as sync;
use super::inode::{Ext4FileInode, Ext4StatInode};
use super::state::RootfsState;

impl RootfsState {
    /// Wrap `ino` (any type): regular → writeable `Ext4FileInode`;
    /// else stat-only `Ext4StatInode`. Both carry `self` so ops route
    /// through this mount.
    /// # C: O(1) inode read
    pub fn wrap_any_ino(self: &Arc<Self>, ino: u32) -> Option<vfs::InodeRef> {
        let inode = self.mount.read_inode(ino).ok()?;
        if inode.is_reg() { return self.wrap_file(ino); }
        let ft = if inode.is_dir() { vfs::FileType::Directory }
                 else if inode.is_link() { vfs::FileType::Symlink }
                 else { vfs::FileType::Regular };
        Some(Arc::new(Ext4StatInode {
            st: self.clone(), ino, ft,
            size: inode.size as u64, perm: (inode.mode & 0o7777) as u16,
        }) as vfs::InodeRef)
    }

    /// Wrap regular-file `ino` in a deferred-bytes `Ext4FileInode`.
    /// # C: O(1) inode read
    pub fn wrap_file(self: &Arc<Self>, ino: u32) -> Option<vfs::InodeRef> {
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        Some(Arc::new(Ext4FileInode {
            st: self.clone(),
            ino,
            size_hint: core::sync::atomic::AtomicU64::new(inode.size),
            bytes: sync::Spinlock::new(None),
        }) as vfs::InodeRef)
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
        let new_ino = self.mount.create_file(pino, name, mode_perm).ok()?;
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
        let new_ino = self.mount.create_symlink(pino, name, target).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(new_ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mknod_at(&self, path: &[u8], mode: u16, rdev: u32) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        let new_ino = self.mount.create_mknod(pino, name, mode, rdev).map_err(|_| vfs::VfsError::Eio)?;
        self.page_cache.invalidate(InodeId(new_ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    pub fn mkdir_at(&self, path: &[u8], mode_perm: u16) -> Result<(), vfs::VfsError> {
        let (pino, name) = self.parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
        self.mount.create_dir(pino, name, mode_perm).map_err(|_| vfs::VfsError::Eio)?;
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
        let dest_exists = self.mount.lookup_path(to).is_ok();
        self.mount.run_journaled(|m| {
            if dest_exists { let _ = m.dir_unlink(to_p, &to_name); }
            m.dir_link(to_p, &to_name, target, ftype)?;
            m.dir_unlink(from_p, &from_name)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)
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
    fn root(&self) -> Option<vfs::InodeRef> { self.st.wrap_any_ino(2) }
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> { self.st.lookup_inode_any(path.as_bytes()) }
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
        let ino = inode.as_any()
            .and_then(|a| a.downcast_ref::<Ext4FileInode>())
            .map(|i| i.ext4_ino())
            .ok_or(vfs::VfsError::Exdev)?;
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
