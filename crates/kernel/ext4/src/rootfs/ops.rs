// Per-mount inode-wrapping + namei helpers (create/unlink/symlink/
// link/rename) on `RootfsState`. Split from `state.rs` to stay under
// the 1000-line file cap; same `RootfsState` type.

use alloc::sync::Arc;

mod mountfs;

use block::types::InodeId;
use super::inode::{build_file_inode, build_stat_inode, ext4_file_ino, ext4_wrap_ino};
use super::state::RootfsState;

pub use mountfs::{Ext4Mount, Ext4SuperOps};

/// ext4 dirent `file_type` byte for an inode's `S_IFMT` (Linux
/// `ext4_type_by_mode` / `fs/ext4/dir.c`). Used by the atomic
/// exchange/whiteout dirent rewrites so a swapped char/block/fifo/sock
/// entry keeps its correct `d_type`, not a blanket `DT_REG`. # C: O(1)
fn dirent_dt(i: &crate::Inode) -> u8 {
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

    /// `RENAME_EXCHANGE` (Linux `ext4_rename` with the `EXCHANGE` flag): swap
    /// the two existing entries `a` and `b` ATOMICALLY in ONE journaled
    /// transaction — both names point at each other's inode after, and both
    /// inodes' nlink + owning parent are unchanged (an exchange moves no link
    /// counts). Replaces the generic non-atomic 3-step temp-name dance: the
    /// two `dir_unlink`s + two swapped `dir_link`s stage into a single shadow
    /// that `run_journaled` commits as one tx, so a crash mid-swap can never
    /// leave one entry pointing at a freed/temp inode. Caller (`082_rename`)
    /// has pre-checked both exist (ENOENT otherwise).
    ///
    /// Residual (matches the existing plain-rename path, not a new gap): a
    /// cross-parent exchange of two DIRECTORIES does not rewrite their `..`
    /// entries or adjust parent `i_nlink` — this ext4 backend maintains no
    /// `..` fixup on any directory move yet (same limitation in `rename_at`).
    /// # C: O(N parent entries) + 1 journaled tx
    pub fn exchange_at(&self, a: &[u8], b: &[u8]) -> Result<(), vfs::VfsError> {
        let (ap, aname) = split_parent_and_name(a).ok_or(vfs::VfsError::Enoent)?;
        let (bp, bname) = split_parent_and_name(b).ok_or(vfs::VfsError::Enoent)?;
        let apino = self.mount.lookup_path(ap).map_err(|_| vfs::VfsError::Enoent)?;
        let bpino = self.mount.lookup_path(bp).map_err(|_| vfs::VfsError::Enoent)?;
        let aino = self.mount.lookup_path(a).map_err(|_| vfs::VfsError::Enoent)?;
        let bino = self.mount.lookup_path(b).map_err(|_| vfs::VfsError::Enoent)?;
        // Exchanging a name with itself is a no-op (Linux returns 0).
        if apino == bpino && aname == bname { return Ok(()); }
        let aft = dirent_dt(&self.mount.read_inode(aino).map_err(|_| vfs::VfsError::Eio)?);
        let bft = dirent_dt(&self.mount.read_inode(bino).map_err(|_| vfs::VfsError::Eio)?);
        let (aname, bname) = (aname.to_vec(), bname.to_vec());
        self.mount.run_journaled(|m| {
            // Remove both, then re-link SWAPPED — all four ops share one shadow
            // (re-entrant `run_journaled`), committing atomically.
            m.dir_unlink(apino, &aname)?;
            m.dir_unlink(bpino, &bname)?;
            m.dir_link(apino, &aname, bino, bft)?;
            m.dir_link(bpino, &bname, aino, aft)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)
    }

    /// `RENAME_WHITEOUT` (Linux `vfs_rename` with the `WHITEOUT` flag, the
    /// overlayfs lower-layer-delete primitive): rename `from`→`to` AND plant a
    /// whiteout at the vacated source — a character device with rdev 0:0
    /// (`S_IFCHR | 0`) — ATOMICALLY in ONE journaled transaction. Replaces the
    /// generic two-step (rename-then-mknod, which on a mid-crash leaves the
    /// source name gone with no whiteout): the overwrite-unlink + dest link +
    /// source unlink + whiteout `create_mknod` all stage into one shadow that
    /// commits together. `create_mknod` is re-entrant under the open shadow, so
    /// the pre-allocated whiteout inode + its dirent join THIS tx. Whiteout
    /// owner is root (uid/gid 0), mirroring the generic default.
    /// # C: O(N parent entries) + 1 journaled tx
    pub fn whiteout_at(&self, from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
        let (from_p, from_name) = split_parent_and_name(from).ok_or(vfs::VfsError::Enoent)?;
        let (to_p, to_name) = split_parent_and_name(to).ok_or(vfs::VfsError::Enoent)?;
        let from_pino = self.mount.lookup_path(from_p).map_err(|_| vfs::VfsError::Enoent)?;
        let to_pino = self.mount.lookup_path(to_p).map_err(|_| vfs::VfsError::Enoent)?;
        let target = self.mount.lookup_path(from).map_err(|_| vfs::VfsError::Enoent)?;
        let src = self.mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        let ftype = dirent_dt(&src);
        let (from_name, to_name) = (from_name.to_vec(), to_name.to_vec());
        // Replaced destination (a whiteout rename may overwrite an existing
        // dest): capture the victim's ino + dir-ness before its entry is
        // removed so its in-memory nlink drops after (mirrors `rename_at`).
        let dest_victim = self.mount.lookup_path(to).ok();
        let dest_is_dir = dest_victim
            .and_then(|v| self.mount.read_inode(v).ok())
            .map(|i| i.is_dir())
            .unwrap_or(false);
        // Whiteout = char device, perm 0, rdev 0:0 (Linux WHITEOUT_MODE /
        // WHITEOUT_DEV). `create_mknod` requires the `S_IFMT` type bits.
        const WHITEOUT_MODE: u16 = crate::inode::S_IFCHR;
        self.mount.run_journaled(|m| {
            if dest_victim.is_some() { let _ = m.dir_unlink(to_pino, &to_name); }
            m.dir_link(to_pino, &to_name, target, ftype)?;
            m.dir_unlink(from_pino, &from_name)?;
            m.create_mknod(from_pino, &from_name, WHITEOUT_MODE, 0, 0, 0)?;
            Ok(())
        }).map_err(|_| vfs::VfsError::Eio)?;
        // In-memory nlink authority for an overwritten dest (mirror `rename_at`).
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
