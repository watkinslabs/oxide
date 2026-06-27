// Per-mount ext4 VFS Inode wrappers. Each wrapper carries an
// `Arc<RootfsState>` (its owning mount + that mount's orphan set), so
// a second mount's inodes never read/free through the first mount's
// device or orphan tracking — the Stage-3 de-singletonisation gate.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use block::types::InodeId;
use ::sync as sync;
use super::state::RootfsState;

/// High-32 marker baked into every ext4 VFS `ino()`:
/// `EXT4_INO_MARK | (ext4_ino as u64)`. Lets `close_hook` / `linkat` /
/// `265_linkat.rs` recognise an ext4-resident inode without a mount
/// handle. The marker occupies the HIGH 32 bits so the LOW 32 bits hold
/// a FULL ext4 inode number (real ext4 images have inos far above 2^16).
/// Per-mount disambiguation is via the wrapper's own `RootfsState` (not
/// the marker), so two mounts can share marker bits. The high-32 value
/// `0x6E54_0000` (`"nT"` + zero) does not collide with SOCK/PERF/UFFD/
/// NLSK/IOUR/LND inode tags.
pub const EXT4_INO_MARK: u64 = 0x6E54_0000_0000_0000;
/// Mask selecting the high-32 marker bits in a VFS ino.
pub const EXT4_INO_MASK: u64 = 0xFFFF_FFFF_0000_0000;

/// Encode an ext4 inode number into a VFS ino (marker | full 32-bit ino).
/// # C: O(1)
#[inline]
pub const fn ext4_wrap_ino(ino: u32) -> vfs::Ino { EXT4_INO_MARK | (ino as u64) }

/// True iff `vfs_ino` carries the ext4 high-32 marker.
/// # C: O(1)
#[inline]
pub const fn is_ext4_ino(vfs_ino: u64) -> bool { (vfs_ino & EXT4_INO_MASK) == EXT4_INO_MARK }

/// Recover the full 32-bit ext4 inode number from a marked VFS ino.
/// Caller must have verified `is_ext4_ino` first.
/// # C: O(1)
#[inline]
pub const fn ext4_unwrap_ino(vfs_ino: u64) -> u32 { (vfs_ino & !EXT4_INO_MASK) as u32 }

/// VFS Inode wrapping a regular ext4 file. Bytes are lazy: stat
/// (size/perm) doesn't pull file contents; first read/write loads
/// them. Carries `st` so reads/writes hit the owning mount's device.
pub struct Ext4FileInode {
    pub(super) st:        Arc<RootfsState>,
    pub(super) ino:       u32,
    pub(super) size_hint: core::sync::atomic::AtomicU64,
    pub(super) bytes:     sync::Spinlock<Option<Vec<u8>>, sync::Inode>,
}

impl Ext4FileInode {
    /// Raw ext4 inode number for fs-local operations like linkat
    /// AT_EMPTY_PATH.
    /// # C: O(1)
    pub fn ext4_ino(&self) -> u32 { self.ino }

    fn refresh(&self) {
        if let Some(b) = self.st.read_full_file(self.ino) {
            self.size_hint.store(b.len() as u64, Ordering::Release);
            *self.bytes.lock() = Some(b);
        }
    }
    fn ensure_bytes(&self) -> Option<Vec<u8>> {
        {
            let g = self.bytes.lock();
            if let Some(b) = g.as_ref() { return Some(b.clone()); }
        }
        let b = self.st.read_full_file(self.ino)?;
        self.size_hint.store(b.len() as u64, Ordering::Release);
        let out = b.clone();
        *self.bytes.lock() = Some(b);
        Some(out)
    }
}

impl vfs::Inode for Ext4FileInode {
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn ino(&self) -> vfs::Ino { ext4_wrap_ino(self.ino) }
    fn fsid(&self) -> u64 { self.st.fsid() }
    fn nlink(&self) -> u32 {
        self.st.mount.read_inode(self.ino).map(|i| i.links_count as u32).unwrap_or(1)
    }
    fn blksize(&self) -> u32 { self.st.mount.sb.block_size }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.size_hint.load(Ordering::Acquire) }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> {
        // i_mode low 12 bits = perms. Fall back to 0o755 so executables
        // stay executable — sys_statx defaults to 0o600 (no x bit) when
        // perm() is None, breaking the shell's PATH search on ARM.
        match self.st.mount.read_inode(self.ino) {
            Ok(i) => Some(i.mode & 0o7777),
            Err(_) => Some(0o755),
        }
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let bytes_owned = self.ensure_bytes();
        let g = self.bytes.lock();
        let slice: &[u8] = match g.as_ref() {
            Some(b) => b.as_slice(),
            None    => match bytes_owned.as_deref() { Some(b) => b, None => return Err(vfs::VfsError::Eio) },
        };
        let off = off as usize;
        if off >= slice.len() { return Ok(0); }
        let n = (slice.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&slice[off..off+n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.st.mount.write_at(self.ino, off, buf).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(self.ino as u64));
        self.refresh();
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> vfs::KResult<()> {
        self.st.mount.truncate_inode(self.ino, len).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(self.ino as u64));
        self.refresh();
        Ok(())
    }
}

/// Stat-only VFS Inode for any ext4 inode (regular, dir, symlink, …).
/// Used by stat/statx and as the directory node for the dentry walk.
pub struct Ext4StatInode {
    pub(super) st:   Arc<RootfsState>,
    pub(super) ino:  u32,
    pub(super) ft:   vfs::FileType,
    pub(super) size: u64,
    pub(super) perm: u16,
}

impl vfs::Inode for Ext4StatInode {
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn ino(&self) -> vfs::Ino { ext4_wrap_ino(self.ino) }
    fn fsid(&self) -> u64 { self.st.fsid() }
    fn nlink(&self) -> u32 {
        self.st.mount.read_inode(self.ino).map(|i| i.links_count as u32).unwrap_or_else(|_| {
            if matches!(self.ft, vfs::FileType::Directory) { 2 } else { 1 }
        })
    }
    fn blksize(&self) -> u32 { self.st.mount.sb.block_size }
    fn file_type(&self) -> vfs::FileType { self.ft }
    fn size(&self) -> u64 { self.size }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    /// Per-component child lookup the dentry path-walk (`docs/16§3`) drives.
    /// # C: O(N_entries in dir)
    fn lookup(&self, name: &str) -> vfs::KResult<vfs::InodeRef> {
        if !matches!(self.ft, vfs::FileType::Directory) {
            return Err(vfs::VfsError::Enotdir);
        }
        let child = self.st.lookup_child_ino(self.ino, name).ok_or(vfs::VfsError::Enoent)?;
        self.st.wrap_any_ino(child).ok_or(vfs::VfsError::Enoent)
    }
    fn read(&self, _o: u64, _b: &mut [u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Eio) }
    fn write(&self, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Eio) }
    fn readlink(&self) -> vfs::KResult<alloc::vec::Vec<u8>> {
        if !matches!(self.ft, vfs::FileType::Symlink) {
            return Err(vfs::VfsError::Einval);
        }
        let mount = &self.st.mount;
        let inode = mount.read_inode(self.ino).map_err(|_| vfs::VfsError::Eio)?;
        if let Some(b) = inode.fast_symlink_target() {
            return Ok(b.to_vec());
        }
        let blk = mount.read_file_block(&inode, 0).map_err(|_| vfs::VfsError::Eio)?;
        let n = (self.size as usize).min(blk.len());
        Ok(blk[..n].to_vec())
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, vfs::FileType) -> bool,
    ) -> vfs::KResult<u64> {
        if !matches!(self.ft, vfs::FileType::Directory) {
            return Err(vfs::VfsError::Enotdir);
        }
        let mount = &self.st.mount;
        let dir_inode = mount.read_inode(self.ino).map_err(|_| vfs::VfsError::Eio)?;
        let mut next = off;
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
                    1 => vfs::FileType::Regular,
                    2 => vfs::FileType::Directory,
                    3 => vfs::FileType::CharDev,
                    4 => vfs::FileType::BlockDev,
                    5 => vfs::FileType::Fifo,
                    6 => vfs::FileType::Socket,
                    7 => vfs::FileType::Symlink,
                    _ => vfs::FileType::Regular,
                };
                let keep = f(idx, name, ft);
                if keep { next = idx; } else { keep_going = false; }
                keep
            });
        }
        Ok(next)
    }

    /// # C: O(N parent entries)
    fn mkdir(&self, name: &str, mode: u32) -> vfs::KResult<vfs::InodeRef> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        if self.st.lookup_child_ino(self.ino, name).is_some() { return Err(vfs::VfsError::Eexist); }
        self.st.mount.create_dir(self.ino, name.as_bytes(), mode as u16).map_err(|_| vfs::VfsError::Eio)?;
        let child = self.st.lookup_child_ino(self.ino, name).ok_or(vfs::VfsError::Eio)?;
        self.st.wrap_any_ino(child).ok_or(vfs::VfsError::Eio)
    }

    /// # C: O(N parent entries)
    fn rmdir(&self, name: &str) -> vfs::KResult<()> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        let mount = &self.st.mount;
        let target = self.st.lookup_child_ino(self.ino, name).ok_or(vfs::VfsError::Enoent)?;
        let inode = mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if !inode.is_dir() { return Err(vfs::VfsError::Enotdir); }
        mount.dir_unlink(self.ino, name.as_bytes()).map_err(|_| vfs::VfsError::Eio)?;
        let _ = mount.free_inode(target);
        Ok(())
    }

    /// # C: O(N parent entries)
    fn create_child(&self, name: &str, mode: u32) -> vfs::KResult<vfs::InodeRef> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        if self.st.lookup_child_ino(self.ino, name).is_some() { return Err(vfs::VfsError::Eexist); }
        let ino = self.st.mount.create_file(self.ino, name.as_bytes(), mode as u16).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(ino as u64));
        self.st.wrap_file(ino).ok_or(vfs::VfsError::Eio)
    }

    /// # C: O(N parent entries)
    fn unlink_child(&self, name: &str) -> vfs::KResult<()> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        let mount = &self.st.mount;
        let target = self.st.lookup_child_ino(self.ino, name).ok_or(vfs::VfsError::Enoent)?;
        let inode = mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
        if inode.is_dir() { return Err(vfs::VfsError::Eisdir); }
        mount.unlink(self.ino, name.as_bytes()).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(target as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    fn symlink_child(&self, name: &str, target: &[u8]) -> vfs::KResult<()> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        if self.st.lookup_child_ino(self.ino, name).is_some() { return Err(vfs::VfsError::Eexist); }
        let ino = self.st.mount.create_symlink(self.ino, name.as_bytes(), target).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    fn mknod_child(&self, name: &str, mode: u16, rdev: u32) -> vfs::KResult<()> {
        if !matches!(self.ft, vfs::FileType::Directory) { return Err(vfs::VfsError::Enotdir); }
        if self.st.lookup_child_ino(self.ino, name).is_some() { return Err(vfs::VfsError::Eexist); }
        let ino = self.st.mount.create_mknod(self.ino, name.as_bytes(), mode, rdev).map_err(|_| vfs::VfsError::Eio)?;
        self.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }
}
