// Per-mount ext4 VFS inodes — concrete `vfs::Inode` (kp2 struct-Inode
// model). Each inode's backend state lives in `i_private` as an
// `Arc<Ext4FileData>` (regular files) or `Arc<Ext4StatData>` (every
// other type), carrying that inode's owning mount + ext4 ino, so a
// second mount's inodes never read/free through the first mount's device
// or orphan tracking — the Stage-3 de-singletonisation gate.
//
// The old two `impl vfs::Inode` collapse into:
//   * data → `i_private` (`Ext4FileData` / `Ext4StatData`),
//   * regular-file behaviour → `Ext4RegInodeOps` (`i_op`) +
//     `Ext4RegFileOps` (`i_fop`) + `Ext4FileMapping` (`i_mapping`),
//   * stat/dir/symlink/dev behaviour → `Ext4StatInodeOps` (`i_op`) +
//     `Ext4StatFileOps` (`i_fop`),
// all shared (ZST ops) across every inode of the backend; the per-inode
// `Arc<…Data>` disambiguates the mount + ino.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::types::InodeId;
use vfs::inode_ops::{mk_mode, InodeOps};
use vfs::file_ops::FileOps;
use vfs::inode::InodeBuilder;
use vfs::mapping::AddressSpaceOps;
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};
use super::state::RootfsState;

fn vfs_error_from_mount(e: crate::MountError) -> vfs::VfsError {
    match e {
        crate::MountError::NoSpace => vfs::VfsError::Enospc,
        crate::MountError::Inode(crate::InodeError::BadLen) => vfs::VfsError::Einval,
        crate::MountError::NotFound => vfs::VfsError::Eopnotsupp,
        crate::MountError::DepthUnsupported | crate::MountError::ExtentTreeFull => vfs::VfsError::Eopnotsupp,
        _ => vfs::VfsError::Eio,
    }
}

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

// ── i_private backend state ──────────────────────────────────────────

/// `i_private` for a regular ext4 file. Stat (size/perm) doesn't pull file
/// contents; read(2)/mmap serve incrementally through the owning mount's
/// shared `page_cache` (D8 — no whole-file `Vec` snapshot). `st` carries the
/// owning mount so reads/writes hit its device + page cache.
pub(crate) struct Ext4FileData {
    pub(crate) st:        Arc<RootfsState>,
    pub(crate) ino:       u32,
    pub(crate) size_hint: AtomicU64,
}

impl Ext4FileData {
    /// Re-read just the on-disk size into the hint after a mutating op
    /// (write/truncate/fallocate) — O(1), no file body load. # C: O(1)
    fn refresh_size(&self) {
        if let Ok(i) = self.st.mount.read_inode(self.ino) {
            self.size_hint.store(i.size, Ordering::Release);
        }
    }
}

/// `i_private` for any non-regular ext4 inode (directory, symlink, char/
/// block dev, FIFO, socket). Stat-only + namespace ops drive off `st`.
pub(crate) struct Ext4StatData {
    pub(crate) st:   Arc<RootfsState>,
    pub(crate) ino:  u32,
    pub(crate) ft:   FileType,
    pub(crate) size: u64,
}

/// Recover `(owning mount state, ext4 ino)` from a concrete inode's
/// `i_private`, regardless of which backend data type it carries. Used by
/// `close_hook_free_orphan` to free against the OWNING mount. # C: O(1)
pub(crate) fn ext4_state_of(inode: &Inode) -> Option<(Arc<RootfsState>, u32)> {
    if let Some(f) = inode.private::<Ext4FileData>() { return Some((f.st.clone(), f.ino)); }
    if let Some(s) = inode.private::<Ext4StatData>() { return Some((s.st.clone(), s.ino)); }
    None
}

/// Recover the raw ext4 inode number of a REGULAR-file inode (linkat
/// AT_EMPTY_PATH); `None` for any non-file inode. # C: O(1)
pub(crate) fn ext4_file_ino(inode: &Inode) -> Option<u32> {
    inode.private::<Ext4FileData>().map(|f| f.ino)
}

// ── regular-file ops (i_op / i_fop / i_mapping) ──────────────────────

/// `inode_operations` for a regular ext4 file: metadata + truncate /
/// fallocate. Namespace ops (lookup/…) stay the trait default. Shared
/// (ZST) across every file inode. # C: O(1)
pub(crate) struct Ext4RegInodeOps;

impl InodeOps for Ext4RegInodeOps {
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        d.st.mount.truncate_inode(d.ino, len).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        Ok(())
    }

    fn fallocate(&self, inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool)
        -> KResult<()>
    {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        if zero_range {
            let old = d.size_hint.load(Ordering::Acquire);
            let end = off.checked_add(len).ok_or(VfsError::Einval)?;
            let bs = d.st.mount.sb.block_size.max(1) as usize;
            let zeros = alloc::vec![0u8; bs];
            let mut pos = off;
            while pos < end {
                let n = core::cmp::min((end - pos) as usize, zeros.len());
                d.st.mount.write_at(d.ino, pos, &zeros[..n]).map_err(vfs_error_from_mount)?;
                pos += n as u64;
            }
            if keep_size && end > old {
                d.st.mount.set_inode_size(d.ino, old).map_err(vfs_error_from_mount)?;
            }
        } else {
            d.st.mount.fallocate_inode(d.ino, off, len, keep_size).map_err(vfs_error_from_mount)?;
        }
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        Ok(())
    }

    /// `i_op->getattr` (Linux `ext4_getattr`): the generic fill, then
    /// `st_blocks` overwritten with the REAL on-disk `i_blocks` (512-byte
    /// sectors) so a preallocated/`fallocate`d or sparse file reports its true
    /// allocation, not a size-derived estimate. # C: O(1) inode read
    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, overlay: Option<vfs::inode_times::InodeTimes>)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap, overlay);
        if let Some(d) = inode.private::<Ext4FileData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
        }
        k
    }
}

/// `file_operations` for a regular ext4 file: read/write through the
/// owning mount's device + page cache. Shared (ZST). # C: O(1)
pub(crate) struct Ext4RegFileOps;

impl FileOps for Ext4RegFileOps {
    /// read(2): serve incrementally from the owning mount's shared page cache
    /// (Linux `generic_file_read_iter` → `address_space`), never loading the
    /// whole file. Short read past EOF; holes read as zero. # C: O(buf.len)
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        d.st.read_cached(d.ino, off, buf).map_err(|_| VfsError::Eio)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        d.st.mount.write_at(d.ino, off, buf).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(d.ino as u64));
        d.refresh_size();
        inode.set_size(d.size_hint.load(Ordering::Acquire));
        Ok(buf.len())
    }
}

/// ext4 file `address_space` (`i_mapping`): reads route through the owning
/// mount's shared `page_cache` (keyed by inode id), so all mappers/readers
/// of one inode hit the SAME cached pages. # C: O(1)
pub(crate) struct Ext4FileMapping { pub(crate) data: Arc<Ext4FileData> }

impl AddressSpaceOps for Ext4FileMapping {
    /// MAP_SHARED writable frame: deferred (no PMM-frame store + extent
    /// writeback yet) → `None`, so the fault path copies into a private frame
    /// (correct for MAP_PRIVATE; unchanged from the pre-i_mapping default).
    /// # C: O(1)
    fn shared_frame(&self, _off: u64) -> Option<u64> { None }
    /// Read-fault / MAP_PRIVATE fill: copy from the per-mount page cache,
    /// shared by every mapper of this inode. # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        self.data.st.read_cached(self.data.ino, off, dst)
    }
    /// # C: O(1)
    fn size(&self) -> u64 { self.data.size_hint.load(Ordering::Acquire) }
}

/// Build a regular-file `vfs::Inode` for ext4 inode `ino`. `mode`/`size`/
/// `nlink` are the captured on-disk metadata (read by the caller before the
/// `iget` build closure). # C: O(1)
pub(crate) fn build_file_inode(st: Arc<RootfsState>, ino: u32, mode: u16, size: u64, nlink: u32)
    -> InodeRef
{
    let data = Arc::new(Ext4FileData {
        st, ino,
        size_hint: AtomicU64::new(size),
    });
    let mapping: Arc<dyn AddressSpaceOps> = Arc::new(Ext4FileMapping { data: data.clone() });
    let weak_sb = data.st.sb.lock().clone();
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(FileType::Regular, mode & 0o7777),
                      Arc::new(Ext4RegInodeOps), Arc::new(Ext4RegFileOps))
        .sb(weak_sb)
        .size(size)
        .nlink(nlink)
        .mapping(mapping)
        .private(data)
        .build()
}

// ── stat / dir / symlink / dev ops (i_op / i_fop) ────────────────────

/// `inode_operations` for any non-regular ext4 inode. Namespace ops gate on
/// the stored `FileType` (a non-directory rejects `lookup`/`mkdir`/… with
/// `Enotdir`, a non-symlink rejects `readlink` with `Einval`), matching the
/// old per-impl guards. Shared (ZST). # C: O(1)
pub(crate) struct Ext4StatInodeOps;

impl Ext4StatInodeOps {
    fn data(inode: &Inode) -> KResult<&Ext4StatData> {
        inode.private::<Ext4StatData>().ok_or(VfsError::Eio)
    }
}

impl InodeOps for Ext4StatInodeOps {
    /// Per-component child lookup the dentry path-walk (`docs/16§3`) drives.
    /// # C: O(N_entries in dir)
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let child = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        d.st.wrap_any_ino(child).ok_or(VfsError::Enoent)
    }

    /// `i_op->getattr` (Linux `ext4_getattr`): generic fill with `st_blocks`
    /// replaced by the real on-disk `i_blocks` (512-byte sectors). # C: O(1)
    fn getattr(&self, inode: &Inode, idmap: &vfs::idmap::Idmap, overlay: Option<vfs::inode_times::InodeTimes>)
        -> vfs::getattr::Kstat
    {
        let mut k = vfs::getattr::generic_fillattr(inode, idmap, overlay);
        if let Some(d) = inode.private::<Ext4StatData>() {
            if let Ok(i) = d.st.mount.read_inode(d.ino) { k.blocks = i.i_blocks; }
        }
        k
    }

    /// # C: O(target_len)
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

    /// # C: O(N parent entries)
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        d.st.mount.create_dir(d.ino, name.as_bytes(), mode as u16).map_err(|_| VfsError::Eio)?;
        let child = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Eio)?;
        d.st.wrap_any_ino(child).ok_or(VfsError::Eio)
    }

    /// # C: O(N parent entries)
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if !i.is_dir() { return Err(VfsError::Enotdir); }
        // Emptiness check (Linux `ext4_rmdir` → `ext4_empty_dir`): reject with
        // ENOTEMPTY if the victim holds any entry other than "." / "..".
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
        Ok(())
    }

    /// # C: O(N parent entries)
    fn create(&self, inode: &Inode, name: &str, mode: u32) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ino = d.st.mount.create_file(d.ino, name.as_bytes(), mode as u16).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        d.st.wrap_file(ino).ok_or(VfsError::Eio)
    }

    /// # C: O(N parent entries)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(d.ino, name).ok_or(VfsError::Enoent)?;
        let i = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        if i.is_dir() { return Err(VfsError::Eisdir); }
        mount.unlink(d.ino, name.as_bytes()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(target as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8]) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ino = d.st.mount.create_symlink(d.ino, name.as_bytes(), target).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    /// # C: O(N parent entries)
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ino = d.st.mount.create_mknod(d.ino, name.as_bytes(), mode, rdev).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }
}

/// `file_operations` for a non-regular ext4 inode: `iterate`/readdir for a
/// directory, the `S_IFMT` default (`EISDIR`/`EINVAL`) otherwise. Shared
/// (ZST). # C: O(1)
pub(crate) struct Ext4StatFileOps;

impl FileOps for Ext4StatFileOps {
    fn iterate(
        &self,
        inode: &Inode,
        off: u64,
        f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let d = inode.private::<Ext4StatData>().ok_or(VfsError::Eio)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        let mount = &d.st.mount;
        let dir_inode = mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?;
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
                    1 => FileType::Regular,
                    2 => FileType::Directory,
                    3 => FileType::CharDev,
                    4 => FileType::BlockDev,
                    5 => FileType::Fifo,
                    6 => FileType::Socket,
                    7 => FileType::Symlink,
                    _ => FileType::Regular,
                };
                let keep = f(e.inode as u64, idx, name, ft);
                if keep { next = idx; } else { keep_going = false; }
                keep
            });
        }
        Ok(next)
    }
}

/// Build a stat/dir/symlink/dev `vfs::Inode` for ext4 inode `ino`. The
/// captured on-disk metadata (`ft`/`perm`/`size`/`nlink`/`rdev`) is read by
/// the caller before the `iget` build closure. `rdev` is only meaningful for
/// CHR/BLK nodes (generic_fillattr reads it for those types only). # C: O(1)
pub(crate) fn build_stat_inode(
    st: Arc<RootfsState>, ino: u32, ft: FileType, perm: u16, size: u64, nlink: u32, rdev: u32,
) -> InodeRef {
    let data = Arc::new(Ext4StatData { st, ino, ft, size });
    let weak_sb = data.st.sb.lock().clone();
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(ft, perm),
                      Arc::new(Ext4StatInodeOps), Arc::new(Ext4StatFileOps))
        .sb(weak_sb)
        .size(size)
        .nlink(nlink)
        .rdev(rdev)
        .private(data)
        .build()
}
