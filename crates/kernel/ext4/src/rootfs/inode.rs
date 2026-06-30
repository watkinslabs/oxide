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
use vfs::file_ops::{FileOps, HoleOrData};
use vfs::inode::InodeBuilder;
use vfs::mapping::AddressSpaceOps;
use vfs::{DirContext, FileType, Inode, InodeRef, KResult, VfsError};
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

/// Write-back-on-modify: re-encode the inode's full in-core xattr set into its
/// on-disk IBODY area (journaled). Called after a successful in-core
/// set/remove so disk stays the authority across eviction/remount. Best-effort:
/// a set that overflows the ibody area (external-block residual) stays in-core
/// only. # C: O(N_xattr) + 1 journaled inode write
fn persist_inode_xattrs(inode: &Inode) {
    if let Some((st, ino)) = ext4_state_of(inode) {
        if let Some(store) = inode.simple_xattrs() {
            let entries: Vec<(alloc::string::String, Vec<u8>)> = store
                .list_names()
                .into_iter()
                .filter_map(|n| store.get(&n).map(|v| (n, v)))
                .collect();
            let _ = st.mount.store_ibody_xattrs(ino, &entries);
        }
    }
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

    /// `i_op->setxattr` — update the in-core store (atomic flag check), then
    /// persist the full set to the on-disk IBODY area. # C: O(N_xattr) + 1 I/O
    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.set(name, value, create, replace)?;
        persist_inode_xattrs(inode);
        Ok(())
    }

    /// `i_op->removexattr` — drop from the in-core store, then re-encode the
    /// IBODY area to disk. # C: O(N_xattr) + 1 I/O
    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.remove(name)?;
        persist_inode_xattrs(inode);
        Ok(())
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

    /// `f_op->llseek` SEEK_HOLE/SEEK_DATA (Linux `ext4_seek_hole`/
    /// `ext4_seek_data`): EXTENT-AWARE override of the generic non-sparse
    /// default. Walks the inode's extent map (`collect_leaf_extents`) so a
    /// sparse or hole-punched ext4 file reports its real data/hole boundaries
    /// — `SEEK_DATA` skips forward over holes to the next allocated extent,
    /// `SEEK_HOLE` skips forward over data to the next gap (or the implicit
    /// hole at EOF). Boundaries are block-granular (ext4 allocates whole
    /// blocks); `offset` already inside a data byte / hole returns `offset`
    /// unchanged. `offset >= i_size` is `ENXIO`. # C: O(N_extents)
    fn seek_hole_data(&self, inode: &Inode, offset: u64, which: HoleOrData) -> KResult<u64> {
        let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
        let i = d.st.mount.read_inode(d.ino).map_err(|_| VfsError::Eio)?;
        let size = i.size;
        if offset >= size { return Err(VfsError::Enxio); }
        let bs = d.st.mount.sb.block_size.max(1) as u64;
        let runs = d.st.mount.collect_leaf_extents(&i.i_block).map_err(|_| VfsError::Eio)?;
        seek_in_runs(&runs, bs, size, offset, which)
    }
}

/// Pure SEEK_HOLE/SEEK_DATA boundary resolver over a file's data runs.
/// `runs` are `(first_logical_block, len_blocks)` ASCENDING by start block,
/// non-overlapping; gaps between runs (and the region after the last run, up
/// to `size`) are holes. `bs` = block size, `size` = i_size (bytes), `offset`
/// = scan-start byte (caller guarantees `offset < size`). Mirrors Linux
/// `ext4_seek_data`/`ext4_seek_hole` semantics. # C: O(N_runs)
fn seek_in_runs(runs: &[(u32, u32)], bs: u64, size: u64, offset: u64, which: HoleOrData)
    -> KResult<u64>
{
    let b = offset / bs; // logical block holding `offset`
    let contains = |blk: u64| runs.iter().any(|&(s, l)| blk >= s as u64 && blk < s as u64 + l as u64);
    match which {
        HoleOrData::Data => {
            if contains(b) { return Ok(offset); }
            // First run that starts strictly after `b` (sorted ascending) is the
            // next data region. Runs entirely before `b` have start <= b and are
            // skipped by the `> b` test.
            for &(s, _l) in runs {
                if (s as u64) > b {
                    let byte = (s as u64) * bs;
                    return if byte < size { Ok(byte) } else { Err(VfsError::Enxio) };
                }
            }
            Err(VfsError::Enxio)
        }
        HoleOrData::Hole => {
            if !contains(b) { return Ok(offset); } // already in a hole
            // Walk the contiguous data chain covering `b`; the hole begins at the
            // end of the last contiguous run.
            let mut chain_end: Option<u64> = None;
            for &(s, l) in runs {
                let start = s as u64;
                let end = start + l as u64;
                match chain_end {
                    None => { if b >= start && b < end { chain_end = Some(end); } }
                    Some(ce) => {
                        if start == ce { chain_end = Some(end); }
                        else if start > ce { break; }
                    }
                }
            }
            let hole_byte = chain_end.map(|e| e * bs).unwrap_or(offset);
            Ok(hole_byte.min(size))
        }
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
pub(crate) fn build_file_inode(st: Arc<RootfsState>, ino: u32, mode: u16, size: u64, nlink: u32, uid: u32, gid: u32)
    -> InodeRef
{
    let data = Arc::new(Ext4FileData {
        st, ino,
        size_hint: AtomicU64::new(size),
    });
    let mapping: Arc<dyn AddressSpaceOps> = Arc::new(Ext4FileMapping { data: data.clone() });
    let weak_sb = data.st.sb.lock().clone();
    // Load-on-iget: disk is the xattr authority, the SimpleXattrs store the
    // in-core cache. Populate from the on-disk ibody + external block so xattrs
    // survive eviction + remount.
    let xattrs = vfs::SimpleXattrs::new();
    data.st.mount.load_xattrs(ino, &xattrs);
    InodeBuilder::new(ext4_wrap_ino(ino), mk_mode(FileType::Regular, mode & 0o7777),
                      Arc::new(Ext4RegInodeOps), Arc::new(Ext4RegFileOps))
        .sb(weak_sb)
        .size(size)
        .nlink(nlink)
        .owner(uid, gid)
        .mapping(mapping)
        .xattrs(xattrs)
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

    /// `i_op->setxattr` — in-core update then on-disk IBODY persist (see the
    /// regular-file impl). # C: O(N_xattr) + 1 I/O
    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), vfs::XattrError>
    {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.set(name, value, create, replace)?;
        persist_inode_xattrs(inode);
        Ok(())
    }

    /// `i_op->removexattr` — in-core drop then on-disk IBODY persist. # C:
    /// O(N_xattr) + 1 I/O
    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), vfs::XattrError> {
        let store = inode.simple_xattrs().ok_or(vfs::XattrError::NotSup)?;
        store.remove(name)?;
        persist_inode_xattrs(inode);
        Ok(())
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

    /// New on-disk inode owner = `ctx.fsuid()`/`ctx.fsgid()` (idmap-mapped),
    /// mode = `ctx.apply_umask(mode)` — Linux `ext4_mkdir` → `ext4_new_inode`.
    /// # C: O(N parent entries)
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let perm = ctx.apply_umask(mode) as u16;
        d.st.mount.create_dir(d.ino, name.as_bytes(), perm, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
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
        // In-memory nlink authority (Linux `ext4_rmdir` → `clear_nlink(victim)`
        // + `ext4_dec_count(dir)`): the FS owns the in-memory drop, not the
        // dcache. Clear the cached victim dir's links (its "." + the parent's
        // entry) so `d_unlink` sees nlink==0 and retires it; drop THIS parent
        // dir's link (the victim's gone ".."), mirroring tmpfs `simple_rmdir`.
        if let Some(sb) = d.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(target)) { victim.set_nlink(0); }
        }
        inode.drop_nlink();
        Ok(())
    }

    /// New on-disk inode owner = `ctx.fsuid()`/`ctx.fsgid()`, mode =
    /// `ctx.apply_umask(mode)` — Linux `ext4_create` → `ext4_new_inode`.
    /// # C: O(N parent entries)
    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &vfs::CreateCtx) -> KResult<InodeRef> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let perm = ctx.apply_umask(mode) as u16;
        let ino = d.st.mount.create_file(d.ino, name.as_bytes(), perm, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
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
        // In-memory nlink authority (Linux `ext4_unlink` → `ext4_dec_count`):
        // the FS owns `drop_nlink` on the victim inode; the dcache `d_unlink`
        // no longer touches nlink. Drop the CACHED victim's link (same `Arc` the
        // victim dentry holds) so `iput`/`drop_inode` can retire it once the
        // last reference drains. Uncached → nothing in memory to drop.
        if let Some(sb) = d.st.i_sb() {
            if let Some(victim) = sb.ilookup(ext4_wrap_ino(target)) { victim.drop_link(); }
        }
        Ok(())
    }

    /// Symlink inode owner = `ctx.fsuid()`/`ctx.fsgid()`; its mode is fixed
    /// `0777` (Linux symlinks ignore umask). # C: O(N parent entries)
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let ino = d.st.mount.create_symlink(d.ino, name.as_bytes(), target, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    /// New node owner = `ctx.fsuid()`/`ctx.fsgid()`; the perm bits carried in
    /// `mode` are umasked (`ctx.apply_umask`), the `S_IFMT` type bits kept —
    /// Linux `ext4_mknod` → `ext4_new_inode`. # C: O(N parent entries)
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &vfs::CreateCtx) -> KResult<()> {
        let d = Self::data(inode)?;
        if !matches!(d.ft, FileType::Directory) { return Err(VfsError::Enotdir); }
        if d.st.lookup_child_ino(d.ino, name).is_some() { return Err(VfsError::Eexist); }
        let mode = (mode & crate::inode::S_IFMT) | (ctx.apply_umask((mode & 0o7777) as u32) as u16);
        let ino = d.st.mount.create_mknod(d.ino, name.as_bytes(), mode, rdev, ctx.fsuid(), ctx.fsgid()).map_err(|_| VfsError::Eio)?;
        d.st.page_cache.invalidate(InodeId(ino as u64));
        Ok(())
    }

    /// `i_op->rename` (Linux `ext4_rename` reached via `vfs_rename`): the
    /// resolved-parent variant of the legacy whole-path `rename_at` — a single
    /// journaled transaction that unlinks any overwritten dest, links the source
    /// inode under the new (dir,name), then unlinks the old name. Only the plain
    /// rename routes here; `RENAME_EXCHANGE`/`RENAME_WHITEOUT` stay on the
    /// `FileSystem` path (`082_rename` branches) and are rejected here
    /// defensively. # C: O(N parent entries) + 1 journaled tx
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
        // rename is within a single mount (Linux EXDEV otherwise). The syscall
        // already guarantees this; re-check on the resolved parents' state.
        if !Arc::ptr_eq(&d.st, &nd.st) { return Err(VfsError::Exdev); }
        let (from_p, to_p) = (d.ino, nd.ino);
        let mount = &d.st.mount;
        let target = d.st.lookup_child_ino(from_p, old_name).ok_or(VfsError::Enoent)?;
        let src = mount.read_inode(target).map_err(|_| VfsError::Eio)?;
        let ftype = if src.is_dir() { crate::DT_DIR } else if src.is_link() { crate::DT_LNK } else { crate::DT_REG };
        let (from_name, to_name) = (old_name.as_bytes(), new_name.as_bytes());
        // Replaced destination (plain rename only; EXCHANGE/WHITEOUT excluded
        // above): capture its ino + dir-ness before the entry is removed so its
        // in-memory nlink drops after (Linux `vfs_rename`: replaced inode loses
        // its link). Mirrors the legacy `rename_at`.
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
    // Load-on-iget (see `build_file_inode`): disk-authority xattr cache.
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

#[cfg(test)]
mod seek_tests {
    use super::{seek_in_runs, HoleOrData};
    use vfs::VfsError;

    const BS: u64 = 4096;

    // Fully-allocated file: one run [0,10) blocks, size 40000 (< 10 blocks).
    #[test]
    fn full_file_data_and_hole() {
        let runs = [(0u32, 10u32)];
        let size = 40000u64;
        // SEEK_DATA at 0 → 0 (already data)
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(0));
        // SEEK_DATA mid-file → unchanged
        assert_eq!(seek_in_runs(&runs, BS, size, 5000, HoleOrData::Data), Ok(5000));
        // SEEK_HOLE in data → implicit hole at EOF (size)
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(size));
        // past EOF handled by caller; resolver assumes offset<size.
    }

    // Sparse: data [0,1), hole [1,5), data [5,8). size = 8 blocks.
    #[test]
    fn sparse_middle_hole() {
        let runs = [(0u32, 1u32), (5u32, 3u32)];
        let size = 8 * BS;
        // In first data block: SEEK_HOLE → start of hole (block 1).
        assert_eq!(seek_in_runs(&runs, BS, size, 100, HoleOrData::Hole), Ok(BS));
        // In the hole: SEEK_DATA → next data extent (block 5).
        assert_eq!(seek_in_runs(&runs, BS, size, 2 * BS, HoleOrData::Data), Ok(5 * BS));
        // In the hole: SEEK_HOLE → unchanged (already a hole).
        let off = 2 * BS + 17;
        assert_eq!(seek_in_runs(&runs, BS, size, off, HoleOrData::Hole), Ok(off));
        // In second data region: SEEK_HOLE → EOF (data runs to size).
        assert_eq!(seek_in_runs(&runs, BS, size, 6 * BS, HoleOrData::Hole), Ok(size));
    }

    // Leading hole: file starts with a hole, data later.
    #[test]
    fn leading_hole() {
        let runs = [(3u32, 2u32)];
        let size = 6 * BS;
        // SEEK_DATA from 0 → first extent at block 3.
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(3 * BS));
        // SEEK_HOLE from 0 → unchanged (offset is in the leading hole).
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Data), Ok(3 * BS));
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
    }

    // Adjacent runs merge: [0,2)+[2,3) are contiguous data → single region.
    #[test]
    fn adjacent_runs_merge() {
        let runs = [(0u32, 2u32), (2u32, 1u32), (10u32, 1u32)];
        let size = 11 * BS;
        // SEEK_HOLE in the merged [0,3) region → hole at block 3.
        assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Hole), Ok(3 * BS));
        // SEEK_DATA in the [3,10) hole → block 10.
        assert_eq!(seek_in_runs(&runs, BS, size, 5 * BS, HoleOrData::Data), Ok(10 * BS));
    }

    // No data at/after offset → SEEK_DATA is ENXIO.
    #[test]
    fn no_more_data_enxio() {
        let runs = [(0u32, 1u32)];
        let size = 8 * BS;
        // Offset in the trailing hole, no further extents → ENXIO.
        assert_eq!(seek_in_runs(&runs, BS, size, 4 * BS, HoleOrData::Data), Err(VfsError::Enxio));
    }

    // Empty file body (no extents): every byte before EOF is a hole.
    #[test]
    fn no_extents_all_hole() {
        let runs: [(u32, u32); 0] = [];
        let size = 3 * BS;
        assert_eq!(seek_in_runs(&runs, BS, size, 0, HoleOrData::Hole), Ok(0));
        assert_eq!(seek_in_runs(&runs, BS, size, BS, HoleOrData::Data), Err(VfsError::Enxio));
    }
}
