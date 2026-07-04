use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Inode};

use super::super::state::RootfsState;

/// `i_private` for a regular ext4 file. Stat (size/perm) doesn't pull file
/// contents; read(2)/mmap serve incrementally through the owning mount's
/// shared `page_cache` (D8 — no whole-file `Vec` snapshot). `st` carries the
/// owning mount so reads/writes hit its device + page cache.
pub(crate) struct Ext4FileData {
    pub(crate) st:        Arc<RootfsState>,
    pub(crate) ino:       u32,
    pub(crate) size_hint: AtomicU64,
    /// D8: per-inode PMM frame store. `read`/`write`/`shared_frame` all serve
    /// from THESE frames (read==write==mmap coherency); writeback flushes
    /// dirty (mmap-written) frames to disk. Shared (same `Arc`) with this
    /// inode's `Ext4FileMapping`.
    pub(crate) frames:    Arc<super::super::framecache::Ext4FrameStore>,
}

impl Ext4FileData {
    /// Re-read just the on-disk size into the hint after a mutating op
    /// (write/truncate/fallocate) — O(1), no file body load. # C: O(1)
    pub(crate) fn refresh_size(&self) {
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
pub(crate) fn persist_inode_xattrs(inode: &Inode) {
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
