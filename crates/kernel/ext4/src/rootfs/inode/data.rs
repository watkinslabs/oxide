use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vfs::{FileType, Inode};
use vfs::xattr::XattrError;

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
    /// Active ext4 swapfile ownership. Mutators reject while this remains
    /// set, preserving the extent map used by direct swap I/O.
    pub(crate) swap_active: Arc<AtomicBool>,
    /// Mutations that passed their active-swap check and may still change
    /// cached data or the extent tree. Activation first publishes
    /// `swap_active`, then drains this count, so it cannot race a writer that
    /// observed the file before activation.
    pub(crate) swap_mutations: Arc<AtomicU64>,
}

/// A mutation admitted before swap activation. Dropping it makes a pending
/// activation observe that the operation has completed.
pub(crate) struct SwapMutation<'a> { file: &'a Ext4FileData }

impl Drop for SwapMutation<'_> {
    fn drop(&mut self) { self.file.swap_mutations.fetch_sub(1, Ordering::Release); }
}

impl Ext4FileData {
    /// Admit one data/extent mutation unless the inode is an active swapfile.
    /// The increment-before-test order closes the activation race: an activator
    /// that publishes `swap_active` waits for every earlier admission, while a
    /// later admission sees the active flag and fails with `EBUSY`.
    pub(crate) fn begin_swap_mutation(&self) -> Result<SwapMutation<'_>, vfs::VfsError> {
        self.swap_mutations.fetch_add(1, Ordering::AcqRel);
        if self.swap_active.load(Ordering::Acquire) {
            self.swap_mutations.fetch_sub(1, Ordering::Release);
            return Err(vfs::VfsError::Ebusy);
        }
        Ok(SwapMutation { file: self })
    }

    /// Publish swap ownership then wait until every mutation admitted before
    /// publication has finished. The caller must clear `swap_active` if its
    /// subsequent validation or persistence step fails.
    pub(crate) fn begin_swap_activation(&self) -> Result<(), vfs::VfsError> {
        self.swap_active.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| vfs::VfsError::Ebusy)?;
        while self.swap_mutations.load(Ordering::Acquire) != 0 {
            crate::mount::cooperative_yield();
        }
        Ok(())
    }
    /// Re-read just the on-disk size into the hint after a mutating op
    /// (write/truncate/fallocate) — O(1), no file body load. # C: O(1)
    pub(crate) fn refresh_size(&self) {
        if let Ok(i) = self.st.mount.read_inode(self.ino) {
            self.size_hint.store(i.size, Ordering::Release);
        }
    }
    /// Re-read on-disk size and i_blocks into the VFS inode. # C: O(1)
    pub(crate) fn refresh_inode_usage(&self, inode: &Inode) {
        if let Ok(i) = self.st.mount.read_inode(self.ino) {
            self.size_hint.store(i.size, Ordering::Release);
            inode.set_size(i.size);
            inode.set_blocks(i.i_blocks as u64);
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

fn xattr_error_from_mount(e: crate::MountError) -> XattrError {
    XattrError::Fs(super::regular::vfs_error_from_mount(e))
}

fn persist_xattr_entries(inode: &Inode, entries: &[(alloc::string::String, Vec<u8>)])
    -> Result<(), XattrError>
{
    if let Some((st, ino)) = ext4_state_of(inode) {
        st.mount.store_xattrs(ino, entries).map_err(xattr_error_from_mount)?;
    }
    Ok(())
}

/// `ext4_xattr_set`: validate flags against the inode cache, commit the full
/// new xattr set to disk, then publish it in-core. # C: O(N_xattr)+journal I/O
pub(crate) fn set_inode_xattr(inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
    -> Result<(), XattrError>
{
    let store = inode.simple_xattrs().ok_or(XattrError::NotSup)?;
    let mut entries = store.entries();
    let pos = entries.iter().position(|(n, _)| n == name);
    if create && pos.is_some() { return Err(XattrError::Exists); }
    if replace && pos.is_none() { return Err(XattrError::NotFound); }
    match pos {
        Some(idx) => entries[idx].1 = value,
        None => entries.push((alloc::string::String::from(name), value)),
    }
    persist_xattr_entries(inode, &entries)?;
    store.replace_all(&entries);
    Ok(())
}

/// `ext4_xattr_set` remove path: commit removal before updating the cache.
/// # C: O(N_xattr)+journal I/O
pub(crate) fn remove_inode_xattr(inode: &Inode, name: &str) -> Result<(), XattrError> {
    let store = inode.simple_xattrs().ok_or(XattrError::NotSup)?;
    let mut entries = store.entries();
    let Some(pos) = entries.iter().position(|(n, _)| n == name) else {
        return Err(XattrError::NotFound);
    };
    entries.remove(pos);
    persist_xattr_entries(inode, &entries)?;
    store.replace_all(&entries);
    Ok(())
}
