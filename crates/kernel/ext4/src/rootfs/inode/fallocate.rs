// `ext4_fallocate` (Linux `fs/ext4/extents.c`) — the mode dispatch and the
// ext4-side `inode_newsize_ok` policy, split out of `regular.rs` so the
// inode-ops manifest stays under the file cap.

use block::types::InodeId;
use core::sync::atomic::Ordering;
use vfs::uapi::{FALLOC_FL_ALLOCATE_RANGE, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_MODE_MASK, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_WRITE_ZEROES,
    FALLOC_FL_ZERO_RANGE};
use vfs::{Inode, KResult, VfsError};

use super::data::Ext4FileData;
use super::regular::vfs_error_from_mount;

/// Every mode `ext4_fallocate` admits. `FALLOC_FL_UNSHARE_RANGE` is absent —
/// ext4 has no shared (reflinked) blocks to unshare, so it reports
/// `EOPNOTSUPP` for a mode the VFS ladder itself accepts.
const EXT4_SUPPORTED_MODES: u32 = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_ZERO_RANGE | FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_WRITE_ZEROES;

/// Page mask used to align the frame-cache invalidation to the containing page.
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

/// `ext4_fallocate` — decode `mode` and run the matching extent operation.
///
/// COLLAPSE_RANGE and INSERT_RANGE are `EOPNOTSUPP`: both re-index every extent
/// past the range (shifting logical block numbers down or up across the whole
/// tree), which this extent implementation cannot do. Linux itself returns
/// `EOPNOTSUPP` from these modes on filesystems that lack the shift, so the
/// errno is the honest one rather than a stand-in.
/// # C: O(len/blocksize)
pub(crate) fn ext4_fallocate(inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
    if mode & !EXT4_SUPPORTED_MODES != 0 { return Err(VfsError::Eopnotsupp); }
    let d = inode.private::<Ext4FileData>().ok_or(VfsError::Eio)?;
    let _mutation = d.begin_swap_mutation()?;
    let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
    match mode & FALLOC_FL_MODE_MASK {
        // Preallocation: map the range as UNWRITTEN extents (no data I/O).
        FALLOC_FL_ALLOCATE_RANGE => {
            grow_check(inode, d, keep_size, off, len)?;
            d.st.mount.fallocate_inode(d.ino, off, len, keep_size).map_err(vfs_error_from_mount)?;
        }
        // Deallocate the range → holes, which read as zeros. Size unchanged
        // (the VFS ladder already required KEEP_SIZE for this mode).
        FALLOC_FL_PUNCH_HOLE => {
            d.st.mount.punch_hole_inode(d.ino, off, len).map_err(vfs_error_from_mount)?;
        }
        // ZERO_RANGE and WRITE_ZEROES share `ext4_zero_range` in Linux and share
        // it here: this backend zeroes eagerly, producing INITIALIZED extents,
        // which satisfies both contracts (read-as-zeros, and no further mapping
        // metadata change on a later overwrite).
        FALLOC_FL_ZERO_RANGE | FALLOC_FL_WRITE_ZEROES => {
            grow_check(inode, d, keep_size, off, len)?;
            zero_range(d, keep_size, off, len)?;
        }
        _ => return Err(VfsError::Eopnotsupp),
    }
    d.st.page_cache.invalidate(InodeId(d.ino as u64));
    if let Some(end) = off.checked_add(len) { d.frames.invalidate_range(off & PAGE_MASK, end); }
    d.refresh_size();
    inode.set_size(d.size_hint.load(Ordering::Acquire));
    d.refresh_inode_usage(inode);
    #[cfg(feature = "ext4-frame-cache")]
    d.frames.set_size(d.size_hint.load(Ordering::Acquire));
    Ok(())
}

/// `inode_newsize_ok` exactly where `ext4_do_fallocate`/`ext4_zero_range` place
/// it: only when the request will actually move the file's end. A KEEP_SIZE
/// request never grows the file, so `RLIMIT_FSIZE` does not bind — the opposite
/// of shmem, which commits pages either way and checks unconditionally.
/// # C: O(1)
fn grow_check(inode: &Inode, d: &Ext4FileData, keep_size: bool, off: u64, len: u64) -> KResult<()> {
    if keep_size { return Ok(()); }
    let end = off.checked_add(len).ok_or(VfsError::Einval)?;
    if end <= d.size_hint.load(Ordering::Acquire) { return Ok(()); }
    vfs::inode_newsize_ok(inode, end)
}

/// Write zeros across `[off, off+len)` one filesystem block at a time,
/// restoring the old size afterwards when the caller asked to keep it.
/// # C: O(len/blocksize)
fn zero_range(d: &Ext4FileData, keep_size: bool, off: u64, len: u64) -> KResult<()> {
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
    if keep_size && end > old { d.st.mount.set_inode_size(d.ino, old).map_err(vfs_error_from_mount)?; }
    Ok(())
}
