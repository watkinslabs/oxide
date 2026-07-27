// `shmem_fallocate` (Linux `mm/shmem.c`) — the tmpfs `f_op->fallocate` body,
// split out of `file.rs` to keep that file's inode/file-ops manifest bounded.

use core::sync::atomic::Ordering;

use vfs::uapi::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE};
use vfs::{Inode, KResult, VfsError};

use vfs::mapping::AddressSpaceOps;

use super::file::TmpfsFileData;
use super::flags::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_WRITE};

/// `shmem_fallocate`. RAM has no extent tree, so the only modes shmem serves
/// are preallocation (with or without `KEEP_SIZE`) and hole punching;
/// ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, UNSHARE_RANGE and WRITE_ZEROES are
/// `EOPNOTSUPP` HERE rather than pre-judged by the VFS, which is why the raw
/// mode is handed down. # C: O(len/PG)
pub(super) fn shmem_fallocate(inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
    if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0 { return Err(VfsError::Eopnotsupp); }
    let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
    let seals = inode.fcntl_seals().map_or(0, |a| a.load(Ordering::Acquire));
    let end = off.checked_add(len).ok_or(VfsError::Einval)?;
    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 { return Err(VfsError::Eperm); }
        // PUNCH_HOLE on RAM-backed data: zero the range, size unchanged
        // (satisfies the read-as-zeros contract for the deallocated range).
        d.do_fallocate(off, len, /*keep_size*/ true, /*zero_range*/ true)?;
        inode.set_size(d.size());
        return Ok(());
    }
    // "We need to check rlimit even when FALLOC_FL_KEEP_SIZE": shmem commits real
    // pages either way, so the caller's RLIMIT_FSIZE binds on the END of the
    // allocated range and not on `i_size`. ext4 deliberately differs.
    vfs::inode_newsize_ok(inode, end)?;
    // F_SEAL_GROW likewise binds on the range, not on the size change: a sealed
    // memfd may not gain pages past its end even under KEEP_SIZE.
    if seals & F_SEAL_GROW != 0 && end > d.size() { return Err(VfsError::Eperm); }
    // New shmem pages arrive zeroed, so plain preallocation already satisfies the
    // read-as-zeros contract without a zeroing pass.
    d.do_fallocate(off, len, mode & FALLOC_FL_KEEP_SIZE != 0, /*zero_range*/ false)?;
    inode.set_size(d.size());
    Ok(())
}
