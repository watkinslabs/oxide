#![cfg(target_os = "oxide-kernel")]

// FS_IOC_FIEMAP (Linux `ioctl_fiemap`'s shape): map a file's physical
// extents into the caller's `struct fiemap`. filefrag(8), backup/dedup tools,
// and `xfs_io fiemap` use it. The per-fs geometry comes from
// `InodeOps::fiemap`; this shim marshals the uapi struct in/out only.

use vfs::{FiemapExtent, InodeRef};

use crate::ioctl_user as user;

/// `_IOWR('f', 11, struct fiemap)`.
const FS_IOC_FIEMAP: u64 = 0xC020_660B;

// `struct fiemap` field offsets; `FM_EXTENTS` is also the header's size.
const FM_START:        u64 = 0;   // __u64 fm_start
const FM_LENGTH:       u64 = 8;   // __u64 fm_length
const FM_FLAGS:        u64 = 16;  // __u32 fm_flags
const FM_MAPPED:       u64 = 20;  // __u32 fm_mapped_extents (out)
const FM_EXTENT_COUNT: u64 = 24;  // __u32 fm_extent_count (in)
const FM_EXTENTS:      u64 = 32;  // struct fiemap_extent fm_extents[]

// `struct fiemap_extent` (56 bytes) field offsets. Every field this shim does
// not set is reported as zero: the whole record is zeroed before it is copied,
// so a caller never reads back its own stale bytes as extent metadata.
const FE_LOGICAL:  u64 = 0;   // __u64 fe_logical
const FE_PHYSICAL: u64 = 8;   // __u64 fe_physical
const FE_LENGTH:   u64 = 16;  // __u64 fe_length
const FE_FLAGS:    u64 = 40;  // __u32 fe_flags

/// Handle `FS_IOC_FIEMAP` on a regular-file/dir fd. Returns `Some(rv)` when
/// `req` is FIEMAP (so the caller stops dispatching), `None` otherwise.
/// `fm_extent_count == 0` is a count-only query (Linux): report how many
/// extents would be returned in `fm_mapped_extents`, write no array entries.
/// Each extent is copied out as it is produced, and a fault on any one of them
/// aborts the walk with `EFAULT` — the extent array is caller memory that can
/// go away mid-walk, so it is never dereferenced raw.
/// # C: O(N_extents)
pub fn handle_fiemap(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    if req != FS_IOC_FIEMAP { return None; }
    let hdr = match user::get_bytes::<{ FM_EXTENTS as usize }>(arg) {
        Ok(b) => b, Err(rv) => return Some(rv),
    };
    let u64_at = |off: u64| { let o = off as usize; let mut v = [0u8; 8]; v.copy_from_slice(&hdr[o..o + 8]); u64::from_ne_bytes(v) };
    let u32_at = |off: u64| { let o = off as usize; u32::from_ne_bytes([hdr[o], hdr[o + 1], hdr[o + 2], hdr[o + 3]]) };
    let (start, length, flags, count) =
        (u64_at(FM_START), u64_at(FM_LENGTH), u32_at(FM_FLAGS), u32_at(FM_EXTENT_COUNT));
    let extent_bytes = match user::fiemap_extent_span(count) { Ok(n) => n, Err(rv) => return Some(rv) };
    let array = match arg.checked_add(FM_EXTENTS) {
        Some(v) => v, None => return Some(user::EFAULT),
    };
    if array.checked_add(extent_bytes).is_none() { return Some(user::EFAULT); }
    let mut matched: u32 = 0;
    let mut written: u32 = 0;
    let mut fault: Option<i64> = None;
    let mut emit = |fe: FiemapExtent| -> bool {
        matched = matched.saturating_add(1);
        if count == 0 { return true; }          // count-only: keep tallying
        if written >= count { return false; }   // array full: stop the walk
        let mut rec = [0u8; user::FIEMAP_EXTENT_BYTES as usize];
        rec[FE_LOGICAL as usize..][..8].copy_from_slice(&fe.logical.to_ne_bytes());
        rec[FE_PHYSICAL as usize..][..8].copy_from_slice(&fe.physical.to_ne_bytes());
        rec[FE_LENGTH as usize..][..8].copy_from_slice(&fe.length.to_ne_bytes());
        rec[FE_FLAGS as usize..][..4].copy_from_slice(&fe.flags.to_ne_bytes());
        let at = array + written as u64 * user::FIEMAP_EXTENT_BYTES;
        if let Err(rv) = user::put_bytes(at, &rec) { fault = Some(rv); return false; }
        written = written.saturating_add(1);
        written < count
    };
    let walk = inode.fiemap(start, length, &mut emit);
    // The reference reports the header back whatever the walk did, so a partial
    // result still tells the caller how many extents it got.
    let mapped = if count == 0 { matched } else { written };
    let mut out = hdr;
    out[FM_FLAGS as usize..][..4].copy_from_slice(&flags.to_ne_bytes());
    out[FM_MAPPED as usize..][..4].copy_from_slice(&mapped.to_ne_bytes());
    let rv = match (fault, walk) {
        (Some(rv), _) => rv,
        (None, Err(e)) => crate::namei_common::errno_from_vfs(e),
        (None, Ok(())) => 0,
    };
    match user::put_bytes(arg, &out) {
        Ok(()) => Some(rv),
        Err(fault) => Some(fault),
    }
}
