#![cfg(target_os = "oxide-kernel")]

// FS_IOC_FIEMAP (Linux `ioctl_fiemap`'s shape): map a file's physical
// extents into the caller's `struct fiemap`. filefrag(8), backup/dedup tools,
// and `xfs_io fiemap` use it. The per-fs geometry comes from
// `InodeOps::fiemap`; this shim marshals the uapi struct in/out only.

use syscall::errno::Errno;
use vfs::{FiemapExtent, InodeRef};

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// `_IOWR('f', 11, struct fiemap)`.
const FS_IOC_FIEMAP: u64 = 0xC020_660B;
const FIEMAP_MAX_EXTENTS: u32 = u32::MAX / FIEMAP_EXTENT_SZ as u32;

// `struct fiemap` field offsets.
const FM_START:        u64 = 0;   // __u64 fm_start
const FM_LENGTH:       u64 = 8;   // __u64 fm_length
const FM_FLAGS:        u64 = 16;  // __u32 fm_flags
const FM_MAPPED:       u64 = 20;  // __u32 fm_mapped_extents (out)
const FM_EXTENT_COUNT: u64 = 24;  // __u32 fm_extent_count (in)
const FM_EXTENTS:      u64 = 32;  // struct fiemap_extent fm_extents[]

// `struct fiemap_extent` (56 bytes) field offsets.
const FE_LOGICAL:  u64 = 0;   // __u64 fe_logical
const FE_PHYSICAL: u64 = 8;   // __u64 fe_physical
const FE_LENGTH:   u64 = 16;  // __u64 fe_length
const FE_FLAGS:    u64 = 40;  // __u32 fe_flags
const FIEMAP_EXTENT_SZ: u64 = 56;

/// Handle `FS_IOC_FIEMAP` on a regular-file/dir fd. Returns `Some(rv)` when
/// `req` is FIEMAP (so the caller stops dispatching), `None` otherwise.
/// `fm_extent_count == 0` is a count-only query (Linux): report how many
/// extents would be returned in `fm_mapped_extents`, write no array entries.
/// # C: O(N_extents)
pub fn handle_fiemap(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    if req != FS_IOC_FIEMAP { return None; }
    if let Err(rv) = validate_user_buf_readable(arg, FM_EXTENTS, 1) { return Some(rv); }
    if let Err(rv) = validate_user_buf_writable(arg, FM_EXTENTS, 1) { return Some(rv); }
    // SAFETY: arg validated in user range; the header fields are 8/4-byte
    // reads of the caller's `struct fiemap` (fm_start/fm_length/fm_extent_count).
    let (start, length, flags, count) = unsafe {
        (
            core::ptr::read_volatile((arg + FM_START) as *const u64),
            core::ptr::read_volatile((arg + FM_LENGTH) as *const u64),
            core::ptr::read_volatile((arg + FM_FLAGS) as *const u32),
            core::ptr::read_volatile((arg + FM_EXTENT_COUNT) as *const u32),
        )
    };
    if count > FIEMAP_MAX_EXTENTS { return Some(-(Errno::Einval.as_i32() as i64)); }
    // Reject an extent array that would run past the user address space.
    if count != 0 {
        let bytes = (count as u64).checked_mul(FIEMAP_EXTENT_SZ)
            .ok_or(-(Errno::Efault.as_i32() as i64));
        let bytes = match bytes { Ok(n) => n, Err(rv) => return Some(rv) };
        let base = match arg.checked_add(FM_EXTENTS) {
            Some(v) => v, None => return Some(-(Errno::Efault.as_i32() as i64)),
        };
        if let Err(rv) = validate_user_buf_writable(base, bytes, 1) { return Some(rv); }
    }
    let mut matched: u32 = 0;
    let mut written: u32 = 0;
    let mut emit = |fe: FiemapExtent| -> bool {
        matched = matched.saturating_add(1);
        if count == 0 { return true; }          // count-only: keep tallying
        if written >= count { return false; }   // array full: stop the walk
        let base = arg + FM_EXTENTS + written as u64 * FIEMAP_EXTENT_SZ;
        // SAFETY: `base + FIEMAP_EXTENT_SZ` bounds-checked above against
        // USER_VA_END; CPL=0 writes of one `struct fiemap_extent` (fe_logical/
        // fe_physical/fe_length/fe_flags; reserved fields left as caller-zeroed).
        unsafe {
            core::ptr::write_volatile((base + FE_LOGICAL) as *mut u64, fe.logical);
            core::ptr::write_volatile((base + FE_PHYSICAL) as *mut u64, fe.physical);
            core::ptr::write_volatile((base + FE_LENGTH) as *mut u64, fe.length);
            core::ptr::write_volatile((base + FE_FLAGS) as *mut u32, fe.flags);
        }
        written = written.saturating_add(1);
        written < count
    };
    let rv = match inode.fiemap(start, length, &mut emit) {
        Ok(()) => {
            let mapped = if count == 0 { matched } else { written };
            // SAFETY: arg validated in user range; 4-byte out-param write of
            // fm_flags/fm_mapped_extents into the caller's `struct fiemap`.
            unsafe {
                core::ptr::write_volatile((arg + FM_FLAGS) as *mut u32, flags);
                core::ptr::write_volatile((arg + FM_MAPPED) as *mut u32, mapped);
            }
            0
        }
        Err(e) => crate::namei_common::errno_from_vfs(e),
    };
    Some(rv)
}
