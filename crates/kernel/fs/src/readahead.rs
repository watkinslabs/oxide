// `readahead(2)` work-fn: admission ladder + `POSIX_FADV_WILLNEED`-style
// range resolution, then a page-cache fill over the resolved window.
//
// Slot 187 used to land in the compat table's `sys_fadvise_validate`, which
// checked only "is `fd` open" and returned 0. That answered the wrong
// questions: Linux rejects an unreadable description, a description with no
// address space, and any inode that is neither a regular file nor a block
// device — and, on success, actually populates the page cache.

use syscall::errno::Errno;
use vfs::{File, FileType, Fmode};

/// Page granularity readahead works in (`PAGE_SHIFT`); 4 KiB on both
/// arches' base page, matching `vfs::file::readahead::PAGE_SIZE`.
const PAGE_SIZE: u64 = 4096;

/// Admission ladder for `readahead(2)`, expressed
/// over the facts the caller has already resolved, so the ORDER — which is the
/// only observable part of a rejected call — is unit tested without a live fd.
///
/// `has_mapping` is "the description has a page-cache address space with
/// operations attached"; an oxide anon-inode description reports `None` from
/// `Inode::i_mapping`, which is the same "cannot execute readahead" condition.
/// # C: O(1)
pub fn readahead_admit(readable: bool, has_mapping: bool, ft: FileType) -> Result<(), Errno> {
    // An unreadable description (no FMODE_READ) → EBADF, checked first.
    if !readable { return Err(Errno::Ebadf); }
    // No address space / no address-space ops → EINVAL, checked next.
    if !has_mapping { return Err(Errno::Einval); }
    // Neither a regular file nor a block device → EINVAL. A FIFO lands
    // here and is EINVAL, NOT ESPIPE: the ESPIPE arm of the general fadvise
    // path is unreachable from this syscall.
    if !matches!(ft, FileType::Regular | FileType::BlockDev) { return Err(Errno::Einval); }
    Ok(())
}

/// `readahead(2)` range argument check: `count` widens from `size_t` to a
/// signed 64-bit byte count, so a `count` above `i64::MAX` arrives negative
/// and is `EINVAL` — as is a negative `offset`.
/// # C: O(1)
pub fn fadvise_range_ok(offset: i64, len: i64) -> bool { offset >= 0 && len >= 0 }

/// `readahead(file, offset, count)` work-fn.
///
/// On success returns 0 unconditionally; the underlying cache-fill primitive
/// returns nothing, so a readahead I/O failure is
/// never reported. The cache fill itself is real: every not-yet-resident page
/// of the requested window that lies below EOF is pulled through the inode's
/// address space, which is what makes a later `read`/fault hit the cache.
/// # C: O(pages in range)
pub fn readahead(file: &File, offset: i64, count: u64) -> i64 {
    let readable = file.f_mode().contains(Fmode::READ);
    let has_mapping = file.inode().i_mapping().is_some();
    if let Err(e) = readahead_admit(readable, has_mapping, file.inode().file_type()) {
        return -(e.as_i32() as i64);
    }
    // `count` is `size_t` at the ABI and `loff_t` inside `vfs_fadvise`.
    let len = count as i64;
    if !fadvise_range_ok(offset, len) { return -(Errno::Einval.as_i32() as i64); }
    let Some(mapping) = file.inode().i_mapping() else { return 0 };
    // Convert [offset, offset+count) to a page window; `count == 0`
    // means "to EOF" (an unbounded end clamped to the file's current size).
    let size = file.inode().size();
    let start = offset as u64;
    let end = if len == 0 { size } else { (start.saturating_add(len as u64)).min(size) };
    if start >= end { return 0; }
    let first = start / PAGE_SIZE;
    let last = (end - 1) / PAGE_SIZE;
    // ONE submit for the whole window. Already-resident pages cost nothing
    // (skipped via a cache probe before any I/O is issued) and a backend that
    // can fetch a run in a single device operation does so here. The
    // page-at-a-time `read_at` loop this replaces also copied every page into
    // a scratch buffer it immediately discarded.
    mapping.readahead(first, last - first + 1);
    // Advance the per-open readahead window so a following sequential read
    // starts from the grown state.
    let req = ((end - start + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
    let _ = file.ra_ondemand(first, req, false);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EBADF for an unreadable description beats every other rejection,
    /// and the mapping test beats the file-type test. # C: O(1)
    #[test]
    fn admission_order_is_ebadf_then_einval() {
        // Unreadable wins even though the type is also wrong.
        assert_eq!(readahead_admit(false, false, FileType::Fifo), Err(Errno::Ebadf));
        assert_eq!(readahead_admit(false, true, FileType::Regular), Err(Errno::Ebadf));
        // Readable but no address space → EINVAL regardless of type.
        assert_eq!(readahead_admit(true, false, FileType::Regular), Err(Errno::Einval));
        assert_eq!(readahead_admit(true, true, FileType::Regular), Ok(()));
        assert_eq!(readahead_admit(true, true, FileType::BlockDev), Ok(()));
    }

    /// A FIFO is EINVAL, not ESPIPE — the general fadvise path's ESPIPE arm
    /// cannot be reached through `readahead(2)` because the `S_ISREG ||
    /// S_ISBLK` filter runs first. `fadvise64(2)` has no such filter and
    /// therefore CAN return ESPIPE; the two syscalls differ here. # C: O(1)
    #[test]
    fn fifo_is_einval_not_espipe() {
        for ft in [FileType::Fifo, FileType::Socket, FileType::CharDev,
                   FileType::Directory, FileType::Symlink] {
            assert_eq!(readahead_admit(true, true, ft), Err(Errno::Einval), "{ft:?}");
        }
    }

    /// EPERM is never a `readahead(2)` answer: the ladder has no capability or
    /// LSM hook at all — no privilege check, no security-module hook, and no
    /// area-verification step. This pins the regression the
    /// compat-table routing used to risk. # C: O(1)
    #[test]
    fn eperm_is_never_a_readahead_answer() {
        for readable in [false, true] {
            for mapped in [false, true] {
                for ft in [FileType::Regular, FileType::BlockDev, FileType::Fifo,
                           FileType::Socket, FileType::CharDev, FileType::Directory] {
                    let r = readahead_admit(readable, mapped, ft);
                    assert_ne!(r, Err(Errno::Eperm), "{readable} {mapped} {ft:?}");
                }
            }
        }
    }

    /// A `count` above `i64::MAX` becomes a negative signed byte count and is
    /// EINVAL, as is a negative offset. # C: O(1)
    #[test]
    fn negative_offset_or_huge_count_is_einval() {
        assert!(fadvise_range_ok(0, 0));
        assert!(fadvise_range_ok(0, 4096));
        assert!(!fadvise_range_ok(-1, 4096));
        assert!(!fadvise_range_ok(0, (u64::MAX as i64).wrapping_add(0))); // -1 as loff_t
        assert!(!fadvise_range_ok(0, (1u64 << 63) as i64));
    }
}
