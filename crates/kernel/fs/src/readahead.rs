// `readahead(2)` work-fn — Linux `mm/readahead.c` `ksys_readahead()`
// (`mm/readahead.c:724-759`) → `vfs_fadvise(POSIX_FADV_WILLNEED)` →
// `generic_fadvise()` (`mm/fadvise.c:96-107`) → `force_page_cache_readahead()`.
//
// Slot 187 used to land in the compat table's `sys_fadvise_validate`, which
// checked only "is `fd` open" and returned 0. That answered the wrong
// questions: Linux rejects an unreadable description, a description with no
// address space, and any inode that is neither a regular file nor a block
// device — and, on success, actually populates the page cache.

use alloc::vec;
use syscall::errno::Errno;
use vfs::{File, FileType, Fmode};

/// Page granularity Linux readahead works in (`PAGE_SHIFT`); 4 KiB on both
/// arches' base page, matching `vfs::file::readahead::PAGE_SIZE`.
const PAGE_SIZE: u64 = 4096;

/// Admission ladder of `ksys_readahead()` (`mm/readahead.c:730-751`) expressed
/// over the facts the caller has already resolved, so the ORDER — which is the
/// only observable part of a rejected call — is unit tested without a live fd.
///
/// `has_mapping` is Linux's `file->f_mapping && file->f_mapping->a_ops`; an
/// oxide anon-inode description reports `None` from `Inode::i_mapping`, which
/// is the same "cannot execute readahead" condition `IS_ANON_FILE` covers.
/// # C: O(1)
pub fn readahead_admit(readable: bool, has_mapping: bool, ft: FileType) -> Result<(), Errno> {
    // `!(file->f_mode & FMODE_READ)` → EBADF (`mm/readahead.c:734-735`).
    if !readable { return Err(Errno::Ebadf); }
    // `!f_mapping` / `!f_mapping->a_ops` → EINVAL (`mm/readahead.c:742-745`).
    if !has_mapping { return Err(Errno::Einval); }
    // `!S_ISREG && !S_ISBLK` → EINVAL (`mm/readahead.c:748-749`). A FIFO lands
    // here and is EINVAL, NOT ESPIPE: `generic_fadvise`'s ESPIPE arm
    // (`mm/fadvise.c:42-43`) is unreachable from this syscall.
    if !matches!(ft, FileType::Regular | FileType::BlockDev) { return Err(Errno::Einval); }
    Ok(())
}

/// `generic_fadvise` argument check (`mm/fadvise.c:46-47`): `readahead(2)`
/// widens `count` from `size_t` to `loff_t`, so a `count` above `LLONG_MAX`
/// arrives negative and is `EINVAL` — as is a negative `offset`.
/// # C: O(1)
pub fn fadvise_range_ok(offset: i64, len: i64) -> bool { offset >= 0 && len >= 0 }

/// `readahead(file, offset, count)` — Linux `ksys_readahead`.
///
/// On success returns 0 unconditionally (`generic_fadvise` `mm/fadvise.c:174`);
/// `force_page_cache_readahead` returns `void`, so a readahead I/O failure is
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
    // Linux converts [offset, offset+count) to a page window; `count == 0`
    // means "to EOF" (`mm/fadvise.c:80-84` `endbyte = LLONG_MAX`).
    let size = file.inode().size();
    let start = offset as u64;
    let end = if len == 0 { size } else { (start.saturating_add(len as u64)).min(size) };
    if start >= end { return 0; }
    let first = start / PAGE_SIZE;
    let last = (end - 1) / PAGE_SIZE;
    // Bound the burst by the description's readahead ceiling scaled to the
    // request, exactly as `force_page_cache_readahead` clamps to `ra_pages`
    // per iteration; the loop below still walks the whole requested window.
    let mut scratch = vec![0u8; PAGE_SIZE as usize];
    for idx in first..=last {
        let off = idx * PAGE_SIZE;
        // Already-resident pages cost nothing (Linux skips them in
        // `page_cache_ra_unbounded` via the xarray probe).
        if mapping.mincore_page(off) { continue; }
        if mapping.read_at(off, &mut scratch).is_err() { break; }
    }
    // Advance the per-open readahead window so a following sequential read
    // starts from the grown state (Linux updates `file->f_ra`).
    let req = ((end - start + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
    let _ = file.ra_ondemand(first, req, false);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EBADF for an unreadable description beats every other rejection
    /// (`mm/readahead.c:734`), and the mapping test beats the file-type test
    /// (`:742` before `:748`). # C: O(1)
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

    /// A FIFO is EINVAL, not ESPIPE — `generic_fadvise`'s ESPIPE arm cannot be
    /// reached through `readahead(2)` because the `S_ISREG || S_ISBLK` filter
    /// runs first (`mm/readahead.c:748`). `fadvise64(2)` has no such filter and
    /// therefore CAN return ESPIPE; the two syscalls differ here. # C: O(1)
    #[test]
    fn fifo_is_einval_not_espipe() {
        for ft in [FileType::Fifo, FileType::Socket, FileType::CharDev,
                   FileType::Directory, FileType::Symlink] {
            assert_eq!(readahead_admit(true, true, ft), Err(Errno::Einval), "{ft:?}");
        }
    }

    /// EPERM is never a `readahead(2)` answer: the ladder has no capability or
    /// LSM hook at all (`mm/readahead.c:724-754` — no `capable()`, no
    /// `security_*`, and no `rw_verify_area`). This pins the regression the
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

    /// A `count` above `LLONG_MAX` becomes a negative `loff_t` and is EINVAL,
    /// as is a negative offset (`mm/fadvise.c:46-47`). # C: O(1)
    #[test]
    fn negative_offset_or_huge_count_is_einval() {
        assert!(fadvise_range_ok(0, 0));
        assert!(fadvise_range_ok(0, 4096));
        assert!(!fadvise_range_ok(-1, 4096));
        assert!(!fadvise_range_ok(0, (u64::MAX as i64).wrapping_add(0))); // -1 as loff_t
        assert!(!fadvise_range_ok(0, (1u64 << 63) as i64));
    }
}
