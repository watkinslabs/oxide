// `sync_file_range(2)` work-fn — Linux `fs/sync.c` `sync_file_range()`
// (`fs/sync.c:223-292`) + `ksys_sync_file_range()` (`:348-357`).
//
// NOT an fsync: Linux `fs/sync.c:341-346` states outright that "none of these
// operations write out the file's metadata". The syscall pushes page-cache
// DATA over a byte range and nothing else, which is why the old routing of slot
// 277 into `sys_fsync` was wrong twice over — it committed metadata the caller
// never asked for, and it ignored every argument but `fd`.

use syscall::errno::Errno;
use vfs::{File, FileType};

/// `SYNC_FILE_RANGE_WAIT_BEFORE` (Linux `include/uapi/linux/fs.h:414`).
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
/// `SYNC_FILE_RANGE_WRITE`.
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
/// `SYNC_FILE_RANGE_WAIT_AFTER`.
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;
/// Linux `fs/sync.c:22-23` `VALID_FLAGS` — every other bit is `EINVAL`.
pub const SYNC_FILE_RANGE_VALID_FLAGS: u32 =
    SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;

/// `LLONG_MAX` — the inclusive end byte Linux substitutes when `nbytes == 0`
/// ("out to EOF", `fs/sync.c:260-261`).
const LLONG_MAX: i64 = i64::MAX;

/// Resolved byte window for one `sync_file_range` call: `[start, end_incl]`,
/// INCLUSIVE at both ends exactly like Linux's `endbyte` (`fs/sync.c:263`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SyncRange { pub start: i64, pub end_incl: i64 }

/// Argument ladder of Linux `sync_file_range()` up to (not including) the
/// file-type test — pure arithmetic on the raw syscall words, so it is unit
/// tested without a live fd. Order is verbatim `fs/sync.c:232-262`:
/// flags first, then `offset < 0`, then `endbyte < 0`, then `endbyte < offset`.
///
/// Returns the resolved inclusive window, or the errno Linux reports.
/// # C: O(1)
pub fn sync_range_window(offset: i64, nbytes: i64, flags: u32) -> Result<SyncRange, Errno> {
    if flags & !SYNC_FILE_RANGE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    // Linux computes `endbyte = offset + nbytes` in loff_t and then tests the
    // three sign/order conditions; a wrapping sum is caught by `endbyte < 0`
    // or `endbyte < offset`, so the wrap is reproduced rather than rejected
    // early (`fs/sync.c:235-241`).
    let endbyte = offset.wrapping_add(nbytes);
    if offset < 0 { return Err(Errno::Einval); }
    if endbyte < 0 { return Err(Errno::Einval); }
    if endbyte < offset { return Err(Errno::Einval); }
    // `nbytes == 0` means "to EOF"; otherwise the window is inclusive.
    let end_incl = if nbytes == 0 { LLONG_MAX } else { endbyte - 1 };
    Ok(SyncRange { start: offset, end_incl })
}

/// `S_ISREG || S_ISBLK || S_ISDIR` gate (Linux `fs/sync.c:265-268`): anything
/// else — pipe, FIFO, socket, char device, anon-inode fd — is `ESPIPE`, NOT
/// `EINVAL`. # C: O(1)
pub fn sync_range_type_ok(ft: FileType) -> bool {
    matches!(ft, FileType::Regular | FileType::BlockDev | FileType::Directory)
}

/// `sync_file_range(file, offset, nbytes, flags)` — Linux `fs/sync.c:223-292`.
///
/// The three phases run in Linux's order and each aborts the call on error:
/// WAIT_BEFORE (wait for writeback already in flight over the range), WRITE
/// (start writeback of the range's dirty pages), WAIT_AFTER (wait for it).
/// Oxide's page-cache writeback is synchronous, so a WAIT phase has nothing
/// left to await once WRITE has returned and only harvests the address space's
/// deferred error; the WRITE phase is a real range-scoped
/// `AddressSpaceOps::writeback_range`, never a whole-file fsync.
///
/// Returns 0 or `-errno`.
/// # C: O(N_dirty in range)
pub fn sync_file_range(file: &File, offset: i64, nbytes: i64, flags: u32) -> i64 {
    let win = match sync_range_window(offset, nbytes, flags) {
        Ok(w)  => w,
        Err(e) => return -(e.as_i32() as i64),
    };
    if !sync_range_type_ok(file.inode().file_type()) {
        return -(Errno::Espipe.as_i32() as i64);
    }
    // No FMODE_WRITE requirement: Linux's ladder never inspects `f_mode`, so a
    // read-only description may flush a shared inode's dirty pages.
    let Some(mapping) = file.inode().i_mapping() else { return 0 };
    // Linux's endbyte is inclusive; `writeback_range` takes a half-open
    // `[start, end)`, and `LLONG_MAX` means "to EOF" (`u64::MAX` sentinel).
    let start = win.start as u64;
    let end = if win.end_incl == LLONG_MAX { u64::MAX } else { (win.end_incl as u64) + 1 };
    if flags & (SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WAIT_AFTER) == 0 {
        return 0;
    }
    if mapping.writeback_range(start, end).is_err() {
        return -(Errno::Eio.as_i32() as i64);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every bit outside `VALID_FLAGS` is `EINVAL`, and the flag test runs
    /// BEFORE the offset tests (`fs/sync.c:232-236`): a call that is invalid on
    /// both counts reports the flag error. # C: O(1)
    #[test]
    fn unknown_flags_rejected_before_offsets() {
        for bad in [8u32, 0x10, 0x8000_0000, !SYNC_FILE_RANGE_VALID_FLAGS] {
            assert_eq!(sync_range_window(0, 0, bad), Err(Errno::Einval), "flags {bad:#x}");
            // Negative offset too — still the flag error, same errno either way.
            assert_eq!(sync_range_window(-1, 0, bad), Err(Errno::Einval));
        }
        for ok in 0..=SYNC_FILE_RANGE_VALID_FLAGS {
            assert!(sync_range_window(0, 4096, ok).is_ok(), "flags {ok:#x} must be accepted");
        }
    }

    /// `offset < 0`, `endbyte < 0` and `endbyte < offset` are the three EINVAL
    /// conditions (`fs/sync.c:237-242`). A wrapping `offset + nbytes` is caught
    /// by one of the latter two rather than by an early overflow reject.
    /// # C: O(1)
    #[test]
    fn offset_sign_and_order_rules() {
        assert_eq!(sync_range_window(-1, 1, 0), Err(Errno::Einval));
        assert_eq!(sync_range_window(0, -1, 0), Err(Errno::Einval)); // endbyte < 0
        assert_eq!(sync_range_window(10, -5, 0), Err(Errno::Einval)); // endbyte < offset
        assert_eq!(sync_range_window(i64::MAX, 2, 0), Err(Errno::Einval)); // wraps negative
        assert_eq!(sync_range_window(0, i64::MAX, 0), Ok(SyncRange { start: 0, end_incl: i64::MAX - 1 }));
    }

    /// `nbytes == 0` is "out to EOF" (`endbyte = LLONG_MAX`), otherwise the
    /// window is INCLUSIVE (`endbyte--`). # C: O(1)
    #[test]
    fn zero_nbytes_means_to_eof_else_inclusive() {
        assert_eq!(sync_range_window(0, 0, 0), Ok(SyncRange { start: 0, end_incl: i64::MAX }));
        assert_eq!(sync_range_window(4096, 0, 0), Ok(SyncRange { start: 4096, end_incl: i64::MAX }));
        assert_eq!(sync_range_window(0, 1, 0), Ok(SyncRange { start: 0, end_incl: 0 }));
        assert_eq!(sync_range_window(100, 8, 0), Ok(SyncRange { start: 100, end_incl: 107 }));
    }

    /// Only REG / BLK / DIR pass; everything else is ESPIPE (`fs/sync.c:265-268`).
    /// # C: O(1)
    #[test]
    fn only_reg_blk_dir_pass_the_type_gate() {
        assert!(sync_range_type_ok(FileType::Regular));
        assert!(sync_range_type_ok(FileType::BlockDev));
        assert!(sync_range_type_ok(FileType::Directory));
        assert!(!sync_range_type_ok(FileType::Fifo));
        assert!(!sync_range_type_ok(FileType::Socket));
        assert!(!sync_range_type_ok(FileType::CharDev));
        assert!(!sync_range_type_ok(FileType::Symlink));
    }
}
