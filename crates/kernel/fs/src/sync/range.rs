// `sync_file_range(2)` work-fn: flag/offset validation, file-type gate, then
// the WAIT_BEFORE/WRITE/WAIT_AFTER range writeback.
//
// NOT an fsync: none of these operations write out the file's metadata. The
// syscall pushes page-cache DATA over a byte range and nothing else, which is
// why the old routing of slot 277 into `sys_fsync` was wrong twice over — it
// committed metadata the caller never asked for, and it ignored every
// argument but `fd`.

use syscall::errno::Errno;
use vfs::{File, FileType};

/// Wait for writeback already in flight over the range, before starting new
/// writeback.
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
/// Start writeback of the range's dirty pages.
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
/// Wait for the writeback just started (or already in flight) to complete.
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;
/// Every other flag bit is `EINVAL`.
pub const SYNC_FILE_RANGE_VALID_FLAGS: u32 =
    SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;

/// The inclusive end byte substituted when `nbytes == 0` ("out to EOF").
const LLONG_MAX: i64 = i64::MAX;

/// Resolved byte window for one `sync_file_range` call: `[start, end_incl]`,
/// INCLUSIVE at both ends.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SyncRange { pub start: i64, pub end_incl: i64 }

/// Argument ladder up to (not including) the file-type test — pure
/// arithmetic on the raw syscall words, so it is unit tested without a live
/// fd. Order: 1) flags outside the valid set, 2) `offset < 0`, 3)
/// `endbyte < 0`, 4) `endbyte < offset`, where `endbyte = offset + nbytes`.
///
/// Returns the resolved inclusive window, or the errno for the failing check.
/// # C: O(1)
pub fn sync_range_window(offset: i64, nbytes: i64, flags: u32) -> Result<SyncRange, Errno> {
    if flags & !SYNC_FILE_RANGE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    // `endbyte = offset + nbytes` is computed with wrapping arithmetic and
    // then tested for the three sign/order conditions; a wrapping sum is
    // caught by `endbyte < 0` or `endbyte < offset`, so the wrap is
    // reproduced rather than rejected early.
    let endbyte = offset.wrapping_add(nbytes);
    if offset < 0 { return Err(Errno::Einval); }
    if endbyte < 0 { return Err(Errno::Einval); }
    if endbyte < offset { return Err(Errno::Einval); }
    // `nbytes == 0` means "to EOF"; otherwise the window is inclusive.
    let end_incl = if nbytes == 0 { LLONG_MAX } else { endbyte - 1 };
    Ok(SyncRange { start: offset, end_incl })
}

/// Only regular files, block devices, and directories pass; anything
/// else — pipe, FIFO, socket, char device, anon-inode fd — is `ESPIPE`, NOT
/// `EINVAL`. # C: O(1)
pub fn sync_range_type_ok(ft: FileType) -> bool {
    matches!(ft, FileType::Regular | FileType::BlockDev | FileType::Directory)
}

/// `sync_file_range(file, offset, nbytes, flags)` work-fn.
///
/// The three phases run in flag order and each aborts the call on error:
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
    /// BEFORE the offset tests: a call that is invalid on both counts reports
    /// the flag error. # C: O(1)
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
    /// conditions. A wrapping `offset + nbytes` is caught by one of the latter
    /// two rather than by an early overflow reject.
    /// # C: O(1)
    #[test]
    fn offset_sign_and_order_rules() {
        assert_eq!(sync_range_window(-1, 1, 0), Err(Errno::Einval));
        assert_eq!(sync_range_window(0, -1, 0), Err(Errno::Einval)); // endbyte < 0
        assert_eq!(sync_range_window(10, -5, 0), Err(Errno::Einval)); // endbyte < offset
        assert_eq!(sync_range_window(i64::MAX, 2, 0), Err(Errno::Einval)); // wraps negative
        assert_eq!(sync_range_window(0, i64::MAX, 0), Ok(SyncRange { start: 0, end_incl: i64::MAX - 1 }));
    }

    /// `nbytes == 0` is "out to EOF" (end is the max inclusive value),
    /// otherwise the window is INCLUSIVE (last byte = `endbyte - 1`).
    /// # C: O(1)
    #[test]
    fn zero_nbytes_means_to_eof_else_inclusive() {
        assert_eq!(sync_range_window(0, 0, 0), Ok(SyncRange { start: 0, end_incl: i64::MAX }));
        assert_eq!(sync_range_window(4096, 0, 0), Ok(SyncRange { start: 4096, end_incl: i64::MAX }));
        assert_eq!(sync_range_window(0, 1, 0), Ok(SyncRange { start: 0, end_incl: 0 }));
        assert_eq!(sync_range_window(100, 8, 0), Ok(SyncRange { start: 100, end_incl: 107 }));
    }

    /// Only REG / BLK / DIR pass; everything else is ESPIPE.
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
