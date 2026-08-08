// Argument checks the two fallocate range-shift modes apply on top of the
// generic ladder. Deliberately free of I/O and of the `Mount` type so the whole
// decision — which errno, in which order — is exercised by hosted tests.

use vfs::{KResult, VfsError};

/// `FALLOC_FL_COLLAPSE_RANGE` admission.
///
/// Order is load-bearing: the alignment rejection comes first, so a misaligned
/// request that ALSO runs past EOF reports the alignment. The range must end
/// strictly before EOF — collapsing to or past the end is a truncate, and is
/// refused rather than silently reinterpreted.
/// # C: O(1)
pub(super) fn collapse_range_ok(off: u64, len: u64, size: u64, bs: u64) -> KResult<()> {
    if bs == 0 { return Err(VfsError::Eio); }
    if off % bs != 0 || len % bs != 0 { return Err(VfsError::Einval); }
    let end = off.checked_add(len).ok_or(VfsError::Einval)?;
    if end >= size { return Err(VfsError::Einval); }
    Ok(())
}

/// `FALLOC_FL_INSERT_RANGE` admission.
///
/// Same alignment-first order. The offset must lie strictly inside the file —
/// inserting at or past EOF is an extension, not an insertion. The size check
/// is expressed against the remaining headroom (`maxbytes - size`) rather than
/// as `size + len`, so it cannot itself overflow, and it reports `EFBIG`.
/// # C: O(1)
pub(super) fn insert_range_ok(off: u64, len: u64, size: u64, bs: u64, maxbytes: u64) -> KResult<()> {
    if bs == 0 { return Err(VfsError::Eio); }
    if off % bs != 0 || len % bs != 0 { return Err(VfsError::Einval); }
    if off >= size { return Err(VfsError::Einval); }
    if len > maxbytes.saturating_sub(size) { return Err(VfsError::Efbig); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 4096;
    const SIZE: u64 = BS * 8;
    const MAXBYTES: u64 = 1 << 46;

    #[test]
    fn collapse_accepts_an_aligned_range_wholly_inside_the_file() {
        assert_eq!(collapse_range_ok(BS, BS * 2, SIZE, BS), Ok(()));
    }

    #[test]
    fn collapse_rejects_a_misaligned_offset_or_length() {
        assert_eq!(collapse_range_ok(1, BS, SIZE, BS), Err(VfsError::Einval));
        assert_eq!(collapse_range_ok(BS, BS + 1, SIZE, BS), Err(VfsError::Einval));
    }

    #[test]
    fn collapse_rejects_a_range_reaching_eof() {
        assert_eq!(collapse_range_ok(BS * 7, BS, SIZE, BS), Err(VfsError::Einval),
            "ending exactly at EOF would be a truncate");
        assert_eq!(collapse_range_ok(BS * 7, BS * 4, SIZE, BS), Err(VfsError::Einval));
    }

    #[test]
    fn collapse_reports_alignment_before_the_eof_rejection() {
        // Misaligned AND past EOF: the alignment answer is the one that wins,
        // so a caller fixing one error at a time is told about the right one.
        assert_eq!(collapse_range_ok(BS * 7 + 1, BS * 9, SIZE, BS), Err(VfsError::Einval));
    }

    #[test]
    fn collapse_on_an_empty_file_is_rejected() {
        assert_eq!(collapse_range_ok(0, BS, 0, BS), Err(VfsError::Einval));
    }

    #[test]
    fn insert_accepts_an_aligned_offset_inside_the_file() {
        assert_eq!(insert_range_ok(BS, BS * 2, SIZE, BS, MAXBYTES), Ok(()));
        assert_eq!(insert_range_ok(0, BS, SIZE, BS, MAXBYTES), Ok(()),
            "inserting at the very start of a non-empty file is legal");
    }

    #[test]
    fn insert_rejects_a_misaligned_offset_or_length() {
        assert_eq!(insert_range_ok(BS + 1, BS, SIZE, BS, MAXBYTES), Err(VfsError::Einval));
        assert_eq!(insert_range_ok(BS, 1, SIZE, BS, MAXBYTES), Err(VfsError::Einval));
    }

    #[test]
    fn insert_at_or_past_eof_is_rejected() {
        assert_eq!(insert_range_ok(SIZE, BS, SIZE, BS, MAXBYTES), Err(VfsError::Einval));
        assert_eq!(insert_range_ok(SIZE + BS, BS, SIZE, BS, MAXBYTES), Err(VfsError::Einval));
    }

    #[test]
    fn insert_past_the_filesystem_size_ceiling_is_efbig() {
        let size = MAXBYTES - BS;
        assert_eq!(insert_range_ok(0, BS * 2, size, BS, MAXBYTES), Err(VfsError::Efbig));
        assert_eq!(insert_range_ok(0, BS, size, BS, MAXBYTES), Ok(()),
            "exactly filling the remaining headroom still fits");
    }

    #[test]
    fn insert_reports_alignment_before_the_size_ceiling() {
        let size = MAXBYTES - BS;
        assert_eq!(insert_range_ok(1, BS * 2, size, BS, MAXBYTES), Err(VfsError::Einval));
    }
}
