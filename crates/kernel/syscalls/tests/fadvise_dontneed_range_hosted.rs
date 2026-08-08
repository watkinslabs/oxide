//! `POSIX_FADV_DONTNEED` whole-page victim arithmetic (slot 221).
//!
//! DONTNEED's observable contract is which pages SURVIVE, and the survivors are
//! decided entirely by integer rounding: round the first index UP, the last
//! DOWN, then step the last back one so a trailing partial page is preserved —
//! except when that partial page ends on a page boundary (nothing is partial)
//! or is the file's EOF page (nothing can want its tail). Every one of those
//! clauses is a silent data-retention/eviction bug when it is wrong, and none
//! of them is visible from userspace except as memory pressure, so the
//! arithmetic is pinned here rather than inferred from a boot.

use syscalls::fadvise_policy::{FADV_PAGE_SIZE as PG, dontneed_page_range, fadvise_endbyte};

/// `len == 0` means "to end of file" and an overflowing `offset + len`
/// saturates rather than wrapping. The overflow test must be SIGNED: with
/// `offset == len == i64::MAX` the unsigned sum is `0xFFFF_FFFF_FFFF_FFFE`,
/// which is larger than `len` as a `u64` and would yield an endbyte of `-3`.
#[test]
fn endbyte_zero_len_and_overflow_saturate() {
    assert_eq!(fadvise_endbyte(0, 0), i64::MAX);
    assert_eq!(fadvise_endbyte(4096, 0), i64::MAX);
    assert_eq!(fadvise_endbyte(i64::MAX, i64::MAX), i64::MAX);
    assert_eq!(fadvise_endbyte(i64::MAX, 1), i64::MAX);
    // The ordinary case is inclusive: [0, 4096) has last byte 4095.
    assert_eq!(fadvise_endbyte(0, 4096), 4095);
    assert_eq!(fadvise_endbyte(1, 1), 1);
}

/// `offset == 0, len == 0` discards the whole cache: index 0 through the
/// highest representable index. `LLONG_MAX`'s low bits are all ones, so it
/// ends on a page boundary and no trailing page is spared.
#[test]
fn zero_offset_zero_len_covers_the_whole_file() {
    assert_eq!(dontneed_page_range(0, 0, 8192), Some((0, (i64::MAX as u64) / PG)));
    // A non-zero offset with len == 0 still runs to the end, from its first
    // FULLY covered page.
    assert_eq!(dontneed_page_range(1, 0, 8192), Some((1, (i64::MAX as u64) / PG)));
}

/// A range wholly inside one page discards nothing — the partial page is
/// preserved, and the index-0 underflow guard is what makes that true instead
/// of "discard the entire file".
#[test]
fn range_inside_one_page_discards_nothing() {
    assert_eq!(dontneed_page_range(100, 200, 4096), None);
    assert_eq!(dontneed_page_range(0, 1, 1 << 20), None);
    assert_eq!(dontneed_page_range(PG as i64 + 8, 16, 1 << 20), None);
}

/// A range whose last byte is exactly `i_size - 1` DOES discard its trailing
/// partial page: no future read of the file can want bytes past EOF.
#[test]
fn trailing_partial_page_at_eof_is_discarded() {
    // One 100-byte file: the whole file is page 0's first 100 bytes.
    assert_eq!(dontneed_page_range(0, 100, 100), Some((0, 0)));
    // Two-and-a-bit pages: page 2 is partial but is the EOF page.
    let size = 2 * PG + 100;
    assert_eq!(dontneed_page_range(0, size as i64, size), Some((0, 2)));
    // The same range against a LARGER file keeps page 2 — the only difference
    // is whether the partial page is at EOF.
    assert_eq!(dontneed_page_range(0, size as i64, size + 1), Some((0, 1)));
}

/// A range that ends on a page's last byte has no partial tail, so the last
/// page is discarded whether or not it is at EOF.
#[test]
fn page_aligned_end_keeps_its_last_page() {
    assert_eq!(dontneed_page_range(0, 2 * PG as i64, 1 << 20), Some((0, 1)));
    assert_eq!(dontneed_page_range(0, PG as i64, 1 << 20), Some((0, 0)));
    // One byte short of the boundary loses that page.
    assert_eq!(dontneed_page_range(0, 2 * PG as i64 - 1, 1 << 20), Some((0, 0)));
}

/// An unaligned start preserves the straddled first page: `start_index` rounds
/// UP, so only fully covered pages are candidates.
#[test]
fn unaligned_start_preserves_the_straddled_page() {
    assert_eq!(dontneed_page_range(1, 3 * PG as i64 - 1, 1 << 20), Some((1, 2)));
    assert_eq!(dontneed_page_range(PG as i64 - 1, 2 * PG as i64, 1 << 20), Some((1, 1)));
    // Start unaligned and end partial: both boundary pages survive.
    assert_eq!(dontneed_page_range(PG as i64 + 1, 2 * PG as i64, 1 << 20), Some((2, 2)));
}

/// A range extending past EOF is not an error and is not clamped — the pages
/// beyond EOF simply are not resident, so naming them costs nothing.
#[test]
fn range_past_eof_is_accepted() {
    assert_eq!(dontneed_page_range(0, 1 << 20, PG), Some((0, (1 << 20) / PG - 1)));
    assert_eq!(dontneed_page_range(0, 8 * PG as i64, 100), Some((0, 7)));
}

/// The overflow pair yields no victim range rather than a wrapped one: the
/// rounded-up start index exceeds the rounded-down end index.
#[test]
fn overflowing_offset_plus_len_yields_no_range() {
    assert_eq!(dontneed_page_range(i64::MAX, i64::MAX, 1 << 20), None);
    assert_eq!(dontneed_page_range(i64::MAX, 1, 1 << 20), None);
    // Negative arguments never reach this function (they are EINVAL), but the
    // total function must not produce a range for them either.
    assert_eq!(dontneed_page_range(-1, 0, 1 << 20), None);
    assert_eq!(dontneed_page_range(0, -1, 1 << 20), None);
}

/// An empty file has no EOF exception to apply, and computing one must not
/// underflow `i_size - 1`.
#[test]
fn empty_file_has_no_eof_exception() {
    assert_eq!(dontneed_page_range(0, 100, 0), None);
    // ...and the whole-file form still names the whole index space.
    assert_eq!(dontneed_page_range(0, 0, 0), Some((0, (i64::MAX as u64) / PG)));
}
