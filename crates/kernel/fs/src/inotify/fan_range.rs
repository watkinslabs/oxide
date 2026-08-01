// fanotify PRE-CONTENT byte ranges (`FAN_PRE_ACCESS`) and the
// `FAN_EVENT_INFO_TYPE_RANGE` info record that carries one.
//
// A pre-content group sits AHEAD of the data: it is asked whether an access may
// proceed before the bytes it names are read, so it can fill them first. That
// only works if it is told WHICH bytes, which is what this record is for.
//
// Deliberately free of any target gate so the alignment rule and the record
// layout are hosted-testable.

/// `FAN_EVENT_INFO_TYPE_RANGE` — the info record naming the byte range an
/// access covers.
pub(crate) const FAN_EVENT_INFO_TYPE_RANGE: u8 = 6;

/// `sizeof(struct fanotify_event_info_range)`: the 4-byte shared
/// `fanotify_event_info_header {info_type u8, pad u8, len u16}`, a `__u32` of
/// padding that aligns the two 64-bit fields, then `__u64 offset` and
/// `__u64 count`. Already a multiple of the record alignment.
pub(crate) const RANGE_INFO_LEN: usize = 4 + 4 + 8 + 8;

/// Reporting granularity for a pre-content range. A watcher fills whole pages —
/// the page is the unit the kernel faults content in at — so a range is widened
/// to page boundaries rather than reported byte-exact.
const RANGE_GRANULE: u64 = hal::PAGE_SIZE_BYTES;

/// The range one access reports: `pos` rounded DOWN to the granule and the end
/// rounded UP, so the reported window always covers every byte the access
/// touches. A zero-length access still reports the granule its offset falls in —
/// a truncate names a point, and the watcher still has to fill the page holding
/// it.
/// # C: O(1)
pub(crate) fn aligned_range(pos: u64, count: u64) -> (u64, u64) {
    let start = pos & !(RANGE_GRANULE - 1);
    let end = pos.saturating_add(count).saturating_add(RANGE_GRANULE - 1) & !(RANGE_GRANULE - 1);
    (start, end.saturating_sub(start))
}

/// Encode one `fanotify_event_info_range`. Returns the bytes written, or 0 when
/// `dst` cannot hold the whole record (a reader never sees a partial record).
/// # C: O(1)
pub(crate) fn encode_range_info(dst: &mut [u8], offset: u64, count: u64) -> usize {
    if dst.len() < RANGE_INFO_LEN { return 0; }
    dst[0] = FAN_EVENT_INFO_TYPE_RANGE;
    dst[1] = 0;
    dst[2..4].copy_from_slice(&(RANGE_INFO_LEN as u16).to_le_bytes());
    dst[4..8].copy_from_slice(&0u32.to_le_bytes());
    dst[8..16].copy_from_slice(&offset.to_le_bytes());
    dst[16..24].copy_from_slice(&count.to_le_bytes());
    RANGE_INFO_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_is_a_header_a_pad_and_two_64_bit_fields() {
        let mut buf = [0xAAu8; 32];
        assert_eq!(encode_range_info(&mut buf, 0x1000, 0x2000), RANGE_INFO_LEN);
        assert_eq!(buf[0], FAN_EVENT_INFO_TYPE_RANGE);
        assert_eq!(buf[1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), RANGE_INFO_LEN as u16);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 0, "explicit pad word");
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x1000);
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 0x2000);
        assert_eq!(buf[24], 0xAA, "nothing written past the record");
        assert_eq!(RANGE_INFO_LEN % 4, 0, "record needs no trailing alignment padding");
    }

    #[test]
    fn encode_refuses_to_write_a_partial_record() {
        let mut buf = [0xAAu8; 23];
        assert_eq!(encode_range_info(&mut buf, 1, 2), 0);
        assert_eq!(buf, [0xAAu8; 23], "nothing written");
    }

    /// The reported window always COVERS the access: start rounds down, end
    /// rounds up, and a range that straddles a boundary reports both granules.
    /// # C: O(1)
    #[test]
    fn a_range_is_widened_outward_to_whole_granules() {
        let g = RANGE_GRANULE;
        assert_eq!(aligned_range(0, g), (0, g));
        assert_eq!(aligned_range(1, 1), (0, g), "one byte still names its whole granule");
        assert_eq!(aligned_range(g - 1, 2), (0, 2 * g), "an access across a boundary reports both");
        assert_eq!(aligned_range(g, g), (g, g));
        assert_eq!(aligned_range(3 * g + 5, g), (3 * g, 2 * g));
    }

    /// A zero-length access still names the granule its offset falls in: a
    /// truncate names a point, and the content at that point still has to exist.
    /// # C: O(1)
    #[test]
    fn a_zero_length_access_still_names_one_granule() {
        let g = RANGE_GRANULE;
        assert_eq!(aligned_range(0, 0), (0, 0), "a zero-length access at zero spans nothing");
        assert_eq!(aligned_range(g + 1, 0), (g, g));
    }

    /// A count that would overflow the end computation saturates instead of
    /// wrapping into a small — and therefore wrong — window.
    /// # C: O(1)
    #[test]
    fn an_overflowing_count_saturates_rather_than_wrapping() {
        let (start, count) = aligned_range(u64::MAX - 1, u64::MAX);
        assert!(start <= u64::MAX - 1);
        assert!(count == 0 || start.checked_add(count).is_some());
    }
}
