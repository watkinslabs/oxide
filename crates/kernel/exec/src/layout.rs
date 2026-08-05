// How one PT_LOAD divides between a mapping of the file it came from and
// kernel-owned bytes.
//
// A segment whose memory size exceeds its file size ends in zeroes the file
// does not contain, so the page straddling that boundary cannot be served from
// the file: its head is file content and its tail is `.bss`. Everything below
// that boundary page is the file, byte for byte, and is mapped as such — which
// is what makes the program's text and data show up as file-backed to anything
// that classifies a mapping by what stands behind it (`/proc/<pid>/maps`, the
// core-dump filter, the `NT_FILE` note).
//
// Decisions live here, with no target gate, so they are testable without a
// kernel; `load` owns the mapping calls.

/// The VA at which one segment stops being a mapping of its file, and the file
/// offset that mapping starts from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SegmentSplit {
    /// End of the file-mapped prefix. Equal to the segment's start when
    /// nothing is mapped from the file.
    pub file_end:   u64,
    /// Page-aligned file offset the prefix maps from. Meaningless when
    /// `file_end` equals the segment start.
    pub file_pgoff: u64,
    /// File offset at which this mapping returns zeroes for `.bss`.
    pub file_zero_from: Option<u64>,
}

/// A loadable segment's file offset and virtual address must agree modulo the
/// page size for a mapping of the file to land its bytes where the segment
/// wants them. Every toolchain-produced object satisfies this, because the
/// segment alignment is at least one page.
/// # C: O(1)
pub fn congruent(file_off: u64, vaddr: u64, page: u64) -> bool {
    (file_off & (page - 1)) == (vaddr & (page - 1))
}

/// Divide `[vstart, vend)` for one segment.
///
/// `file_backed` is false when the image has no file behind it; the whole
/// segment is then kernel-owned. A segment with
/// no `.bss` is a mapping of the file to its very last page: the bytes past its
/// file size in that page are the file's, exactly as a mapping of it serves
/// them. A segment with `.bss` gives up its boundary page.
/// # C: O(1)
pub fn split(
    vstart: u64,
    vend: u64,
    vaddr: u64,
    file_off: u64,
    file_sz: u64,
    mem_sz: u64,
    page: u64,
    file_backed: bool,
) -> SegmentSplit {
    let none = SegmentSplit { file_end: vstart, file_pgoff: 0, file_zero_from: None };
    if !file_backed || !congruent(file_off, vaddr, page) { return none; }
    let boundary = vaddr.saturating_add(file_sz);
    let file_end = if mem_sz <= file_sz { vend } else { ((boundary + page - 1) & !(page - 1)).min(vend) };
    SegmentSplit { file_end, file_pgoff: file_off & !(page - 1),
        file_zero_from: (mem_sz > file_sz).then_some(file_off + file_sz) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 0x1000;

    /// Text: file size equals memory size, so the whole segment is the file —
    /// including the partial last page, whose tail a mapping of the file
    /// serves from the file.
    #[test]
    fn a_segment_without_bss_is_mapped_from_the_file_to_its_last_page() {
        let s = split(0x400000, 0x403000, 0x400000, 0, 0x2abc, 0x2abc, PAGE, true);
        assert_eq!(s, SegmentSplit { file_end: 0x403000, file_pgoff: 0, file_zero_from: None });
    }

    /// Data: the page holding the file/memory boundary is part file, part
    /// zero, so it stops being a mapping of the file.
    #[test]
    fn a_segment_with_bss_keeps_its_boundary_page_and_zeroes_its_tail() {
        let s = split(0x600000, 0x604000, 0x600000, 0x5000, 0x2abc, 0x3fff, PAGE, true);
        assert_eq!(s.file_end, 0x603000);
        assert_eq!(s.file_pgoff, 0x5000);
        assert_eq!(s.file_zero_from, Some(0x7abc));
    }

    /// The boundary lands in the first page, so no whole page is the file.
    #[test]
    fn a_segment_whose_file_part_is_under_a_page_maps_nothing_from_the_file() {
        let s = split(0x600000, 0x603000, 0x600000, 0x5000, 0x800, 0x2000, PAGE, true);
        assert_eq!(s.file_end, 0x601000);
        assert_eq!(s.file_zero_from, Some(0x5800));
    }

    /// A segment starting mid-page maps from the page the file offset sits in,
    /// so the bytes before it are the file's too.
    #[test]
    fn an_unaligned_segment_maps_from_the_page_its_file_offset_sits_in() {
        let s = split(0x400000, 0x402000, 0x400120, 0x120, 0x1e00, 0x1e00, PAGE, true);
        assert_eq!(s, SegmentSplit { file_end: 0x402000, file_pgoff: 0, file_zero_from: None });
    }

    /// Offset and address that disagree modulo the page size cannot be
    /// expressed as a mapping at all.
    #[test]
    fn a_non_congruent_segment_is_never_mapped_from_the_file() {
        assert!(!congruent(0x140, 0x400120, PAGE));
        let s = split(0x400000, 0x402000, 0x400120, 0x140, 0x1e00, 0x1e00, PAGE, true);
        assert_eq!(s.file_end, 0x400000);
    }

    #[test]
    fn an_image_with_no_file_behind_it_is_never_mapped_from_one() {
        let s = split(0x400000, 0x402000, 0x400000, 0, 0x1e00, 0x1e00, PAGE, false);
        assert_eq!(s.file_end, 0x400000);
    }

}
