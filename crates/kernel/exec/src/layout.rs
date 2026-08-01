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

use elf::ElfType;

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
}

/// Whether the loader edits an image's bytes before it runs.
///
/// A position-independent image with no interpreter has nothing else to apply
/// its own `R_*_RELATIVE` entries before `_start`, so the loader applies them.
/// The result differs from the file on disk, so those segments cannot be a
/// mapping of it.
/// # C: O(1)
pub fn relocs_precede_file_backing(apply_self_relocs: bool, et: ElfType, bias: u64) -> bool {
    apply_self_relocs && matches!(et, ElfType::Dyn) && bias != 0
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
/// `file_backed` is false when the image has no file behind it or the loader
/// rewrote its bytes; the whole segment is then kernel-owned. A segment with
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
    let none = SegmentSplit { file_end: vstart, file_pgoff: 0 };
    if !file_backed || !congruent(file_off, vaddr, page) { return none; }
    let file_end = if mem_sz <= file_sz {
        vend
    } else {
        let boundary = vaddr.saturating_add(file_sz) & !(page - 1);
        if boundary <= vstart { return none; }
        boundary
    };
    SegmentSplit { file_end, file_pgoff: file_off & !(page - 1) }
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
        assert_eq!(s, SegmentSplit { file_end: 0x403000, file_pgoff: 0 });
    }

    /// Data: the page holding the file/memory boundary is part file, part
    /// zero, so it stops being a mapping of the file.
    #[test]
    fn a_segment_with_bss_gives_up_its_boundary_page() {
        let s = split(0x600000, 0x604000, 0x600000, 0x5000, 0x2abc, 0x3fff, PAGE, true);
        assert_eq!(s.file_end, 0x602000);
        assert_eq!(s.file_pgoff, 0x5000);
    }

    /// The boundary lands in the first page, so no whole page is the file.
    #[test]
    fn a_segment_whose_file_part_is_under_a_page_maps_nothing_from_the_file() {
        let s = split(0x600000, 0x603000, 0x600000, 0x5000, 0x800, 0x2000, PAGE, true);
        assert_eq!(s, SegmentSplit { file_end: 0x600000, file_pgoff: 0 });
    }

    /// A segment starting mid-page maps from the page the file offset sits in,
    /// so the bytes before it are the file's too.
    #[test]
    fn an_unaligned_segment_maps_from_the_page_its_file_offset_sits_in() {
        let s = split(0x400000, 0x402000, 0x400120, 0x120, 0x1e00, 0x1e00, PAGE, true);
        assert_eq!(s, SegmentSplit { file_end: 0x402000, file_pgoff: 0 });
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

    #[test]
    fn only_a_biased_dyn_image_the_loader_relocates_loses_its_file_backing() {
        assert!(relocs_precede_file_backing(true, ElfType::Dyn, 0x1000));
        assert!(!relocs_precede_file_backing(true, ElfType::Dyn, 0));
        assert!(!relocs_precede_file_backing(true, ElfType::Exec, 0x1000));
        assert!(!relocs_precede_file_backing(false, ElfType::Dyn, 0x1000));
    }
}
