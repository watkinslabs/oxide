use elf::{LoadSegment, PFlags};

use super::*;

fn seg(vaddr: u64, mem_sz: u64, align: u64) -> LoadSegment {
    LoadSegment {
        vaddr, mem_sz, align, file_off: 0, file_sz: mem_sz, flags: PFlags::R,
    }
}

/// `fs/binfmt_elf.c:463-478`: lowest PT_LOAD page start to highest PT_LOAD end.
/// Reserving less than this splits an image across two holes; reserving from
/// the raw `p_vaddr` instead of its page start loses the head fragment.
#[test]
fn total_mapping_size_spans_page_start_to_last_byte() {
    let loads = [seg(0x1000, 0x2000, 0x1000), seg(0x5000, 0x800, 0x1000)];
    assert_eq!(total_mapping_size(&loads), 0x5800 - 0x1000);
    // Unaligned first vaddr: the span starts at its PAGE START.
    let loads = [seg(0x1240, 0x1000, 0x1000)];
    assert_eq!(total_mapping_size(&loads), 0x2240 - 0x1000);
    assert_eq!(min_vaddr(&loads), 0x1000);
    // Out-of-order phdrs must not fool the scan.
    let loads = [seg(0x9000, 0x1000, 0x1000), seg(0x2000, 0x1000, 0x1000)];
    assert_eq!(total_mapping_size(&loads), 0xa000 - 0x2000);
    assert_eq!(min_vaddr(&loads), 0x2000);
    assert_eq!(total_mapping_size(&[]), 0);
}

/// `fs/binfmt_elf.c:491-509`: coarsest power-of-two `p_align`, page-aligned;
/// non-power-of-two alignments are skipped rather than adopted.
#[test]
fn maximum_alignment_takes_the_coarsest_power_of_two() {
    assert_eq!(maximum_alignment(&[seg(0, 0x1000, 0x1000), seg(0x200000, 0x1000, 0x200000)]),
        0x200000);
    assert_eq!(maximum_alignment(&[seg(0, 0x1000, 0x1000)]), 0x1000);
    // A bogus alignment is ignored, not promoted.
    assert_eq!(maximum_alignment(&[seg(0, 0x1000, 0x1000), seg(0x3000, 0x1000, 3)]), 0x1000);
    // Sub-page alignments round up to a page (`ELF_PAGEALIGN`).
    assert_eq!(maximum_alignment(&[seg(0, 0x1000, 2)]), crate::PAGE);
    assert_eq!(maximum_alignment(&[]), 0);
}
