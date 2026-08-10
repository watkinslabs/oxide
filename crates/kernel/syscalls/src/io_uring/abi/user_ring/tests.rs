use super::*;
use super::super::layout::*;
use super::super::uapi::*;

const PAGE: u64 = 4096;

fn req(flags: u32) -> Params {
    let mut p = Params::default();
    p.flags = flags;
    p
}

#[test]
fn a_caller_supplied_ring_is_not_mappable_from_its_descriptor() {
    assert!(caller_supplied(IORING_SETUP_NO_MMAP));
    assert!(!mappable(IORING_SETUP_NO_MMAP));
    assert!(mappable(0));
    assert!(registered_only(IORING_SETUP_REGISTERED_FD_ONLY));
    assert!(!registered_only(0));
}

#[test]
fn a_region_address_must_be_a_real_page_aligned_range() {
    assert_eq!(admit_addr(0, PAGE, PAGE), Err(Errno::Efault), "null names nothing");
    assert_eq!(admit_addr(PAGE + 1, PAGE, PAGE), Err(Errno::Einval), "unaligned");
    assert_eq!(admit_addr(PAGE, 0, PAGE), Err(Errno::Einval), "an empty region");
    assert_eq!(admit_addr(u64::MAX & !(PAGE - 1), PAGE * 2, PAGE), Err(Errno::Efault),
               "a range that wraps");
    assert_eq!(admit_addr(PAGE * 16, PAGE * 4, PAGE), Ok(()));
}

#[test]
fn the_span_rule_is_what_it_says() {
    assert!(spans_one_page(0, 16, PAGE));
    assert!(spans_one_page(PAGE - 16, 16, PAGE), "ending exactly at the boundary is inside");
    assert!(!spans_one_page(PAGE - 16, 17, PAGE));
    assert!(!spans_one_page(0, 0, PAGE), "a zero-length object is not an object");
}

/// The invariant every direct access into a caller-supplied region rests on,
/// checked against the real geometry rather than asserted: walk every object
/// of every admitted ring shape and confirm none straddles a page.
#[test]
fn no_ring_object_ever_straddles_a_page() {
    let shapes = [
        0,
        IORING_SETUP_CQE32,
        IORING_SETUP_SQE128,
        IORING_SETUP_CQE_MIXED | IORING_SETUP_SQE_MIXED,
        IORING_SETUP_NO_SQARRAY,
        IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | IORING_SETUP_NO_SQARRAY,
    ];
    for flags in shapes {
        for entries in [1u32, 2, 8, 64, 512] {
            let mut p = req(flags);
            let Ok(g) = prepare(&mut p, entries) else { continue };

            // Header words: each is four bytes at a fixed offset.
            for off in [RING_SQ_HEAD, RING_SQ_TAIL, RING_CQ_HEAD, RING_CQ_TAIL,
                        RING_SQ_RING_MASK, RING_CQ_RING_MASK, RING_SQ_RING_ENTRIES,
                        RING_CQ_RING_ENTRIES, RING_SQ_DROPPED, RING_SQ_FLAGS,
                        RING_CQ_FLAGS, RING_CQ_OVERFLOW] {
                assert!(spans_one_page(off as u64, 4, PAGE),
                        "header word {off:#x}, flags {flags:#x}");
            }

            // Completions: `cqe_size` bytes each, and a mixed ring's wide
            // completion is two adjacent slots, so check the pair too.
            let cs = cqe_size(g.flags) as u64;
            let wide = if g.flags & IORING_SETUP_CQE_MIXED != 0 { 2 } else { 1 };
            for i in 0..g.cq_entries as u64 {
                let off = RING_CQES as u64 + i * cs;
                assert!(spans_one_page(off, cs, PAGE),
                        "cqe {i}, flags {flags:#x}, entries {entries}");
                // A wide completion is only ever placed where both slots fit,
                // which on a page-dividing stride means the pair fits too.
                if wide == 2 && i + 1 < g.cq_entries as u64 {
                    assert!(spans_one_page(off, cs * 2, PAGE) || (off & (PAGE - 1)) + cs == PAGE,
                            "wide cqe pair at {i}, flags {flags:#x}");
                }
            }

            // Submission index array: one four-byte word per entry.
            if g.sq_array_off != NO_SQ_ARRAY {
                for i in 0..g.sq_entries as u64 {
                    let off = g.sq_array_off as u64 + i * 4;
                    assert!(spans_one_page(off, 4, PAGE),
                            "sq index {i}, flags {flags:#x}");
                }
            }

            // Submission entries, in their own region starting at offset zero.
            let ss = sqe_size(g.flags) as u64;
            for i in 0..g.sq_entries as u64 {
                assert!(spans_one_page(i * ss, ss, PAGE),
                        "sqe {i}, flags {flags:#x}, entries {entries}");
            }
        }
    }
    // And the alignment the whole argument rests on: the completion array
    // starts on a cacheline that divides a page.
    assert_eq!(PAGE % SMP_CACHE_BYTES as u64, 0);
    assert_eq!(RING_CQES as u64 % 32, 0);
}
