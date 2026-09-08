use super::*;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

#[test]
fn the_record_is_aligned_and_the_entry_pointer_is_one_word_below_it() {
    let top = 0x7fff_0000_0000u64;
    let placed = place(top - (8 << 20), top).expect("an eight-megabyte stack carries the record");
    assert_eq!(placed.context % RECORD_ALIGN, 0);
    assert_eq!(placed.context, ((top - START_STACK_GAP) & !(RECORD_ALIGN - 1)) - CONTEXT_BYTES as u64);
    assert_eq!(placed.stack_pointer, placed.context - START_RETURN_SLOT);
    assert_eq!(placed.context_bytes(), CONTEXT_BYTES as u64);
}

#[test]
fn the_whole_scrubbed_extent_lies_inside_the_stack_mapping() {
    let top = 0x7fff_0000_0000u64;
    let base = top - (1 << 20);
    let placed = place(base, top).expect("a one-megabyte stack carries the record");
    // The runtime zeroes from the floor up to the page the record starts in.
    assert_eq!(placed.scrub_floor, (placed.context & !(PAGE - 1)) - START_SCRUB_BYTES);
    assert!(placed.scrub_floor >= base, "the scrub must not run below the mapping");
    assert!(placed.context + CONTEXT_BYTES as u64 <= top, "the record must not run past the base");
    // The entry stack pointer is above the scrub floor: the scrub lowers the
    // stack pointer itself before it writes, and never crosses the record.
    assert!(placed.stack_pointer > placed.scrub_floor);
}

#[test]
fn a_stack_shorter_than_the_scrubbed_extent_is_refused() {
    let top = 0x7fff_0000_0000u64;
    assert_eq!(place(top - 0x1000, top), None);
    assert_eq!(place(top - START_SCRUB_BYTES, top), None);
    assert_eq!(place(top, top), None);
    assert_eq!(place(top + 1, top), None);
}

#[test]
fn the_documented_minimum_is_admitted_at_every_stack_alignment() {
    // The record plus its gap never spans more than two pages, so the floor
    // never sits more than two pages plus the scrub below the stack base.
    for offset in [0u64, 8, 0x28, 0x501, 0xfff] {
        let top = 0x7fff_0000_0000u64 - offset;
        assert!(place(top - MIN_START_STACK_BYTES, top).is_some(),
            "the documented minimum must be admitted at every alignment");
    }
    // A stack only as large as the scrubbed extent cannot carry the record.
    let top = 0x7fff_0000_0000u64;
    assert!(place(top - START_SCRUB_BYTES, top).is_none());
    assert!(place(top - (START_SCRUB_BYTES + PAGE - 1), top).is_none());
}

#[test]
fn placement_never_wraps_on_a_low_stack() {
    assert_eq!(place(0, 0x1000), None);
    assert_eq!(place(0, START_STACK_GAP), None);
}
