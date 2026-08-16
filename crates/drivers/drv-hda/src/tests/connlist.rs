// Provenance: the connection-list response format — packed slots, the two
// slot widths, and the range marker that stands for a run of node ids.

use super::*;

#[test]
fn short_and_long_layouts_decode_from_the_length_parameter() {
    let short = layout(4);
    assert_eq!(short, Layout { shift: 8, per_word: 4, mask: 0x7f, len: 4 });
    let long = layout(CLIST_LONG | 3);
    assert_eq!(long, Layout { shift: 16, per_word: 2, mask: 0x7fff, len: 3 });
}

#[test]
fn packed_short_slots_expand_in_order() {
    let l = layout(4);
    // Four 8-bit slots in one word, lowest slot first.
    let words = [0x14_13_12_11u32];
    assert_eq!(expand(&l, &words), alloc::vec![0x11, 0x12, 0x13, 0x14]);
}

#[test]
fn a_range_marker_expands_the_span_from_the_previous_entry() {
    let l = layout(2);
    // Entry 0x02, then 0x85 = "up to 0x05" -> 0x03,0x04,0x05.
    let words = [0x0000_8502u32];
    assert_eq!(expand(&l, &words), alloc::vec![0x02, 0x03, 0x04, 0x05]);
}

#[test]
fn a_malformed_range_is_skipped_rather_than_fabricating_nodes() {
    let l = layout(2);
    // A range marker with no predecessor.
    assert_eq!(expand(&l, &[0x0000_0085u32]), alloc::vec![]);
    // A range running backwards from its predecessor.
    assert_eq!(expand(&l, &[0x0000_8205u32]), alloc::vec![0x05]);
}

#[test]
fn a_second_null_entry_ends_the_list() {
    let l = layout(4);
    // 0x11, null, 0x13, null -> the second null stops the walk.
    assert_eq!(expand(&l, &[0x00_13_00_11u32]), alloc::vec![0x11, 0x13]);
    assert_eq!(expand(&l, &[0x00_00_00_11u32]), alloc::vec![0x11]);
}

#[test]
fn long_slots_carry_a_fifteen_bit_node_id() {
    let l = layout(CLIST_LONG | 2);
    let words = [0x0034_0012u32];
    assert_eq!(expand(&l, &words), alloc::vec![0x12, 0x34]);
}

#[test]
fn word_count_matches_the_slots_per_response() {
    assert_eq!(word_count(&layout(0)), 0);
    assert_eq!(word_count(&layout(1)), 1);
    assert_eq!(word_count(&layout(4)), 1);
    assert_eq!(word_count(&layout(5)), 2);
    assert_eq!(word_count(&layout(CLIST_LONG | 3)), 2);
}
