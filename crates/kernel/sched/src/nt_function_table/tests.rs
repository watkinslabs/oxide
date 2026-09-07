//! Dynamic unwind registration contracts: the entry layout, which
//! registration a program counter reaches, the tag a callback registration
//! must carry, the range a static one covers, removal by table, and the
//! ordered entry search.

use super::*;

fn table_entry(base: u64, end: u64, table: u64, count: u32) -> Entry { static_entry(table, count, base, end) }

#[test]
fn one_unwind_entry_is_three_image_relative_addresses() {
    assert_eq!(ENTRY_BYTES, 12);
    assert_eq!(BEGIN_ADDRESS_OFFSET, 0);
    assert_eq!(END_ADDRESS_OFFSET, 4);
    assert_eq!(UNWIND_DATA_OFFSET, 8);
    assert_eq!(CHAINED_ENTRY, 1);
}

#[test]
fn a_lookup_reaches_the_registration_whose_range_holds_the_address() {
    let entries = alloc::vec![table_entry(0x1000, 0x2000, 0xaa00, 4), table_entry(0x3000, 0x4000, 0xbb00, 7)];
    assert_eq!(lookup(&entries, 0x1000), Some(Found::Table { base: 0x1000, table: 0xaa00, count: 4 }));
    assert_eq!(lookup(&entries, 0x1fff), Some(Found::Table { base: 0x1000, table: 0xaa00, count: 4 }));
    assert_eq!(lookup(&entries, 0x3500), Some(Found::Table { base: 0x3000, table: 0xbb00, count: 7 }));
    // The end address is one past the range, and gaps belong to nobody.
    assert_eq!(lookup(&entries, 0x2000), None);
    assert_eq!(lookup(&entries, 0x0fff), None);
    assert_eq!(lookup(&entries, 0x2fff), None);
    assert_eq!(lookup(&[], 0x1000), None);
}

#[test]
fn a_callback_registration_answers_with_its_callback_not_its_table() {
    let entry = callback_entry(0x5003, 0x8000, 0x100, 0xcb00, 0xc0de).unwrap();
    assert_eq!(entry.end, 0x8100);
    assert_eq!(entry.count, 0);
    let entries = alloc::vec![entry];
    assert_eq!(lookup(&entries, 0x8050), Some(Found::Callback { base: 0x8000, callback: 0xcb00, context: 0xc0de }));
    assert_eq!(CALLBACK_ENTRY_COUNT, 1);
}

#[test]
fn a_callback_registration_without_both_tag_bits_is_refused() {
    assert_eq!(CALLBACK_TABLE_TAG, 3);
    assert!(callback_entry(0x5000, 0x8000, 0x100, 0xcb00, 0).is_none());
    assert!(callback_entry(0x5001, 0x8000, 0x100, 0xcb00, 0).is_none());
    assert!(callback_entry(0x5002, 0x8000, 0x100, 0xcb00, 0).is_none());
    assert!(callback_entry(0x5003, 0x8000, 0x100, 0xcb00, 0).is_some());
}

#[test]
fn a_static_registration_ends_where_its_last_entry_ends() {
    assert_eq!(static_range_end(0x10000, 3, Some(0x840)), 0x10840);
    // No entries means the registration covers no code at all.
    assert_eq!(static_range_end(0x10000, 0, Some(0x840)), 0x10000);
    assert_eq!(static_range_end(0x10000, 0, None), 0x10000);
    let entry = static_entry(0xaa00, 3, 0x10000, static_range_end(0x10000, 3, Some(0x840)));
    assert_eq!(entry.callback, 0);
    assert_eq!(entry.max_count, 0);
    assert_eq!(lookup(&[entry], 0x1083f), Some(Found::Table { base: 0x10000, table: 0xaa00, count: 3 }));
    assert_eq!(lookup(&[entry], 0x10840), None);
}

#[test]
fn removal_names_the_table_and_reports_whether_one_left() {
    let mut entries = alloc::vec![table_entry(0x1000, 0x2000, 0xaa00, 1), table_entry(0x3000, 0x4000, 0xbb00, 1)];
    assert!(!remove_by_table(&mut entries, 0xcc00));
    assert_eq!(entries.len(), 2);
    assert!(remove_by_table(&mut entries, 0xaa00));
    assert_eq!(entries.len(), 1);
    assert_eq!(lookup(&entries, 0x1500), None);
    assert!(remove_by_table(&mut entries, 0xbb00));
    assert!(entries.is_empty());
    assert!(!remove_by_table(&mut entries, 0xbb00));
}

#[test]
fn the_ordered_search_finds_the_covering_entry_and_only_that_one() {
    let ranges = [(0x10u32, 0x20u32), (0x20, 0x40), (0x60, 0x80)];
    let bounds = |index: u32| ranges.get(index as usize).copied();
    assert_eq!(find_entry(3, 0x10, bounds), Some(0));
    assert_eq!(find_entry(3, 0x1f, bounds), Some(0));
    assert_eq!(find_entry(3, 0x20, bounds), Some(1));
    assert_eq!(find_entry(3, 0x3f, bounds), Some(1));
    assert_eq!(find_entry(3, 0x60, bounds), Some(2));
    assert_eq!(find_entry(3, 0x7f, bounds), Some(2));
    // Before the first, inside the gap, and past the last all miss.
    assert_eq!(find_entry(3, 0x0f, bounds), None);
    assert_eq!(find_entry(3, 0x40, bounds), None);
    assert_eq!(find_entry(3, 0x5f, bounds), None);
    assert_eq!(find_entry(3, 0x80, bounds), None);
    assert_eq!(find_entry(0, 0x10, bounds), None);
}

#[test]
fn the_ordered_search_stops_when_an_entry_cannot_be_read() {
    assert_eq!(find_entry(3, 0x10, |_| None), None);
}
