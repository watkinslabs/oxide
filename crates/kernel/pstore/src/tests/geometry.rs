use super::*;
use crate::limits::{DEFAULT_CONSOLE_SIZE, DEFAULT_MEM_SIZE, DEFAULT_RECORD_SIZE};

#[test]
fn the_default_region_carves_into_dump_zones_plus_one_console_zone() {
    let l = carve(DEFAULT_MEM_SIZE, DEFAULT_RECORD_SIZE, DEFAULT_CONSOLE_SIZE);
    assert!(!l.dump.is_empty());
    let c = l.console.expect("a console zone");
    assert_eq!(c.len, DEFAULT_CONSOLE_SIZE);
    assert_eq!(c.off + c.len, DEFAULT_MEM_SIZE);
}

#[test]
fn zones_are_consecutive_and_do_not_overlap_the_console() {
    let l = carve(64 * 1024, 8 * 1024, 4096);
    let mut expect = 0usize;
    for z in &l.dump {
        assert_eq!(z.off, expect);
        expect += z.len;
    }
    let c = l.console.unwrap();
    assert!(expect <= c.off, "dump area {expect} runs into console at {}", c.off);
}

#[test]
fn the_dump_area_is_used_whole() {
    // 60 KiB of dump area, 8 KiB requested per record: 7 zones of 8 KiB
    // would leave 4 KiB stranded, so the zones grow to consume it. What is
    // left over is only what the even-size rounding drops — under one byte
    // per zone, never a whole zone's worth.
    let l = carve(64 * 1024, 8 * 1024, 4096);
    assert_eq!(l.dump.len(), 7);
    let used: usize = l.dump.iter().map(|z| z.len).sum();
    assert!(used <= 60 * 1024);
    assert!(60 * 1024 - used < 2 * l.dump.len(), "stranded {} bytes", 60 * 1024 - used);
}

#[test]
fn zone_sizes_are_even() {
    let l = carve(1001, 100, 0);
    for z in &l.dump { assert_eq!(z.len % 2, 0, "odd zone {z:?}"); }
}

#[test]
fn a_region_too_small_for_one_record_gets_no_dump_zones() {
    let l = carve(4096, 8192, 0);
    assert!(l.dump.is_empty());
    assert!(l.console.is_none());
}

#[test]
fn a_zero_console_size_leaves_the_whole_region_to_dumps() {
    let l = carve(16 * 1024, 4096, 0);
    assert!(l.console.is_none());
    assert_eq!(l.dump.len(), 4);
    assert_eq!(l.dump.iter().map(|z| z.len).sum::<usize>(), 16 * 1024);
}

#[test]
fn an_empty_region_carves_into_nothing() {
    assert_eq!(carve(0, 4096, 4096), Layout::default());
}

fn ranges() -> [UsableRange; 3] {
    [
        UsableRange { base: 0x0010_0000, len: 0x0010_0000 },
        UsableRange { base: 0x0100_0000, len: 0x4000_0000 },
        UsableRange { base: 0x8000_0000, len: 0x0020_0000 },
    ]
}

#[test]
fn the_base_is_the_top_of_the_largest_range() {
    let want = 0x4_0000u64;
    let base = choose_base(&ranges(), want).unwrap();
    assert_eq!(base, 0x0100_0000 + 0x4000_0000 - want);
    assert_eq!(base % REGION_ALIGN, 0);
}

#[test]
fn the_same_map_always_yields_the_same_base() {
    // The whole mechanism rests on this: a different answer after a reboot
    // means the previous boot's records are unreachable.
    let want = 0x4_0000u64;
    let a = choose_base(&ranges(), want);
    let mut shuffled = ranges();
    shuffled.reverse();
    assert_eq!(a, choose_base(&shuffled, want));
}

#[test]
fn a_range_the_reservation_would_dominate_is_not_used() {
    let small = [UsableRange { base: 0x1000, len: 0x5000 }];
    assert_eq!(choose_base(&small, 0x4000), None);
}

#[test]
fn no_ranges_and_no_size_yield_no_base() {
    assert_eq!(choose_base(&[], 4096), None);
    assert_eq!(choose_base(&ranges(), 0), None);
}

#[test]
fn a_requested_size_is_rounded_up_to_a_page_and_floored() {
    assert_eq!(round_region_size(1), MIN_MEM_SIZE);
    assert_eq!(round_region_size(4097), 8192);
    assert_eq!(round_region_size(DEFAULT_MEM_SIZE), DEFAULT_MEM_SIZE);
}
