//! The pump profile must name the ordinal that dominates an interval by the
//! time it spends, and must report nothing from an interval already reported.

use crate::win32_window::pump_profile::{PumpProfile, SLOTS};

#[test]
fn the_costliest_ordinal_is_reported_first_with_its_time() {
    let profile = PumpProfile::new();
    for _ in 0..7 { profile.record(0x1234, 1_000); }
    profile.record(0x99, 100_000);
    let interval = profile.take();
    assert_eq!(interval.total, 8);
    assert_eq!(interval.other, 0);
    assert_eq!(interval.total_ns, 107_000);
    assert_eq!(interval.top[0].ordinal, 0x99);
    assert_eq!(interval.top[0].max_ns, 100_000);
    assert_eq!(interval.top[1].ordinal, 0x1234);
    assert_eq!(interval.top[1].count, 7);
    assert_eq!(interval.top[1].total_ns, 7_000);
}

#[test]
fn ordinals_past_the_slot_table_are_counted_as_other_and_keep_their_time() {
    let profile = PumpProfile::new();
    for ordinal in 1..=(SLOTS as u64) { profile.record(ordinal, 10); }
    profile.record(0xdead, 500);
    profile.record(0xbeef, 500);
    let interval = profile.take();
    assert_eq!(interval.total, SLOTS as u64 + 2);
    assert_eq!(interval.other, 2);
    assert_eq!(interval.total_ns, SLOTS as u64 * 10 + 1_000);
}

#[test]
fn a_reported_interval_leaves_the_next_one_empty() {
    let profile = PumpProfile::new();
    for _ in 0..5 { profile.record(0x42, 7); }
    let _ = profile.take();
    let interval = profile.take();
    assert_eq!(interval.total, 0);
    assert_eq!(interval.total_ns, 0);
    assert_eq!(interval.top[0], Default::default());
}

#[test]
fn a_second_interval_reuses_the_freed_slots_for_new_ordinals() {
    let profile = PumpProfile::new();
    for ordinal in 1..=(SLOTS as u64) { profile.record(ordinal, 1); }
    let _ = profile.take();
    for _ in 0..4 { profile.record(0x777, 3); }
    let interval = profile.take();
    assert_eq!(interval.other, 0);
    assert_eq!(interval.top[0].ordinal, 0x777);
    assert_eq!(interval.top[0].count, 4);
}
