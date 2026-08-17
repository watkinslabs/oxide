//! When a log recycles a segment instead of opening a fresh one.

use crate::place::ssr::{self, Choice, Need};

/// A volume with room: nothing is pressing, so nothing recycles.
fn roomy() -> Need {
    Need { free_sections: 100, min_ssr_sections: 3, reserved_sections: 2, ..Need::default() }
}

/// Recycling answers pressure, and there is none.
#[test]
fn a_volume_with_room_appends() {
    assert!(!ssr::need_ssr(&roomy()));
}

/// The comparison is at-or-below, not below: a volume with exactly the floor's
/// worth of free sections is already at the point the floor exists to hold.
#[test]
fn the_floor_is_inclusive() {
    let n = Need { free_sections: 5, ..roomy() };
    assert!(ssr::need_ssr(&n));
    assert!(!ssr::need_ssr(&Need { free_sections: 6, ..n }));
}

/// Dirty metadata counts against the free sections, and dentry blocks count
/// twice — the block is written and the node naming it is written after.
#[test]
fn dirty_metadata_raises_the_bar() {
    let n = Need { free_sections: 10, min_ssr_sections: 1, reserved_sections: 1, ..roomy() };
    assert!(!ssr::need_ssr(&n));
    assert!(ssr::need_ssr(&Need { node_secs: 8, ..n }));
    assert!(!ssr::need_ssr(&Need { dent_secs: 3, ..n }));
    assert!(ssr::need_ssr(&Need { dent_secs: 4, ..n }));
    assert!(ssr::need_ssr(&Need { imeta_secs: 8, ..n }));
}

/// A mount that never overwrites in place never recycles either, whatever the
/// pressure — including the two states that otherwise force it.
#[test]
fn an_append_only_mount_never_recycles() {
    let n = Need { lfs: true, free_sections: 0, gc_urgent_high: true, cp_disabled: true,
                   ..roomy() };
    assert!(!ssr::need_ssr(&n));
}

/// An urgent cleaner needs every section it can be handed, and a mount with
/// checkpointing off gets no space back until it is on again. Both recycle on a
/// volume with room to spare.
#[test]
fn urgency_and_suspended_checkpoints_recycle_regardless() {
    assert!(ssr::need_ssr(&Need { gc_urgent_high: true, ..roomy() }));
    assert!(ssr::need_ssr(&Need { cp_disabled: true, ..roomy() }));
}

/// Pages become sections by rounding up: one page short of a section still
/// needs the whole section to land in.
#[test]
fn pages_round_up_into_sections() {
    assert_eq!(ssr::secs_for_pages(0, 512), 0);
    assert_eq!(ssr::secs_for_pages(1, 512), 1);
    assert_eq!(ssr::secs_for_pages(512, 512), 1);
    assert_eq!(ssr::secs_for_pages(513, 512), 2);
    // A volume whose section size is unknown counts one section per page rather
    // than dividing by zero.
    assert_eq!(ssr::secs_for_pages(3, 0), 3);
}

/// A file's own node blocks go into whole appended segments on a volume whose
/// checkpoints cannot be verified: their ORDER is what a replay reads, and a
/// recycled segment has no order to read.
#[test]
fn a_file_node_log_appends_when_the_checkpoint_carries_no_checksum() {
    let c = Choice { crc_recovery: false, warm_node_log: true, ..Choice::default() };
    assert!(ssr::need_new_seg(&c, || true));
    // With a verifiable checkpoint the log is like any other.
    assert!(!ssr::need_new_seg(&Choice { crc_recovery: true, ..c }, || true));
}

/// The segment straight after the one being closed is free and in the same
/// section: appending costs nothing, so there is no reason to hunt for gaps.
#[test]
fn a_free_next_segment_is_appended_to() {
    let c = Choice { crc_recovery: true, appending: true, next_seg_free: true,
                     ..Choice::default() };
    assert!(ssr::need_new_seg(&c, || true));
    // Not for a log that was already recycling — it is not appending anywhere.
    assert!(!ssr::need_new_seg(&Choice { appending: false, ..c }, || true));
    // And not while checkpointing is off, where the space that segment is in
    // does not come back either way.
    assert!(!ssr::need_new_seg(&Choice { cp_disabled: true, ..c }, || true));
}

/// With none of the three shortcuts taken, the pressure decides — and it is
/// asked exactly once.
#[test]
fn otherwise_the_pressure_decides() {
    let c = Choice { crc_recovery: true, ..Choice::default() };
    let mut asked = 0u32;
    assert!(!ssr::need_new_seg(&c, || { asked += 1; true }));
    assert_eq!(asked, 1);
    assert!(ssr::need_new_seg(&c, || false));
}

/// Where the search for a fresh segment starts: from the low end for the logs
/// whose blocks are rewritten soonest and for a mount that asked to reuse
/// freed space, and from the segment being closed otherwise.
#[test]
fn the_search_starts_where_the_log_and_the_mount_ask() {
    assert_eq!(ssr::next_segno_hint(true, false, 77), 0);
    assert_eq!(ssr::next_segno_hint(false, true, 77), 0);
    assert_eq!(ssr::next_segno_hint(false, false, 77), 77);
}
