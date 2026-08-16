//! The free-slot run, the damaged-directory refusal, and the scan by name.

use super::*;

use syscall::errno::Errno;

use crate::dirent::{ATTR_ARCH, ATTR_EXT, ATTR_VOLUME, ENTRY_BYTES};
use crate::namei::{find_free_run, find_short, FreeRun};
use crate::namei::limits::FAT_MAX_DIR_SIZE;

const FILE: [u8; 11] = *b"HELLO   TXT";
const OTHER: [u8; 11] = *b"OTHER   TXT";

/// An empty directory hands back its first slot.
#[test]
fn an_empty_directory_starts_at_its_first_slot() {
    let bytes = blank(8);
    assert_eq!(find_free_run(&bytes, 1).unwrap(), FreeRun::Found { at: 0 });
}

/// A released slot is reusable. It is the only free slot a directory
/// accumulates in practice, so a search that skipped it would grow a
/// directory forever.
#[test]
fn a_released_slot_is_reused() {
    let mut bytes = blank(8);
    for i in 0..4 { used(&mut bytes, i, &FILE, ATTR_ARCH); }
    deleted(&mut bytes, 2);
    assert_eq!(find_free_run(&bytes, 1).unwrap(),
               FreeRun::Found { at: (2 * ENTRY_BYTES) as u64 });
}

/// The run must be CONTIGUOUS: a used entry between two free ones ends the
/// run there rather than counting both. A name whose slots were split across
/// it would be read as two different, broken names.
#[test]
fn a_used_entry_restarts_the_run() {
    let mut bytes = blank(8);
    for i in 0..6 { used(&mut bytes, i, &FILE, ATTR_ARCH); }
    deleted(&mut bytes, 1);
    deleted(&mut bytes, 3);
    deleted(&mut bytes, 4);
    // Slot 1 is free but alone; the pair at 3 and 4 is the first run of two.
    assert_eq!(find_free_run(&bytes, 2).unwrap(),
               FreeRun::Found { at: (3 * ENTRY_BYTES) as u64 });
}

/// A run that reaches the end of the directory reports what it has, and where
/// it started — the growth continues the SAME run, so the group begins at the
/// free slot already there rather than in the new cluster.
#[test]
fn a_run_running_off_the_end_reports_the_tail_it_found() {
    let mut bytes = blank(4);
    for i in 0..3 { used(&mut bytes, i, &FILE, ATTR_ARCH); }
    assert_eq!(find_free_run(&bytes, 3).unwrap(),
               FreeRun::Grow { at: (3 * ENTRY_BYTES) as u64, have: 1 });
}

/// A full directory with no tail run at all still reports where the growth
/// begins.
#[test]
fn a_full_directory_grows_from_its_end() {
    let mut bytes = blank(4);
    for i in 0..4 { used(&mut bytes, i, &FILE, ATTR_ARCH); }
    assert_eq!(find_free_run(&bytes, 1).unwrap(),
               FreeRun::Grow { at: (4 * ENTRY_BYTES) as u64, have: 0 });
}

/// A used record AFTER the end-of-directory marker is a directory that
/// disagrees with itself. Filling free slots past that point publishes a name
/// every scan stops before reaching, so it is refused instead.
#[test]
fn a_used_entry_after_the_end_marker_is_refused() {
    let mut bytes = blank(8);
    used(&mut bytes, 0, &FILE, ATTR_ARCH);
    // Record 1 is the marker; record 2 is live and must not be there.
    used(&mut bytes, 2, &OTHER, ATTR_ARCH);
    // A run of one is satisfied by the marker itself and never reaches the
    // offending record; a longer one walks into it.
    assert_eq!(find_free_run(&bytes, 1).unwrap(), FreeRun::Found { at: ENTRY_BYTES as u64 });
    assert_eq!(find_free_run(&bytes, 2), Err(Errno::Eio));
}

/// A directory past the ceiling is full whatever the volume has left.
#[test]
fn the_directory_ceiling_is_enospc_not_a_larger_directory() {
    let entries = (FAT_MAX_DIR_SIZE / ENTRY_BYTES as u64) as usize;
    let mut bytes = blank(entries + 1);
    for i in 0..entries + 1 { used(&mut bytes, i, &FILE, ATTR_ARCH); }
    assert_eq!(find_free_run(&bytes, 1), Err(Errno::Enospc));
}

/// The scan finds a live entry by its eleven bytes.
#[test]
fn the_scan_finds_a_live_entry() {
    let mut bytes = blank(8);
    used(&mut bytes, 0, &OTHER, ATTR_ARCH);
    used(&mut bytes, 1, &FILE, ATTR_ARCH);
    assert_eq!(find_short(&bytes, &FILE), Some(ENTRY_BYTES as u64));
}

/// Three kinds of record are not a name and must never match one: a released
/// slot, a long-name slot, and the volume label. Matching any of them makes a
/// create refuse a name that is free, or an alias collide with a label.
#[test]
fn released_slots_long_slots_and_the_label_are_not_names() {
    let mut bytes = blank(8);
    used(&mut bytes, 0, &FILE, ATTR_ARCH);
    deleted(&mut bytes, 0);
    used(&mut bytes, 1, &FILE, ATTR_EXT);
    used(&mut bytes, 2, &FILE, ATTR_VOLUME);
    assert_eq!(find_short(&bytes, &FILE), None);
    // ...and the same bytes as a real file DO match.
    used(&mut bytes, 3, &FILE, ATTR_ARCH);
    assert_eq!(find_short(&bytes, &FILE), Some((3 * ENTRY_BYTES) as u64));
}

/// The scan stops at the end of the directory rather than reading past it.
#[test]
fn the_scan_stops_at_the_end_marker() {
    let mut bytes = blank(8);
    used(&mut bytes, 4, &FILE, ATTR_ARCH);
    assert_eq!(find_short(&bytes, &FILE), None);
}
