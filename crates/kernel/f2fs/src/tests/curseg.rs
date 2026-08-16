//! The six open logs, and which one a write appends to.

use super::*;
use crate::opts::AllocMode;

#[test]
fn a_log_with_nothing_open_has_no_room() {
    let c = Curseg::empty();
    assert_eq!(c.segno, NULL_SEGNO);
    assert!(!c.has_room());
}

#[test]
fn a_log_has_room_until_its_segment_is_full() {
    let mut c = Curseg::empty();
    c.segno = 3;
    assert!(c.has_room());
    c.next_blkoff = BLKS_PER_SEG as u16 - 1;
    assert!(c.has_room());
    c.next_blkoff = BLKS_PER_SEG as u16;
    assert!(!c.has_room());
}

#[test]
fn the_next_address_is_the_segments_base_plus_the_offset() {
    let mut c = Curseg::empty();
    c.segno = 2;
    c.next_blkoff = 5;
    assert_eq!(c.next_addr(1000), 1000 + 2 * BLKS_PER_SEG + 5);
}

#[test]
fn a_summary_entry_round_trips_through_its_seven_bytes() {
    let mut c = Curseg::empty();
    let s = Summary { nid: 0x1234_5678, version: 9, ofs_in_node: 0x0BAD };
    c.set_summary(3, s);
    assert_eq!(c.summary(3), s);
    // The neighbours are untouched: an entry is seven bytes, not eight.
    assert_eq!(c.summary(2), Summary::default());
    assert_eq!(c.summary(4), Summary::default());
}

#[test]
fn every_summary_slot_of_a_segment_fits_in_the_block() {
    let last = summary_off(ENTRIES_IN_SUM - 1) + SUMMARY_SIZE;
    assert!(last <= SUM_JOURNAL_OFF);
    assert_eq!(ENTRIES_IN_SUM, BLKS_PER_SEG as usize);
}

#[test]
fn sealing_marks_the_block_as_node_or_data() {
    let mut c = Curseg::empty();
    c.seal(true);
    assert_eq!(c.sum[BLKSIZE - SUM_FOOTER_SIZE], crate::volume::curseg::SUM_TYPE_NODE);
    c.seal(false);
    assert_eq!(c.sum[BLKSIZE - SUM_FOOTER_SIZE], crate::volume::curseg::SUM_TYPE_DATA);
}

#[test]
fn sealing_covers_the_entries_and_the_journal() {
    let mut c = Curseg::empty();
    c.seal(false);
    let before = c.sum[BLKSIZE - SUM_FOOTER_SIZE + 1..].to_vec();
    c.set_summary(0, Summary { nid: 7, version: 0, ofs_in_node: 0 });
    c.seal(false);
    assert_ne!(c.sum[BLKSIZE - SUM_FOOTER_SIZE + 1..].to_vec(), before);
}

#[test]
fn six_logs_separate_every_kind() {
    use crate::volume::curseg::log_for;
    let all = [
        log_for(Kind::DirData, 6),
        log_for(Kind::FileData, 6),
        log_for(Kind::DirNode, 6),
        log_for(Kind::FileNode, 6),
        log_for(Kind::IndirectNode, 6),
    ];
    assert_eq!(all, [CURSEG_HOT_DATA, CURSEG_WARM_DATA, CURSEG_HOT_NODE, CURSEG_WARM_NODE,
                     CURSEG_COLD_NODE]);
}

#[test]
fn two_logs_separate_only_nodes_from_data() {
    use crate::volume::curseg::log_for;
    assert_eq!(log_for(Kind::DirData, 2), CURSEG_HOT_DATA);
    assert_eq!(log_for(Kind::FileData, 2), CURSEG_HOT_DATA);
    assert_eq!(log_for(Kind::DirNode, 2), CURSEG_HOT_NODE);
    assert_eq!(log_for(Kind::IndirectNode, 2), CURSEG_HOT_NODE);
}

#[test]
fn four_logs_split_hot_from_cold_on_both_sides() {
    use crate::volume::curseg::log_for;
    assert_eq!(log_for(Kind::DirData, 4), CURSEG_HOT_DATA);
    assert_eq!(log_for(Kind::FileData, 4), CURSEG_COLD_DATA);
    // The node side splits on temperature: only a file's own dnode is warm.
    assert_eq!(log_for(Kind::FileNode, 4), CURSEG_WARM_NODE);
    assert_eq!(log_for(Kind::DirNode, 4), CURSEG_COLD_NODE);
    assert_eq!(log_for(Kind::IndirectNode, 4), CURSEG_COLD_NODE);
}

#[test]
fn every_log_a_write_can_pick_is_one_the_checkpoint_records() {
    use crate::volume::curseg::log_for;
    for logs in [2u8, 4, 6] {
        for kind in [Kind::DirData, Kind::FileData, Kind::DirNode, Kind::FileNode,
                     Kind::IndirectNode] {
            assert!(log_for(kind, logs) < NR_CURSEG_PERSIST_TYPE);
        }
    }
}

#[test]
fn the_node_kinds_are_nodes_and_the_data_kinds_are_not() {
    assert!(Kind::DirNode.is_node());
    assert!(Kind::FileNode.is_node());
    assert!(Kind::IndirectNode.is_node());
    assert!(!Kind::DirData.is_node());
    assert!(!Kind::FileData.is_node());
}

#[test]
fn the_checkpoint_slot_splits_the_data_logs_from_the_node_ones() {
    use crate::volume::curseg::cp_slot;
    assert_eq!(cp_slot(CURSEG_HOT_DATA), (false, 0));
    assert_eq!(cp_slot(CURSEG_COLD_DATA), (false, 2));
    assert_eq!(cp_slot(CURSEG_HOT_NODE), (true, 0));
    assert_eq!(cp_slot(CURSEG_COLD_NODE), (true, 2));
}

#[test]
fn recycling_is_asked_for_by_the_mount() {
    use crate::volume::curseg::wants_recycle;
    assert!(wants_recycle(AllocMode::Reuse));
    assert!(!wants_recycle(AllocMode::Default));
}
