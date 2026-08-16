use super::*;
use crate::uapi::SPARSE_LCN;

/// The volume every test decodes against, wide enough for its runs.
const CLUSTERS: u64 = 1 << 20;

#[test]
fn one_run_decodes_to_its_length_and_cluster() {
    // Header 0x21: one length byte, two offset bytes.
    let packed = [0x21, 0x18, 0x34, 0x56, 0x00];
    let runs = unpack(&packed, 0, 0x17, CLUSTERS).unwrap();
    assert_eq!(runs.runs, alloc::vec![Run { vcn: 0, lcn: 0x5634, len: 0x18 }]);
}

#[test]
fn a_second_runs_offset_is_a_delta_from_the_first() {
    // The second run's cluster is 0x100 PAST the first, not 0x100.
    let packed = [0x11, 0x04, 0x40, 0x11, 0x04, 0x10, 0x00];
    let runs = unpack(&packed, 0, 7, CLUSTERS).unwrap();
    assert_eq!(runs.runs[0].lcn, 0x40);
    assert_eq!(runs.runs[1].lcn, 0x50);
}

#[test]
fn a_negative_delta_moves_backwards() {
    // 0xF0 as a signed byte is -16.
    let packed = [0x11, 0x04, 0x40, 0x11, 0x04, 0xF0, 0x00];
    let runs = unpack(&packed, 0, 7, CLUSTERS).unwrap();
    assert_eq!(runs.runs[0].lcn, 0x40);
    assert_eq!(runs.runs[1].lcn, 0x30);
}

#[test]
fn a_run_with_no_offset_is_a_hole() {
    let packed = [0x01, 0x08, 0x11, 0x04, 0x40, 0x00];
    let runs = unpack(&packed, 0, 11, CLUSTERS).unwrap();
    assert!(runs.runs[0].is_hole());
    assert_eq!(runs.runs[0].len, 8);
    assert_eq!(runs.runs[1].lcn, 0x40);
    // A hole does not move the delta base: the run after it is relative to
    // the last REAL cluster.
    assert_eq!(runs.lookup(0), Some(SPARSE_LCN));
    assert_eq!(runs.lookup(8), Some(0x40));
}

#[test]
fn a_lookup_finds_the_cluster_inside_a_run() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 100, len: 4 });
    runs.push(Run { vcn: 4, lcn: 200, len: 4 });
    assert_eq!(runs.lookup(0), Some(100));
    assert_eq!(runs.lookup(3), Some(103));
    assert_eq!(runs.lookup(4), Some(200));
    assert_eq!(runs.lookup(7), Some(203));
    assert_eq!(runs.lookup(8), None);
}

#[test]
fn adjacent_runs_merge_on_append() {
    // An unmerged list grows a run per append and no longer packs into the
    // record it must be written back into.
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 100, len: 1 });
    runs.push(Run { vcn: 1, lcn: 101, len: 1 });
    runs.push(Run { vcn: 2, lcn: 102, len: 1 });
    assert_eq!(runs.runs.len(), 1);
    assert_eq!(runs.runs[0].len, 3);
}

#[test]
fn runs_that_are_not_adjacent_do_not_merge() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 100, len: 1 });
    runs.push(Run { vcn: 1, lcn: 200, len: 1 });
    assert_eq!(runs.runs.len(), 2);
}

#[test]
fn two_holes_merge_and_a_hole_does_not_merge_with_a_run() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: SPARSE_LCN, len: 2 });
    runs.push(Run { vcn: 2, lcn: SPARSE_LCN, len: 2 });
    assert_eq!(runs.runs.len(), 1);
    runs.push(Run { vcn: 4, lcn: 100, len: 1 });
    assert_eq!(runs.runs.len(), 2);
}

#[test]
fn a_runlist_round_trips_through_both_directions() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 0x1234, len: 5 });
    runs.push(Run { vcn: 5, lcn: 0x40, len: 3 });
    runs.push(Run { vcn: 8, lcn: SPARSE_LCN, len: 7 });
    runs.push(Run { vcn: 15, lcn: 0x9000, len: 2 });
    let packed = pack(&runs);
    assert_eq!(unpack(&packed, 0, 16, CLUSTERS).unwrap(), runs);
}

#[test]
fn a_large_cluster_number_round_trips() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 0xF_0000, len: 0xFFFF });
    let packed = pack(&runs);
    assert_eq!(unpack(&packed, 0, 0xFFFE, CLUSTERS).unwrap(), runs);
}

#[test]
fn a_length_whose_top_bit_is_set_does_not_read_back_negative() {
    // The packed length is unsigned but shares the width encoding with the
    // signed offset; a width chosen without room for the sign bit reads back
    // as a different number.
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 8, len: 0x80 });
    let packed = pack(&runs);
    assert_eq!(unpack(&packed, 0, 0x7F, CLUSTERS).unwrap(), runs);
}

#[test]
fn a_header_reaching_past_the_bytes_is_refused() {
    assert_eq!(unpack(&[0x21, 0x04], 0, 3, CLUSTERS), Err(RunError::Truncated));
    assert_eq!(unpack(&[0x11, 0x04], 0, 3, CLUSTERS), Err(RunError::Truncated));
}

#[test]
fn a_run_of_no_clusters_is_refused() {
    assert_eq!(unpack(&[0x11, 0x00, 0x40, 0x00], 0, 3, CLUSTERS), Err(RunError::ZeroLength));
}

#[test]
fn a_cluster_outside_the_volume_is_refused() {
    assert_eq!(unpack(&[0x11, 0x04, 0x7F, 0x00], 0, 3, 8), Err(RunError::OutOfRange));
}

#[test]
fn a_negative_absolute_cluster_is_refused() {
    // A first run whose delta is negative names a cluster before the volume.
    assert_eq!(unpack(&[0x11, 0x04, 0xF0, 0x00], 0, 3, CLUSTERS), Err(RunError::OutOfRange));
}

#[test]
fn runs_covering_more_than_the_attribute_declared_are_refused() {
    assert_eq!(unpack(&[0x11, 0x10, 0x40, 0x00], 0, 3, CLUSTERS), Err(RunError::Mismatch));
}

#[test]
fn an_empty_range_decodes_to_nothing() {
    assert_eq!(unpack(&[0x00], 1, 0, CLUSTERS).unwrap().runs.len(), 0);
}

#[test]
fn a_sparse_file_allocates_less_than_it_covers() {
    let mut runs = Runs::new();
    runs.push(Run { vcn: 0, lcn: 100, len: 2 });
    runs.push(Run { vcn: 2, lcn: SPARSE_LCN, len: 6 });
    assert_eq!(runs.clusters(), 8);
    assert_eq!(runs.allocated(), 2);
}
