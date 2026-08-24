//! What readahead decides, asserted without a medium.

use alloc::vec;

use super::*;

/// The areas a small volume has, spaced so every bound is distinguishable:
/// a wrong bound picks a neighbouring area rather than passing by accident.
/// # C: O(1)
fn areas() -> Areas {
    Areas {
        cp_start: 2,
        sit_start: 100,
        sit_blocks: 3,
        ssa_start: 300,
        main_start: 400,
        nat_blocks: 5,
        main_end: 500,
    }
}

/// A contiguous window is ONE transfer, which is the entire point: the same
/// blocks read in one request instead of one per block. # C: O(1)
#[test]
fn contiguous_window_is_one_run() {
    let w = vec![Some(40), Some(41), Some(42), Some(43)];
    assert_eq!(runs(&w), vec![Run { at: 0, addr: 40, len: 4 }]);
}

/// A gap in the file breaks the run: the blocks either side are not adjacent
/// on the medium, so one transfer could not carry both. # C: O(1)
#[test]
fn a_hole_breaks_the_run() {
    let w = vec![Some(40), Some(41), None, Some(50), Some(51)];
    assert_eq!(runs(&w),
               vec![Run { at: 0, addr: 40, len: 2 }, Run { at: 3, addr: 50, len: 2 }]);
}

/// Adjacency is the MEDIUM's, not the window's. Two window slots side by side
/// whose blocks are not consecutive are two transfers — the bug this pins is
/// a run built by counting slots instead of comparing addresses, which would
/// read `len` blocks from the first address and file blocks the file does not
/// own as its later ones. # C: O(1)
#[test]
fn window_adjacency_is_not_run_adjacency() {
    let w = vec![Some(40), Some(99), Some(100)];
    assert_eq!(runs(&w),
               vec![Run { at: 0, addr: 40, len: 1 }, Run { at: 1, addr: 99, len: 2 }]);
}

/// A run longer than one transfer is SPLIT, never truncated: every block of
/// the window is still fetched, in more than one request. # C: O(MAX_RA_BLOCKS)
#[test]
fn an_overlong_run_splits_and_loses_nothing() {
    let w: alloc::vec::Vec<Option<u32>> =
        (0..MAX_RA_BLOCKS as u32 + 3).map(|i| Some(1000 + i)).collect();
    let r = runs(&w);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0], Run { at: 0, addr: 1000, len: MAX_RA_BLOCKS });
    assert_eq!(r[1], Run { at: MAX_RA_BLOCKS, addr: 1000 + MAX_RA_BLOCKS as u32, len: 3 });
    assert_eq!(r.iter().map(|x| x.len).sum::<usize>(), w.len());
}

/// An empty window and an all-skipped window are both no transfers at all.
/// # C: O(1)
#[test]
fn nothing_to_do_is_no_transfer() {
    assert!(runs(&[]).is_empty());
    assert!(runs(&[None, None, None]).is_empty());
}

/// Each kind of metadata is bounded by ITS OWN area. A summary index inside
/// the main area, a pack index inside the segment table, a table index past
/// the entries the table holds — each is refused by the kind that cannot reach
/// it and accepted by the kind that can, which is what stops one area's blocks
/// being filed under another's name. # C: O(1)
#[test]
fn each_meta_kind_is_bounded_by_its_own_area() {
    let a = areas();
    // Checkpoint pack: from its own start, up to the segment table.
    assert!(meta_index_ok(RaMeta::Cp, 2, &a));
    assert!(meta_index_ok(RaMeta::Cp, 99, &a));
    assert!(!meta_index_ok(RaMeta::Cp, 1, &a));
    assert!(!meta_index_ok(RaMeta::Cp, 100, &a));
    // Summary area: from its start, up to the main area.
    assert!(meta_index_ok(RaMeta::Ssa, 300, &a));
    assert!(meta_index_ok(RaMeta::Ssa, 399, &a));
    assert!(!meta_index_ok(RaMeta::Ssa, 299, &a));
    assert!(!meta_index_ok(RaMeta::Ssa, 400, &a));
    // The segment table is bounded by the blocks its ENTRIES need, not by the
    // blocks the area reserves: the area is twice as large because of its
    // second copy.
    assert!(meta_index_ok(RaMeta::Sit, 0, &a));
    assert!(meta_index_ok(RaMeta::Sit, 2, &a));
    assert!(!meta_index_ok(RaMeta::Sit, 3, &a));
}

/// The node table is the one kind that WRAPS instead of stopping, because the
/// scan it serves walks it as a ring. An index past the end reads the first
/// block again rather than the block after the table. # C: O(1)
#[test]
fn the_node_table_window_wraps() {
    let a = areas();
    assert!(meta_index_ok(RaMeta::Nat, a.nat_blocks + 10, &a));
    assert_eq!(nat_ra_index(0, 5), 0);
    assert_eq!(nat_ra_index(4, 5), 4);
    assert_eq!(nat_ra_index(5, 5), 0);
    assert_eq!(nat_ra_index(9, 5), 0);
    // A volume with no table at all cannot wrap into it.
    assert_eq!(nat_ra_index(3, 0), 3);
}

/// An index is not an address for the two table kinds: it names a group of
/// entries, so it scales by the entries a block holds. A readahead that used
/// the index directly would resolve the wrong block for every index but zero.
/// # C: O(1)
#[test]
fn a_table_index_scales_to_its_first_entry() {
    assert_eq!(nat_ra_nid(0, 455), 0);
    assert_eq!(nat_ra_nid(3, 455), 1365);
    assert_eq!(sit_ra_segno(0, 55), 0);
    assert_eq!(sit_ra_segno(4, 55), 220);
    // A scaled index that would overflow saturates rather than wrapping to a
    // small number, which would name an entry in the wrong block.
    assert_eq!(nat_ra_nid(u32::MAX, 455), u32::MAX);
}
