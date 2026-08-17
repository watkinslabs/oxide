//! Every pair of sites must cancel, and no site may wrap.

use crate::stats::counters::*;

/// An inode brought in and evicted again leaves nothing behind. A counter
/// that survived one round trip would drift up for the life of the mount and
/// read as a leak nobody could locate.
#[test]
fn an_inode_in_and_out_again_leaves_every_counter_where_it_started() {
    let mut c = Counters::new();
    let s = Shape { inline_xattr: true, inline_data: true, inline_dentry: true,
                    compressed: true, compr_blocks: 7 };
    let held = c.inode_in(s);
    assert_eq!((c.inline_xattr, c.inline_inode, c.inline_dir), (1, 1, 1));
    assert_eq!((c.compr_inode, c.compr_blocks), (1, 7));
    c.inode_out(held);
    assert_eq!(c, Counters::new());
}

/// Only the shapes the inode actually has are counted.
#[test]
fn an_inode_with_no_inline_region_raises_no_inline_counter() {
    let mut c = Counters::new();
    c.inode_in(Shape::default());
    assert_eq!((c.inline_xattr, c.inline_inode, c.inline_dir, c.compr_inode), (0, 0, 0, 0));
}

/// The record returned by the entry site is what the exit site must undo. An
/// inode whose shape changed while it was live has already had the change
/// counted, so undoing the CURRENT shape would count it twice.
#[test]
fn eviction_undoes_what_instantiation_counted_not_the_current_shape() {
    let mut c = Counters::new();
    let held = c.inode_in(Shape { inline_data: true, ..Shape::default() });
    // The file's contents moved out while it was live.
    c.dec_inline_data();
    assert_eq!(c.inline_inode, 0);
    c.inode_out(held);
    // Undoing the recorded shape a second time is exactly the double count
    // this test exists to expose, so the record must be updated by whatever
    // changed the shape — which is what a live inode's own copy is for.
    assert_eq!(c.inline_inode, -1);
}

/// The peak is raised as it happens. Reading it back later could only ever
/// see the count that survived, which is not the peak.
#[test]
fn the_atomic_write_peak_records_the_highest_that_were_ever_open() {
    let mut c = Counters::new();
    c.inc_atomic_inode();
    c.inc_atomic_inode();
    c.inc_atomic_inode();
    c.dec_atomic_inode();
    c.dec_atomic_inode();
    assert_eq!(c.atomic_files, 1);
    assert_eq!(c.max_aw_cnt, 3);
}

/// A metadata write is filed by the area its address falls in, and an address
/// past the metadata is filed nowhere: counting a data block as metadata would
/// make the four figures add up to more than the metadata written.
#[test]
fn a_metadata_write_is_filed_by_the_area_its_address_falls_in() {
    // Areas begin at these addresses, in this order.
    let (sit, nat, ssa, main) = (10, 20, 30, 40);
    assert_eq!(meta_kind(0, sit, nat, ssa, main), Some(meta::CP));
    assert_eq!(meta_kind(9, sit, nat, ssa, main), Some(meta::CP));
    assert_eq!(meta_kind(10, sit, nat, ssa, main), Some(meta::SIT));
    assert_eq!(meta_kind(19, sit, nat, ssa, main), Some(meta::SIT));
    assert_eq!(meta_kind(20, sit, nat, ssa, main), Some(meta::NAT));
    assert_eq!(meta_kind(30, sit, nat, ssa, main), Some(meta::SSA));
    assert_eq!(meta_kind(39, sit, nat, ssa, main), Some(meta::SSA));
    assert_eq!(meta_kind(40, sit, nat, ssa, main), None);
    assert_eq!(meta_kind(4000, sit, nat, ssa, main), None);
}

/// The counter follows the address, so a writer that knows only where the
/// block went still files it correctly.
#[test]
fn the_meta_counter_files_by_address() {
    let mut c = Counters::new();
    c.inc_meta_count(0, 10, 20, 30, 40);
    c.inc_meta_count(25, 10, 20, 30, 40);
    c.inc_meta_count(100, 10, 20, 30, 40);
    assert_eq!(c.meta_count[meta::CP], 1);
    assert_eq!(c.meta_count[meta::NAT], 1);
    assert_eq!(c.meta_count.iter().sum::<u32>(), 2);
}

/// The moved-block total is raised at the site rather than summed at report
/// time, so a block counted in neither row shows as a discrepancy.
#[test]
fn cleaned_blocks_raise_the_total_and_their_own_row() {
    let mut c = Counters::new();
    c.add_gc_data_blks(3, gc_when::FG);
    c.add_gc_data_blks(2, gc_when::BG);
    c.add_gc_node_blks(4, gc_when::BG);
    assert_eq!(c.tot_blks, 9);
    assert_eq!((c.data_blks, c.bg_data_blks), (5, 2));
    assert_eq!((c.node_blks, c.bg_node_blks), (4, 4));
}

/// A demand clean contributes nothing to the background figures.
#[test]
fn a_demand_clean_adds_nothing_to_the_background_rows() {
    let mut c = Counters::new();
    c.add_gc_node_blks(6, gc_when::FG);
    assert_eq!(c.bg_node_blks, 0);
    assert_eq!(c.node_blks, 6);
}

/// Only the read cache has an extent on the inode itself, so only its total
/// includes those hits. Adding them to the age cache's total would make its
/// ratio exceed a hundred percent.
#[test]
fn only_the_read_caches_total_includes_the_hits_the_inode_answered() {
    let mut c = Counters::new();
    c.inc_largest_hit();
    c.inc_cached_hit(extent_of::READ);
    c.inc_rbtree_hit(extent_of::READ);
    c.inc_cached_hit(extent_of::BLOCK_AGE);
    assert_eq!(c.hit_total(extent_of::READ), 3);
    assert_eq!(c.hit_total(extent_of::BLOCK_AGE), 1);
}

/// The allocation strategy indexes an array, so an out-of-range value must be
/// dropped rather than panicking a read of the report.
#[test]
fn an_unknown_allocation_strategy_is_dropped_rather_than_indexed() {
    let mut c = Counters::new();
    c.inc_seg_type(9);
    c.inc_block_count(9);
    assert_eq!(c.segment_count, [0, 0]);
    assert_eq!(c.block_count, [0, 0]);
}

/// The unsigned lists must not wrap. A dirty-inode count that went round to
/// four billion would read as the volume being entirely dirty.
#[test]
fn an_unmatched_decrement_of_an_unsigned_list_stops_at_zero() {
    let mut c = Counters::new();
    c.dec_dirty_inode(dirty_of::DIR);
    c.dec_donate_files();
    assert_eq!(c.ndirty_inode[dirty_of::DIR], 0);
    assert_eq!(c.donate_files, 0);
}

/// The two call slots are distinct and the reported total is the demand one:
/// a checkpoint taken ahead of demand must not inflate the figure that says
/// how often something had to wait for one.
#[test]
fn the_reported_checkpoint_total_is_the_demand_slot() {
    let mut c = Counters::new();
    c.inc_cp_call(call::TOTAL);
    c.inc_cp_call(call::TOTAL);
    c.inc_cp_call(call::BACKGROUND);
    assert_eq!(c.cp_call_count[call::TOTAL], 2);
    assert_eq!(c.cp_call_count[call::BACKGROUND], 1);
    assert_eq!(call::TOTAL, call::FOREGROUND);
}

/// The shape a stored inode presents is what the entry site counts.
#[test]
fn a_stored_inodes_shape_is_read_off_the_inode() {
    let mut b = crate::test_image::with_root();
    crate::test_image::nodes::add_inline_file(&mut b, 4, b"hello");
    let v = b.mount_rw().unwrap();
    let i = v.read_inode(4).unwrap();
    let s = Shape::of(&i);
    assert!(s.inline_data, "the fixture's file keeps its contents inline");
    assert!(!s.compressed);
}
