//! The picture must match the volume it was taken from.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::stats::counters::{call, Counters};
use crate::stats::sample::General;
use crate::test_image;
use crate::volume::Volume;

/// # C: O(1)
fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// # C: O(main segments)
fn pic(v: &mut Volume<MemImage>, c: &Counters) -> General { General::sample(v, c).unwrap() }

/// The layout figures come off the superblock, not off anything the mount
/// accumulated: a mount that has done nothing still describes its volume.
#[test]
fn the_area_sizes_are_the_volumes_own() {
    let mut v = vol();
    let g = pic(&mut v, &Counters::new());
    assert_eq!(g.sit_area_segs, test_image::SEG_SIT);
    assert_eq!(g.nat_area_segs, test_image::SEG_NAT);
    assert_eq!(g.ssa_area_segs, test_image::SEG_SSA);
    assert_eq!(g.main_area_segs, test_image::SEG_MAIN);
    assert_eq!(g.all_area_segs, test_image::SEGMENT_COUNT);
    assert_eq!(g.sits, test_image::SEG_MAIN, "one segment-table entry per segment");
}

/// The segment table is loaded by the sample itself. A mount that has never
/// written has never had reason to read it, and reporting an untouched volume
/// because nothing loaded the table is a lie the reader cannot detect.
#[test]
fn taking_the_picture_loads_the_table_it_needs() {
    let mut b = test_image::with_root();
    test_image::nodes::add_inline_file(&mut b, 4, b"x");
    let mut v = b.mount_rw().unwrap();
    let g = pic(&mut v, &Counters::new());
    assert!(g.free_segs < g.main_area_segs, "the fixture's blocks are somewhere");
}

/// Occupancy is reported per log, and every live block is filed under exactly
/// one of them: a block counted twice or not at all makes the table disagree
/// with the volume it describes.
#[test]
fn every_live_block_is_filed_under_exactly_one_log() {
    let mut b = test_image::with_root();
    test_image::nodes::add_inline_file(&mut b, 4, b"hello");
    test_image::nodes::add_inline_file(&mut b, 5, b"world");
    let mut v = b.mount_rw().unwrap();
    let g = pic(&mut v, &Counters::new());
    let filed: u32 = g.valid_blks.iter().sum();
    let live: u32 = (0..g.main_area_segs).map(|s| u32::from(v.seg_valid(s))).sum();
    assert_eq!(filed, live);
}

/// A segment is dirty when it holds something, is not full, and is not the one
/// a log is filling — the only kind the cleaner would ever look at.
#[test]
fn the_dirty_count_excludes_the_segment_a_log_is_filling() {
    let mut v = vol();
    let g = pic(&mut v, &Counters::new());
    let open: Vec<u32> = v.logs().iter().map(|l| l.segno).collect();
    let counted = (0..g.main_area_segs).filter(|&s| {
        let live = v.seg_valid(s);
        live > 0 && live < v.super_block().blks_per_seg() as u16 && !open.contains(&s)
    }).count() as u32;
    assert_eq!(g.dirty_count, counted);
}

/// The four segment states partition the main area. A volume whose parts do
/// not add up is reporting at least one of them wrongly.
#[test]
fn the_segment_states_account_for_the_whole_main_area() {
    let mut v = vol();
    let g = pic(&mut v, &Counters::new());
    let sum = g.valid_segs() + i64::from(g.dirty_count)
        + i64::from(g.prefree_count) + i64::from(g.free_segs);
    assert_eq!(sum, i64::from(g.main_area_segs));
}

/// Utilisation is what is used, over what may be used.
#[test]
fn utilisation_is_valid_blocks_as_a_share_of_the_users_blocks() {
    let mut v = vol();
    let user = v.checkpoint().user_block_count;
    let g = pic(&mut v, &Counters::new());
    assert_eq!(g.utilization, g.valid_count * 100 / user);
    assert!(g.utilization <= 100);
}

/// The three shares of the distribution bar are halves of a percent each and
/// must add to fifty, whatever the volume looks like.
#[test]
fn the_three_block_shares_add_up_to_the_whole_bar() {
    let mut v = vol();
    let g = pic(&mut v, &Counters::new());
    assert_eq!(g.util_valid + g.util_invalid + g.util_free, 50);
}

/// Each log's reported position is the log's own, and the section and zone are
/// derived from the segment rather than tracked beside it.
#[test]
fn each_logs_position_is_the_log_the_volume_is_writing_through() {
    let mut v = vol();
    let per_sec = v.super_block().segs_per_sec.max(1);
    let per_zone = v.super_block().secs_per_zone.max(1);
    let logs: Vec<(u32, u16)> = v.logs().iter().map(|l| (l.segno, l.next_blkoff)).collect();
    let g = pic(&mut v, &Counters::new());
    for (i, (segno, blkoff)) in logs.iter().enumerate() {
        assert_eq!(g.curseg[i], *segno);
        assert_eq!(g.blkoff[i], u32::from(*blkoff));
        assert_eq!(g.cursec[i], segno / per_sec);
        assert_eq!(g.curzone[i], (segno / per_sec) / per_zone);
    }
}

/// Counters are carried through untouched. The picture must not recompute a
/// running total, and must not lose one.
#[test]
fn every_counter_reaches_the_picture_unchanged() {
    let mut v = vol();
    let mut c = Counters::new();
    c.inc_cp_call(call::TOTAL);
    c.inc_cp_count();
    c.inc_inplace_blocks();
    c.add_defrag_blks(11);
    c.inc_io_skip_bggc();
    c.inc_other_skip_bggc();
    c.inode_in(crate::stats::Shape { compressed: true, compr_blocks: 3,
                                     ..Default::default() });
    let g = pic(&mut v, &c);
    assert_eq!(g.cp_call_count[call::TOTAL], 1);
    assert_eq!(g.cp_count, 1);
    assert_eq!(g.inplace_count, 1);
    assert_eq!(g.defrag_blks, 11);
    assert_eq!((g.io_skip_bggc, g.other_skip_bggc), (1, 1));
    assert_eq!((g.compr_inode, g.compr_blocks), (1, 3));
}

/// Orphans are read off the volume, not counted: the set is the truth and a
/// counter beside it could disagree with it.
#[test]
fn the_orphan_figure_is_the_volumes_own_set() {
    let mut v = vol();
    assert_eq!(pic(&mut v, &Counters::new()).orphans, 0);
    v.orphans.insert(9);
    v.orphans.insert(10);
    assert_eq!(pic(&mut v, &Counters::new()).orphans, 2);
}

/// Blocks the mount has released but not yet announced are reported, because
/// they are neither in use nor available to the device.
#[test]
fn blocks_awaiting_announcement_are_reported() {
    let mut v = vol();
    v.pending_discard.push(100);
    v.pending_discard.push(101);
    let g = pic(&mut v, &Counters::new());
    assert_eq!(g.discard_blks, 2);
    assert_eq!(g.undiscard_blks, 2);
}

/// A read-only mount says so, and the condition word agrees with the mount's
/// own status attribute rather than being computed a second way.
#[test]
fn the_condition_word_is_the_one_the_mount_publishes() {
    let mut v = test_image::with_root().mount().unwrap();
    let g = pic(&mut v, &Counters::new());
    assert!(!g.writable);
    assert_eq!(g.sbi_flags,
               crate::sysfs::status_word(v.is_dirty(), v.recovering, v.writable(),
                                         v.options().checkpoint_disabled,
                                         v.checkpoint().flags));
}

/// Node slots left are what the table can name, less what is reserved and
/// what is already used — the same axis a volume can exhaust independently of
/// its blocks.
#[test]
fn the_available_node_figure_leaves_out_the_reserved_and_the_used() {
    let mut v = vol();
    let max = v.max_nid();
    let used = v.valid_node_count;
    let g = pic(&mut v, &Counters::new());
    assert_eq!(g.avail_nids, max - crate::uapi::RESERVED_NODE_NUM - used);
}
