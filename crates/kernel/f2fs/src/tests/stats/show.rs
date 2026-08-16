//! The report's exact text, which is the part tools depend on.
//!
//! Every assertion here is on a LABEL or a COLUMN, because a reader matches
//! on those and a field that moves is a field that stops being read. The
//! numbers are checked where the line's meaning depends on which of two
//! similar figures it carries.

use alloc::string::String;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::stats::counters::{alloc_of, call, gc_mode, gc_of, gc_when, meta, Counters};
use crate::stats::sample::General;
use crate::stats::show::partition;
use crate::test_image;
use crate::volume::Volume;

/// # C: O(1)
fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// # C: O(main segments)
fn body(c: &Counters) -> alloc::string::String {
    let mut v = vol();
    let g = General::sample(&mut v, c).unwrap();
    partition(&g, "vda", 0, 1234)
}

/// The banner carries the device, the position in the list, the mount's
/// writability and the checkpoint's health — the four things that decide
/// whether the rest of the section means anything.
#[test]
fn the_banner_names_the_device_its_position_and_the_checkpoints_health() {
    let b = body(&Counters::new());
    assert!(b.starts_with("\n=====[ partition info(vda). #0, RW, CP: Good]=====\n"), "{b}");
}

/// A read-only mount says so in the same field, so a reader does not have to
/// find the writability anywhere else.
#[test]
fn a_read_only_mount_is_named_in_the_banner() {
    let mut v = test_image::with_root().mount().unwrap();
    let g = General::sample(&mut v, &Counters::new()).unwrap();
    let b = partition(&g, "vdb", 3, 0);
    assert!(b.starts_with("\n=====[ partition info(vdb). #3, RO, CP: Good]=====\n"), "{b}");
}

/// The disabled state is reported ahead of the error state: it is the one
/// that explains the other numbers.
#[test]
fn a_checkpoint_that_is_off_is_reported_ahead_of_one_in_error() {
    use crate::flags::{CP_DISABLED_FLAG, CP_ERROR_FLAG};
    use crate::stats::show::head::cp_state;
    assert_eq!(cp_state(0), "Good");
    assert_eq!(cp_state(CP_ERROR_FLAG), "Error");
    assert_eq!(cp_state(CP_DISABLED_FLAG), "Disabled");
    assert_eq!(cp_state(CP_DISABLED_FLAG | CP_ERROR_FLAG), "Disabled");
}

/// The area line is the on-medium layout: two fixed areas and four sized
/// ones, with the reserve and overprovision inside the main area's bracket.
#[test]
fn the_area_line_carries_every_area_and_the_reserve_inside_the_main_one() {
    let b = body(&Counters::new());
    let line = b.lines().find(|l| l.starts_with("[SB: 1]")).unwrap();
    assert!(line.contains(&alloc::format!("[SIT: {}]", test_image::SEG_SIT)), "{line}");
    assert!(line.contains(&alloc::format!("[NAT: {}]", test_image::SEG_NAT)), "{line}");
    assert!(line.contains(&alloc::format!("[SSA: {}]", test_image::SEG_SSA)), "{line}");
    assert!(line.contains(&alloc::format!("[MAIN: {}(OverProv:", test_image::SEG_MAIN)), "{line}");
    assert!(line.ends_with(")]"), "{line}");
}

/// Nothing rewrites a block where it sits in this build, so the policy set is
/// empty and must read as disabled rather than as an unnamed policy.
#[test]
fn the_policy_block_reports_in_place_update_as_off() {
    let b = body(&Counters::new());
    assert!(b.contains("Policy:\n  - IPU: [ DISABLE ]\n\n"), "{b}");
}

/// The per-shape inode counts each get their own line, so a reader can take
/// one without parsing the others.
#[test]
fn each_inode_shape_has_its_own_line() {
    let mut c = Counters::new();
    c.inc_inline_xattr();
    c.inc_inline_data();
    c.inc_inline_data();
    c.inc_inline_dentry();
    c.inc_compr_inode();
    c.add_compr_blocks(12);
    c.inc_swapfile_inode();
    c.inc_donate_files();
    let b = body(&c);
    assert!(b.contains("  - Inline_xattr Inode: 1\n"), "{b}");
    assert!(b.contains("  - Inline_data Inode: 2\n"), "{b}");
    assert!(b.contains("  - Inline_dentry Inode: 1\n"), "{b}");
    assert!(b.contains("  - Compressed Inode: 1, Blocks: 12\n"), "{b}");
    assert!(b.contains("  - Swapfile Inode: 1\n"), "{b}");
    assert!(b.contains("  - Donate Inode: 1\n"), "{b}");
}

/// The three unlinked-or-pending inode figures share one line, in a fixed
/// order a reader splits on.
#[test]
fn the_three_pending_inode_figures_share_one_line_in_order() {
    let mut v = vol();
    v.orphans.insert(4);
    let mut c = Counters::new();
    c.append_ino = 5;
    c.update_ino = 6;
    let g = General::sample(&mut v, &c).unwrap();
    let b = partition(&g, "vda", 0, 0);
    assert!(b.contains("  - Orphan/Append/Update Inode: 1, 5, 6\n"), "{b}");
}

/// The occupancy table has one row per log, in the report's own order, and
/// each row carries seven columns.
#[test]
fn the_occupancy_table_has_one_row_per_log_with_seven_columns() {
    let b = body(&Counters::new());
    assert!(b.contains("    TYPE         "), "{b}");
    for name in ["COLD   data", "WARM   data", "HOT    data",
                 "Dir   dnode", "File  dnode", "Indir nodes"] {
        let row = b.lines().find(|l| l.starts_with(&alloc::format!("  - {name}:")))
            .unwrap_or_else(|| panic!("no row for {name} in {b}"));
        // The leading dash, the label's own words, and seven columns.
        assert_eq!(row.split_whitespace().count(), 1 + name.split_whitespace().count() + 7,
                   "{row}");
    }
    assert!(b.contains("  - Pinned file: "), "{b}");
    assert!(b.contains("  - ATGC   data: "), "{b}");
}

/// The four segment tallies follow the table, each on its own line, with the
/// free-section count in the free line's bracket.
#[test]
fn the_segment_tallies_follow_the_table() {
    let b = body(&Counters::new());
    assert!(b.contains("\n  - Valid: "), "{b}");
    assert!(b.contains("\n  - Dirty: "), "{b}");
    assert!(b.contains("\n  - Prefree: "), "{b}");
    let free = b.lines().find(|l| l.starts_with("  - Free: ")).unwrap();
    assert!(free.ends_with(')'), "{free}");
}

/// The checkpoint block reports what was asked for, what was written, and
/// where the metadata went — three different questions on separate lines.
#[test]
fn the_checkpoint_block_separates_calls_writes_and_where_they_landed() {
    let mut c = Counters::new();
    c.inc_cp_call(call::TOTAL);
    c.inc_cp_call(call::TOTAL);
    c.inc_cp_call(call::BACKGROUND);
    c.inc_cp_count();
    c.meta_count[meta::CP] = 4;
    c.meta_count[meta::SIT] = 5;
    c.meta_count[meta::NAT] = 6;
    c.meta_count[meta::SSA] = 7;
    let b = body(&c);
    assert!(b.contains("CP calls: 2 (BG: 1)\n"), "{b}");
    assert!(b.contains("CP count: 1\n"), "{b}");
    assert!(b.contains("  - cp blocks : 4\n"), "{b}");
    assert!(b.contains("  - sit blocks : 5\n"), "{b}");
    assert!(b.contains("  - nat blocks : 6\n"), "{b}");
    assert!(b.contains("  - ssa blocks : 7\n"), "{b}");
}

/// The cleaning block's totals are the sum of both urgencies, with the
/// ahead-of-demand share in the parenthesis.
#[test]
fn the_cleaning_totals_carry_the_background_share_in_the_bracket() {
    let mut c = Counters::new();
    c.inc_gc_call(call::FOREGROUND);
    c.inc_gc_call(call::BACKGROUND);
    c.inc_gc_call(call::BACKGROUND);
    c.inc_gc_seg(gc_of::DATA, gc_when::FG);
    c.inc_gc_seg(gc_of::DATA, gc_when::BG);
    c.inc_gc_seg(gc_of::NODE, gc_when::BG);
    c.add_gc_data_blks(9, gc_when::BG);
    c.add_gc_node_blks(1, gc_when::FG);
    c.add_reclaimed_segs(gc_mode::IDLE_GREEDY, 3);
    let b = body(&c);
    assert!(b.contains("GC calls: 3 (gc_thread: 2)\n"), "{b}");
    assert!(b.contains("  - data segments : 2 (BG: 1)\n"), "{b}");
    assert!(b.contains("  - node segments : 1 (BG: 1)\n"), "{b}");
    assert!(b.contains("    - Idle Greedy : 3\n"), "{b}");
    assert!(b.contains("Try to move 10 blocks (BG: 9)\n"), "{b}");
    assert!(b.contains("  - data blocks : 9 (9)\n"), "{b}");
    assert!(b.contains("  - node blocks : 1 (0)\n"), "{b}");
}

/// Section rows appear only where a section is more than one segment; on a
/// volume where the two are the same they would repeat the segment rows.
#[test]
fn section_rows_appear_only_where_a_section_is_more_than_one_segment() {
    let mut v = vol();
    let mut g = General::sample(&mut v, &Counters::new()).unwrap();
    g.large_section = false;
    assert!(!partition(&g, "vda", 0, 0).contains("data sections"));
    g.large_section = true;
    assert!(partition(&g, "vda", 0, 0).contains("  - data sections : 0 (BG: 0)\n"));
}

/// Both extent caches are reported, each with its hit breakdown and its ratio.
#[test]
fn both_extent_caches_are_reported_with_their_ratios() {
    use crate::stats::counters::extent_of;
    let mut c = Counters::new();
    for _ in 0..4 { c.inc_total_hit(extent_of::READ); }
    c.inc_cached_hit(extent_of::READ);
    c.inc_largest_hit();
    let b = body(&c);
    assert!(b.contains("\nExtent Cache (Read):\n"), "{b}");
    assert!(b.contains("  - Hit Count: L1-1:1 L1-2:1 L2:0\n"), "{b}");
    assert!(b.contains("  - Hit Ratio: 50% (2 / 4)\n"), "{b}");
    assert!(b.contains("\nExtent Cache (Block Age):\n"), "{b}");
    assert!(b.contains("  - Allocated Data Blocks: 0\n"), "{b}");
}

/// A cache nothing has asked reports no ratio rather than dividing by nothing.
#[test]
fn a_cache_with_no_lookups_reports_no_ratio() {
    let b = body(&Counters::new());
    assert!(b.contains("  - Hit Ratio: 0% (0 / 0)\n"), "{b}");
}

/// The distribution bar draws the three shares in order, separated by bars.
#[test]
fn the_distribution_bar_draws_three_shares() {
    let b = body(&Counters::new());
    assert!(b.contains("Distribution of User Blocks: [ valid | invalid | free ]\n"), "{b}");
    let bar = b.lines().find(|l| l.starts_with("  [")).unwrap();
    assert!(bar.ends_with(']'), "{bar}");
    let parts: alloc::vec::Vec<&str> = bar
        .trim_start_matches("  [").trim_end_matches(']').split('|').collect();
    assert_eq!(parts.len(), 3, "{bar}");
    assert_eq!(parts.iter().map(|p| p.len()).sum::<usize>(), 50, "{bar}");
}

/// The three ways a block can be written each get a line, so a reader can see
/// at a glance whether the volume is appending or recycling.
#[test]
fn the_write_split_reports_all_three_strategies() {
    let mut c = Counters::new();
    c.block_count[alloc_of::LFS] = 40;
    c.segment_count[alloc_of::LFS] = 2;
    c.block_count[alloc_of::SSR] = 5;
    c.segment_count[alloc_of::SSR] = 1;
    c.inplace_count = 7;
    let b = body(&c);
    assert!(b.contains("IPU: 7 blocks\n"), "{b}");
    assert!(b.contains("SSR: 5 blocks in 1 segments\n"), "{b}");
    assert!(b.contains("LFS: 40 blocks in 2 segments\n"), "{b}");
}

/// The spread figure and the memory block close the section, and the memory
/// total is the sum of its own parts.
#[test]
fn the_section_closes_with_the_spread_and_a_memory_total_that_adds_up() {
    let mut v = vol();
    let g = General::sample(&mut v, &Counters::new()).unwrap();
    let b = partition(&g, "vda", 0, 0);
    assert!(b.contains(&alloc::format!("\nBDF: {}, avg. vblocks: {}\n", g.bimodal, g.avg_vblocks)),
            "{b}");
    assert!(b.contains(&alloc::format!("\nMemory: {} KB\n", g.mem_total_kb())), "{b}");
    assert!(b.contains("  - static: "), "{b}");
    assert!(b.contains("  - cached all: "), "{b}");
    assert!(b.contains("  - paged : 0 KB\n"), "{b}");
    assert_eq!(g.mem.total(), g.mem.base_mem + g.mem.cache_mem + g.mem.page_mem);
}

/// The clock the report prints is the one it is given: nothing below this
/// layer can read one, so a report that invented a time would be inventing it.
#[test]
fn the_reported_time_is_the_one_the_caller_supplied() {
    let b = body(&Counters::new());
    assert!(b.contains("Current Time Sec: 1234 / Mounted Time Sec: "), "{b}");
}

/// A mount in a reportable condition lists it by name — and a mount in none
/// lists nothing, which is the answer an ordinary read-write mount gives.
///
/// The old spelling of this asserted `writable` on an ordinary mount, which
/// was the report of a bit fed from the wrong thing: the position means a
/// READ-ONLY mount made writable transiently to repair itself, not a mount
/// that may be written to.
#[test]
fn the_conditions_a_mount_is_in_are_listed_by_name() {
    let mut v = vol();
    let g = General::sample(&mut v, &Counters::new()).unwrap();
    assert!(!partition(&g, "vda", 0, 0).contains("[SBI:"), "an ordinary mount is in none");
    v.set_closing(true);
    let g = General::sample(&mut v, &Counters::new()).unwrap();
    assert!(partition(&g, "vda", 0, 0).contains("[SBI: closing]\n"));
}
