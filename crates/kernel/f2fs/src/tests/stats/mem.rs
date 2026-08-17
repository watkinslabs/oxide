//! The footprint must follow the structures it measures.

use sectors::MemImage;

use crate::stats::counters::Counters;
use crate::stats::mem::Footprint;
use crate::test_image;
use crate::volume::Volume;

/// # C: O(1)
fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// The static part is fixed by geometry and is never zero: a mount always
/// holds its superblock, its checkpoint and both version bitmaps.
#[test]
fn the_static_part_is_what_the_geometry_forces_the_mount_to_hold() {
    let v = vol();
    let f = Footprint::of(&v, &Counters::new());
    assert!(f.base_mem > 0);
    assert!(f.base_mem as usize >= v.checkpoint_bytes().len());
}

/// Loading the segment table is what makes the static part grow, and it grows
/// by the whole table: the table is one entry per segment whether or not
/// anything has been written into them.
#[test]
fn loading_the_segment_table_adds_the_whole_table() {
    let mut v = vol();
    let before = Footprint::of(&v, &Counters::new()).base_mem;
    v.load_segments().unwrap();
    let after = Footprint::of(&v, &Counters::new()).base_mem;
    let table = u64::from(v.super_block().segment_count_main)
        * core::mem::size_of::<crate::summary::SitEntry>() as u64;
    assert_eq!(after - before, table);
}

/// The cached part follows what the mount has touched, so a mount that has
/// touched nothing owes nothing.
#[test]
fn the_cached_part_grows_with_what_the_mount_has_touched() {
    let mut v = vol();
    let before = Footprint::of(&v, &Counters::new()).cache_mem;
    for ino in 0..8u32 { v.orphans.insert(ino); }
    v.pending_discard.push(1);
    let after = Footprint::of(&v, &Counters::new()).cache_mem;
    assert!(after > before, "{before} -> {after}");
}

/// The total is the sum of the three parts and nothing else: a total computed
/// another way could disagree with the breakdown printed beside it.
#[test]
fn the_total_is_exactly_the_three_parts() {
    let v = vol();
    let f = Footprint::of(&v, &Counters::new());
    assert_eq!(f.total(), f.base_mem + f.cache_mem + f.page_mem);
}

/// Nothing is held for its own sake here — there is no page cache — so the
/// paged figure is a measurement of zero rather than an absent one.
#[test]
fn no_bytes_are_held_for_their_own_sake() {
    let v = vol();
    assert_eq!(Footprint::of(&v, &Counters::new()).page_mem, 0);
}
