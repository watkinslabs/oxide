//! The mount's metadata mapping, driven through a real volume.
//!
//! Two properties carry the feature and both are asserted against the MEDIUM
//! rather than against the mapping's own bookkeeping: a second read of a
//! metadata block does not go to the device, and a block the mount rewrote
//! reads back as what was written. A cache that only reported hits would pass
//! a test written against its counters while serving the previous checkpoint.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::checkpoint::cache::META_CACHE_MAX_BLOCKS;
use crate::test_image::{self, CP_BLKADDR, MAIN_BLKADDR, NAT_BLKADDR,
                        SIT_BLKADDR, SSA_BLKADDR};
use crate::uapi::BLKSIZE;
use crate::volume::Volume;

/// # C: O(1 image)
fn volume() -> Volume<MemImage> { test_image::with_root().mount().unwrap() }

/// # C: O(n)
fn patterned(n: usize, seed: u8) -> Vec<u8> { (0..n).map(|_| seed).collect() }

/// Overwrite the medium under a block address, behind the mount's back.
///
/// Stands in for "the device now holds something else", which is what a test
/// needs in order to tell a served read from a re-read. # C: O(BLKSIZE)
fn poison(v: &Volume<MemImage>, addr: u32) {
    v.source_ref().poke(addr as usize * BLKSIZE, &patterned(BLKSIZE, 0xA5));
}

#[test]
fn the_mapping_covers_the_metadata_area_and_nothing_else() {
    let v = volume();
    // The superblock copies are below the checkpoint area and are written by a
    // path that does not pass the volume's block writer.
    assert!(!v.meta_cache.covers(0));
    assert!(!v.meta_cache.covers(CP_BLKADDR - 1));
    for a in [CP_BLKADDR, SIT_BLKADDR, NAT_BLKADDR, SSA_BLKADDR, MAIN_BLKADDR - 1] {
        assert!(v.meta_cache.covers(a), "{a} is metadata");
    }
    // A file's blocks are the main area's business, not this mapping's.
    assert!(!v.meta_cache.covers(MAIN_BLKADDR));
    assert!(!v.meta_cache.covers(MAIN_BLKADDR + 1));
}

#[test]
fn a_second_read_of_a_metadata_block_never_reaches_the_medium() {
    let v = volume();
    let first = v.read_block(NAT_BLKADDR).unwrap();
    assert_eq!(v.meta_cache.hits(), 0, "the first read had nothing to hit");
    // The device now holds something else at that address. A read that goes
    // back to it returns the new bytes; a read served from the mapping does
    // not — so this distinguishes the two without trusting either counter.
    poison(&v, NAT_BLKADDR);
    assert_eq!(v.read_block(NAT_BLKADDR).unwrap(), first, "the second read went to the medium");
    assert_eq!(v.meta_cache.hits(), 1);
}

#[test]
fn a_main_area_block_is_read_every_time() {
    // The control for the case above: the same poisoning on an address the
    // mapping does not cover must be visible.
    let v = volume();
    let addr = MAIN_BLKADDR;
    let first = v.read_block(addr).unwrap();
    poison(&v, addr);
    assert_ne!(v.read_block(addr).unwrap(), first, "a main-area read was served from somewhere");
    assert_eq!(v.meta_cache.hits(), 0);
}

#[test]
fn a_rewritten_metadata_block_reads_back_as_what_was_written() {
    // THE failure a read cache produces: the block is held, the mount rewrites
    // it, and the next read hands back the bytes it used to have — no error
    // anywhere, and a checkpoint or a node table read as an older version of
    // itself.
    let v = volume();
    let addr = SIT_BLKADDR + 1;
    let before = v.read_block(addr).unwrap();
    assert_eq!(v.meta_cache.blocks(), 1, "the read must have been kept or this proves nothing");

    let after = patterned(BLKSIZE, 0x5C);
    assert_ne!(before, after);
    v.write_block(addr, &after).unwrap();
    assert_eq!(v.read_block(addr).unwrap(), after, "served the bytes the block used to hold");
    // And the medium agrees, so the mapping was not merely made to lie
    // consistently with itself.
    assert_eq!(v.source_ref().peek(addr as usize * BLKSIZE, BLKSIZE), after);
}

#[test]
fn a_metadata_write_does_not_fill_the_mapping() {
    // Writing is not evidence a block is worth holding. A checkpoint writes
    // every summary block it owns and reads none of them back; taking them
    // here would spend the ceiling on blocks nothing will ask for.
    let v = volume();
    let start = v.meta_cache.blocks();
    v.write_block(SSA_BLKADDR, &patterned(BLKSIZE, 0x3D)).unwrap();
    assert_eq!(v.meta_cache.blocks(), start);
}

#[test]
fn a_failed_metadata_write_leaves_the_held_block_alone() {
    // A write refused before it reached the medium must not be recorded as if
    // it had landed: the address still holds what it held.
    let v = volume();
    let addr = NAT_BLKADDR + 2;
    let before = v.read_block(addr).unwrap();
    assert!(v.write_block(addr, &[0u8; 7]).is_err());
    assert_eq!(v.read_block(addr).unwrap(), before);
    assert_eq!(v.source_ref().peek(addr as usize * BLKSIZE, BLKSIZE), before);
}

#[test]
fn a_held_block_is_answered_without_charging_the_device() {
    // The counter the mapping exists to move. Metadata read traffic is charged
    // where the read happens, so a served read must add nothing to it.
    let mut v = volume();
    v.set_iostat_enabled(true);
    let read = crate::stats::iostat::Io::FsMetaRead as usize;
    let addr = SIT_BLKADDR;
    v.read_block(addr).unwrap();
    let once = v.counters().iostat.bytes[read];
    assert_eq!(once, BLKSIZE as u64, "the first read moved a block at the device");
    v.read_block(addr).unwrap();
    assert_eq!(v.counters().iostat.bytes[read], once,
               "a served read was charged to the device");
}

#[test]
fn the_status_report_carries_what_is_held() {
    // The line has always been rendered and has always said nothing. A reader
    // matching on it cannot tell "this mount holds none" from "this build does
    // not count", so the figure has to be the mapping's own.
    let mut v = volume();
    for a in [CP_BLKADDR, SIT_BLKADDR, NAT_BLKADDR] { v.read_block(a).unwrap(); }
    let held = v.meta_cache.blocks();
    assert!(held >= 3, "held {held}");
    let c = crate::stats::counters::Counters::new();
    let g = crate::stats::sample::General::sample(&mut v, &c).unwrap();
    assert_eq!(g.meta_cached, v.meta_cache.blocks());
    let text = crate::stats::show::partition(&g, "vda", 0, 0);
    assert!(text.contains(&alloc::format!("  - meta:    0 in {:>4}\n", g.meta_cached)), "{text}");
}

#[test]
fn the_mapping_stops_at_its_bound_and_keeps_what_it_already_holds() {
    let v = volume();
    let data = patterned(BLKSIZE, 0x77);
    // Addresses inside the covered area are not required by `store` — the
    // bound is the mapping's, not the layout's — so the ceiling is reached
    // directly rather than by building a volume large enough to have one.
    for i in 0..META_CACHE_MAX_BLOCKS as u32 { v.meta_cache.store(i, &data); }
    assert_eq!(v.meta_cache.blocks(), META_CACHE_MAX_BLOCKS);
    v.meta_cache.store(META_CACHE_MAX_BLOCKS as u32, &data);
    assert_eq!(v.meta_cache.blocks(), META_CACHE_MAX_BLOCKS, "the bound is a bound");
    assert!(v.meta_cache.load(0).is_some(), "a full mapping declines rather than evicting");
}

#[test]
fn a_forgotten_block_is_read_again() {
    // What the write path does when it cannot know the bytes that landed. The
    // mapping must go back to the medium afterwards, not keep answering with
    // what the address used to hold.
    let v = volume();
    let addr = NAT_BLKADDR;
    let first = v.read_block(addr).unwrap();
    v.meta_cache.invalidate_range(addr, 1);
    assert_eq!(v.meta_cache.blocks(), 0);
    poison(&v, addr);
    assert_ne!(v.read_block(addr).unwrap(), first, "a forgotten block was still answered");
}

#[test]
fn resolving_the_same_inode_twice_reads_the_node_table_once() {
    // The mapping driven by a REAL path rather than by `read_block` directly:
    // resolving an inode consults the node table, and the second resolution of
    // the same inode must not pay the medium for the table block again. A
    // mapping nothing reached would pass every test above and change nothing.
    let mut v = volume();
    v.set_iostat_enabled(true);
    let read = crate::stats::iostat::Io::FsMetaRead as usize;
    v.root().unwrap();
    let once = v.counters().iostat.bytes[read];
    assert!(once > 0, "resolving an inode read no metadata at all");
    // The NODE mapping would answer the second resolution out of its own copy
    // of the inode block and never reach the table at all, which is a
    // different mapping's coverage. Dropped, so the question this test asks is
    // the one it says it asks: does the METADATA mapping hold the table block.
    let root = v.super_block().root_ino;
    v.node_cache().forget(root);
    v.root().unwrap();
    assert_eq!(v.counters().iostat.bytes[read], once,
               "the node table was read from the medium twice");
    assert!(v.meta_cache.hits() > 0);
}

#[test]
fn a_held_block_never_reaches_the_read_fault_site() {
    // The injected failure is the DEVICE's, and a block the mapping answered
    // submitted no request — so the site is not consulted and does not count.
    // The reference decides the same way by placing the injection inside the
    // submission the mapping's hit path never reaches.
    let v = volume();
    let addr = SIT_BLKADDR + 2;
    let held = v.read_block(addr).unwrap();
    v.set_fault(1, 0, crate::fault::Which::RATE).unwrap();
    v.set_fault(0, crate::fault::Fault::ReadIo.bit(), crate::fault::Which::TYPE).unwrap();
    assert_eq!(v.read_block(addr).unwrap(), held, "a held block was failed by the device's site");
    assert_eq!(v.fault_info().count(crate::fault::Fault::ReadIo), 0,
               "the site was consulted for an I/O that never happened");
    // The control: an address the mapping does not hold still fails, so the
    // site is armed and the case above is not simply a disarmed mount.
    assert_eq!(v.read_block(MAIN_BLKADDR), Err(syscall::errno::Errno::Eio));
    assert_eq!(v.fault_info().count(crate::fault::Fault::ReadIo), 1);
}

#[test]
fn a_remount_starts_with_an_empty_mapping() {
    // What a mapping holds is one mount's, and a mount is the only proof a
    // write landed: a held block surviving into the next mount would let a
    // change that never reached the medium read back as if it had.
    let v = volume();
    v.read_block(NAT_BLKADDR).unwrap();
    assert!(v.meta_cache.blocks() > 0);
    let src = v.into_source();
    let v2 = Volume::mount_with(src, crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(v2.meta_cache.blocks(), 0);
}
