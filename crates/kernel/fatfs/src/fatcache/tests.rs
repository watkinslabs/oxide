//! Remembered chain positions.

use super::lru::{ChainCache, FAT_MAX_CACHE};
use super::seek::{get_cluster, Seek, TO_EOF};
use crate::bpb::Bpb;
use crate::cluster_alloc::{allocate, end_mark, write_entry};
use crate::geometry::{resolve, FatWidth, Geometry};
use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;

fn volume() -> (Geometry, Vec<u8>) {
    let b = Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1, dir_entries: 16,
        media: 0xf8, fat_length16: 64, fat_length32: 0, total_sect16: 0, total_sect32: 20_000,
        root_cluster: 0, fsinfo_sector: 0 };
    let g = resolve(&b).expect("valid volume");
    assert_eq!(g.width, FatWidth::Fat16);
    let t = vec![0u8; (g.fat_length * g.sector_size) as usize];
    (g, t)
}

/// Lay a chain of `clusters` in the given order, ending it.
fn lay(g: &Geometry, t: &mut [u8], clusters: &[u32]) {
    for (i, c) in clusters.iter().enumerate() {
        let value = match clusters.get(i + 1) { Some(n) => *n, None => end_mark(g.width) };
        write_entry(g.width, t, *c, value).unwrap();
    }
}

/// The Nth cluster of a contiguous chain is the one the walk reaches.
#[test]
fn a_walk_reaches_the_offset_asked_for() {
    let (g, mut t) = volume();
    let got = allocate(&g, &mut t, 0, 10, None).expect("allocate");
    let mut cache = ChainCache::new();
    for (n, want) in got.iter().enumerate() {
        assert_eq!(get_cluster(&g, &t, &mut cache, got[0], n as u32),
                   Ok(Seek::At { fclus: n as u32, dclus: *want }));
    }
}

/// Offset zero is the chain's own start and costs nothing.
#[test]
fn offset_zero_is_the_start() {
    let (g, mut t) = volume();
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    let mut cache = ChainCache::new();
    assert_eq!(get_cluster(&g, &t, &mut cache, got[0], 0),
               Ok(Seek::At { fclus: 0, dclus: got[0] }));
    assert!(cache.is_empty(), "and remembers nothing");
}

/// Walking past the chain's end reports the LAST cluster, which is what a
/// caller appending to the chain needs.
#[test]
fn walking_past_the_end_reports_the_last_cluster() {
    let (g, mut t) = volume();
    let got = allocate(&g, &mut t, 0, 4, None).expect("allocate");
    let mut cache = ChainCache::new();
    assert_eq!(get_cluster(&g, &t, &mut cache, got[0], TO_EOF),
               Ok(Seek::Eof { fclus: 3, dclus: got[3] }));
    assert_eq!(get_cluster(&g, &t, &mut cache, got[0], 99),
               Ok(Seek::Eof { fclus: 3, dclus: got[3] }));
}

/// A contiguous chain collapses into ONE remembered run, however long it is.
/// That is the case the cache exists for.
#[test]
fn a_contiguous_chain_becomes_one_remembered_run() {
    let (g, mut t) = volume();
    let got = allocate(&g, &mut t, 0, 40, None).expect("allocate");
    let mut cache = ChainCache::new();
    get_cluster(&g, &t, &mut cache, got[0], 39).expect("walk");
    assert_eq!(cache.len(), 1, "one run covers the whole thing");
    // And it answers every offset inside that run without rewalking.
    assert_eq!(get_cluster(&g, &t, &mut cache, got[0], 25),
               Ok(Seek::At { fclus: 25, dclus: got[25] }));
}

/// A remembered position resumes the walk part-way rather than from the start,
/// which is the whole point: a table changed only BEFORE the cached position
/// cannot affect the answer.
#[test]
fn a_remembered_position_resumes_the_walk() {
    let (g, mut t) = volume();
    // Two runs: 2..6 then a jump to 40..44, so a position exists at offset 4.
    lay(&g, &mut t, &[2, 3, 4, 5, 40, 41, 42, 43]);
    let mut cache = ChainCache::new();
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, 7), Ok(Seek::At { fclus: 7, dclus: 43 }));
    assert_eq!(cache.len(), 1, "the second run was remembered");

    // Break the FIRST run's links. A walk from the start would now fail; a
    // walk resuming from the remembered position still answers.
    write_entry(g.width, &mut t, 3, 0).unwrap();
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, 6), Ok(Seek::At { fclus: 6, dclus: 42 }));
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, 2), Err(Errno::Eio), "but an early offset walks");
}

/// Invalidation drops every position AND stops a walk still in flight from
/// reinstating one — a position naming clusters the file no longer owns would
/// be a read of another file's data.
#[test]
fn invalidation_also_discards_a_walk_already_in_flight() {
    let (g, mut t) = volume();
    lay(&g, &mut t, &[2, 3, 4, 5, 40, 41, 42, 43]);
    let mut cache = ChainCache::new();
    get_cluster(&g, &t, &mut cache, 2, 7).expect("walk");
    assert_eq!(cache.len(), 1);

    // A walk that starts now takes a position stamped with this generation.
    let (_, _, stale) = cache.lookup(7).expect("hit");
    cache.invalidate();
    assert!(cache.is_empty(), "everything forgotten");
    cache.add(&stale);
    assert!(cache.is_empty(), "and the in-flight position was refused");
}

/// The set is bounded: a chain of many runs keeps the reference's maximum and
/// no more.
#[test]
fn the_remembered_set_is_bounded() {
    let (g, mut t) = volume();
    // Alternate forward jumps so no two consecutive clusters are contiguous.
    let mut chain: Vec<u32> = Vec::new();
    let mut c = 2u32;
    for i in 0..40 { chain.push(c); c += if i % 2 == 0 { 7 } else { 3 }; }
    lay(&g, &mut t, &chain);
    let mut cache = ChainCache::new();
    for n in 0..chain.len() as u32 {
        get_cluster(&g, &t, &mut cache, chain[0], n).expect("walk");
    }
    assert!(cache.len() <= FAT_MAX_CACHE, "held {} positions", cache.len());
    assert_eq!(FAT_MAX_CACHE, 8);
    // Bounded or not, every answer is still right.
    for (n, want) in chain.iter().enumerate() {
        assert_eq!(get_cluster(&g, &t, &mut cache, chain[0], n as u32).map(|s| s.dclus()),
                   Ok(*want), "offset {n}");
    }
}

/// A CIRCULAR chain errors rather than spinning: no honest chain visits more
/// clusters than the volume has.
#[test]
fn a_circular_chain_errors_instead_of_looping() {
    let (g, mut t) = volume();
    write_entry(g.width, &mut t, 2, 3).unwrap();
    write_entry(g.width, &mut t, 3, 4).unwrap();
    write_entry(g.width, &mut t, 4, 2).unwrap();
    let mut cache = ChainCache::new();
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, TO_EOF), Err(Errno::Eio));
}

/// A free entry part-way along, a link off the volume, and a start that is not
/// a data cluster are all corrupt tables and all error.
#[test]
fn corrupt_links_error() {
    let (g, mut t) = volume();
    let mut cache = ChainCache::new();
    assert_eq!(get_cluster(&g, &t, &mut cache, 1, 1), Err(Errno::Eio), "reserved start");
    assert_eq!(get_cluster(&g, &t, &mut cache, g.max_cluster, 1), Err(Errno::Eio), "start off the end");
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, 1), Err(Errno::Eio), "free entry mid-chain");
    write_entry(g.width, &mut t, 2, g.max_cluster).unwrap();
    assert_eq!(get_cluster(&g, &t, &mut cache, 2, 1), Err(Errno::Eio), "link off the end");
}
