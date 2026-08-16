//! Releasing and truncating, including chains a corrupt table produced.
use ::alloc::vec;

use super::geo;
use crate::chain::{self, Link};
use crate::cluster_alloc::{allocate, count_free, end_mark, free_chain, free_chain_state,
    truncate_chain, truncate_chain_state, write_entry};
use crate::fsinfo::FreeState;
use crate::geometry::{FatWidth, Geometry};
use syscall::errno::Errno;

fn link(g: &Geometry, t: &[u8], cluster: u32) -> Option<Link> { chain::read_entry(g.width, t, cluster) }

/// Freeing a chain returns its clusters to the pool, and they are handed out
/// again rather than lost.
#[test]
fn a_freed_chain_becomes_allocatable_again() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let before = count_free(&g, &t);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(count_free(&g, &t), before - 3);
    assert_eq!(free_chain(&g, &mut t, got[0]), Ok(3));
    assert_eq!(count_free(&g, &t), before, "every cluster came back");
}

/// Freeing counts each cluster back into the running free total as it goes.
#[test]
fn freeing_maintains_the_running_free_count() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    st.set_counted(count_free(&g, &t));
    let total = st.free_clusters().unwrap();
    let got = crate::cluster_alloc::alloc_clusters(&g, &mut t, &mut st, 3).expect("allocate");
    assert_eq!(st.free_clusters(), Some(total - 3));
    assert_eq!(free_chain_state(&g, &mut t, &mut st, got[0]), Ok(3));
    assert_eq!(st.free_clusters(), Some(total), "back where it started");
    assert_eq!(st.free_clusters(), Some(count_free(&g, &t)), "and it agrees with a scan");
}

/// A CIRCULAR chain terminates rather than spinning: releasing as the walk
/// goes means the loop's own head reads as free when it comes back round, and
/// a free entry mid-chain is a corrupt table.
#[test]
fn a_circular_chain_errors_instead_of_looping() {
    let (g, mut t) = geo(FatWidth::Fat16);
    write_entry(g.width, &mut t, 2, 3).unwrap();
    write_entry(g.width, &mut t, 3, 4).unwrap();
    write_entry(g.width, &mut t, 4, 2).unwrap();
    assert_eq!(free_chain(&g, &mut t, 2), Err(Errno::Eio));
    // What it did release stays released, which is the reference's outcome.
    for cluster in [2u32, 3, 4] { assert_eq!(link(&g, &t, cluster), Some(Link::Free)); }
}

/// A link naming a cluster this volume does not have is refused, not followed.
#[test]
fn a_link_past_the_volume_is_refused() {
    let (g, mut t) = geo(FatWidth::Fat16);
    write_entry(g.width, &mut t, 2, g.max_cluster).unwrap();
    assert_eq!(free_chain(&g, &mut t, 2), Err(Errno::Eio));
    assert_eq!(free_chain(&g, &mut t, g.max_cluster), Err(Errno::Eio), "and so is the start");
    assert_eq!(free_chain(&g, &mut t, 1), Err(Errno::Eio), "including a reserved entry");
}

/// Entry number one is a link to a reserved number, not an end-of-chain: the
/// reference hands it back and lets the walker refuse it, so a corrupt table
/// errors rather than making a file silently end early.
#[test]
fn a_link_to_the_reserved_entry_errors() {
    let (g, mut t) = geo(FatWidth::Fat16);
    write_entry(g.width, &mut t, 2, 1).unwrap();
    assert_eq!(chain::classify(g.width, 1), Link::Next(1));
    assert_eq!(free_chain(&g, &mut t, 2), Err(Errno::Eio));
    assert_eq!(chain::walk(&g, &t, 2), Err(chain::ChainError::OutOfRange));
}

/// A free entry found part-way along a chain is a corrupt table: the file
/// claims a cluster the volume says nobody owns.
#[test]
fn a_free_entry_mid_chain_errors() {
    let (g, mut t) = geo(FatWidth::Fat16);
    write_entry(g.width, &mut t, 2, 3).unwrap();
    assert_eq!(free_chain(&g, &mut t, 2), Err(Errno::Eio));
}

/// Truncation keeps the head, ends it, and releases the tail — and a reader
/// stopping between the two never follows a link into a freed cluster.
#[test]
fn truncation_ends_the_survivor_and_frees_the_rest() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 5, None).expect("allocate");
    assert_eq!(truncate_chain(&g, &mut t, got[0], 2), Ok(3));
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(vec![got[0], got[1]]));
    for cluster in &got[2..] {
        assert_eq!(link(&g, &t, *cluster), Some(Link::Free), "cluster {cluster} was released");
    }
}

/// Truncating to nothing releases the whole chain.
#[test]
fn truncating_to_nothing_releases_everything() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(truncate_chain(&g, &mut t, got[0], 0), Ok(3));
    for cluster in &got { assert_eq!(link(&g, &t, *cluster), Some(Link::Free)); }
}

/// Truncating to more than a chain holds changes nothing.
#[test]
fn truncating_past_the_end_is_a_no_op() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 2, None).expect("allocate");
    let before = t.clone();
    assert_eq!(truncate_chain(&g, &mut t, got[0], 9), Ok(0));
    assert_eq!(t, before);
}

/// Truncating to exactly the chain's length changes nothing either — the
/// survivor already carries an end.
#[test]
fn truncating_to_the_exact_length_is_a_no_op() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    let before = t.clone();
    assert_eq!(truncate_chain(&g, &mut t, got[0], 3), Ok(0));
    assert_eq!(t, before);
}

/// Truncation counts the released clusters back into the running total.
#[test]
fn truncation_maintains_the_running_free_count() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    st.set_counted(count_free(&g, &t));
    let got = crate::cluster_alloc::alloc_clusters(&g, &mut t, &mut st, 5).expect("allocate");
    let after_alloc = st.free_clusters().unwrap();
    assert_eq!(truncate_chain_state(&g, &mut t, &mut st, got[0], 2), Ok(3));
    assert_eq!(st.free_clusters(), Some(after_alloc + 3));
    assert_eq!(st.free_clusters(), Some(count_free(&g, &t)));
}

/// Every width releases through its own entry encoding.
#[test]
fn every_width_frees_a_whole_chain() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, mut t) = geo(width);
        let got = allocate(&g, &mut t, 0, 6, None).expect("allocate");
        assert_eq!(free_chain(&g, &mut t, got[0]), Ok(6), "{width:?}");
        assert_eq!(count_free(&g, &t), g.total_clusters, "{width:?}");
    }
}

/// A chain ending on the bad-cluster mark ends rather than failing: the
/// reference folds bad and every reserved value above it into end-of-chain.
#[test]
fn a_chain_ending_on_the_bad_mark_still_frees() {
    let (g, mut t) = geo(FatWidth::Fat16);
    write_entry(g.width, &mut t, 2, 3).unwrap();
    write_entry(g.width, &mut t, 3, chain::BAD_FAT16).unwrap();
    assert_eq!(link(&g, &t, 3), Some(Link::End));
    assert_eq!(free_chain(&g, &mut t, 2), Ok(2));
    let _ = end_mark(g.width);
}
