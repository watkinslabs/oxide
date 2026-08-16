//! Establishing and maintaining the free-cluster total.

use super::geo;
use crate::cluster_alloc::{alloc_clusters, count_free, count_free_clusters, free_chain_state};
use crate::fsinfo::{FreeState, FsInfo};
use crate::geometry::FatWidth;

/// An empty volume's every data cluster is free.
#[test]
fn an_empty_volume_counts_every_data_cluster() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, t) = geo(width);
        assert_eq!(count_free(&g, &t), g.total_clusters, "{width:?}");
    }
}

/// With no trusted count, the total is derived by scanning — and the result is
/// trusted from then on, so a second question costs nothing.
#[test]
fn an_untrusted_volume_scans_once_and_then_remembers() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    assert!(st.trusted_count().is_none(), "nothing to act on yet");
    let first = count_free_clusters(&g, &t, &mut st);
    assert_eq!(first, g.total_clusters);
    assert!(st.is_trusted());
    assert!(st.is_dirty(), "a derived count is worth writing back");

    // The stored count is now the answer: a table changed behind its back does
    // not change it, which is exactly the reference's trade.
    alloc_clusters(&g, &mut t, &mut st, 3).expect("allocate");
    st.clear_dirty();
    let second = count_free_clusters(&g, &t, &mut st);
    assert_eq!(second, g.total_clusters - 3, "maintained, not rescanned");
    assert!(!st.is_dirty(), "and no scan happened");
}

/// A count read from the information sector is NOT acted on unless the mount
/// asked for it to be trusted; without that it is re-derived.
#[test]
fn a_stored_count_is_rederived_unless_it_is_trusted() {
    let (g, t) = geo(FatWidth::Fat16);
    let lie = FsInfo { free_clusters: Some(7), next_cluster: Some(2), trailer_ok: true };

    let mut untrusted = FreeState::new();
    untrusted.adopt(&lie, false);
    untrusted.sanitize(&g);
    assert_eq!(untrusted.free_clusters(), Some(7), "the number is kept");
    assert_eq!(count_free_clusters(&g, &t, &mut untrusted), g.total_clusters, "but not believed");

    let mut trusted = FreeState::new();
    trusted.adopt(&lie, true);
    trusted.sanitize(&g);
    assert_eq!(count_free_clusters(&g, &t, &mut trusted), 7, "believed, wrong or not");
}

/// Allocating and freeing keep the maintained total equal to a fresh scan.
#[test]
fn maintenance_tracks_a_scan_exactly() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, mut t) = geo(width);
        let mut st = FreeState::new();
        count_free_clusters(&g, &t, &mut st);
        let a = alloc_clusters(&g, &mut t, &mut st, 5).expect("a");
        let b = alloc_clusters(&g, &mut t, &mut st, 7).expect("b");
        assert_eq!(st.free_clusters(), Some(count_free(&g, &t)), "{width:?} after allocating");
        free_chain_state(&g, &mut t, &mut st, a[0]).expect("free a");
        assert_eq!(st.free_clusters(), Some(count_free(&g, &t)), "{width:?} after freeing");
        free_chain_state(&g, &mut t, &mut st, b[0]).expect("free b");
        assert_eq!(st.free_clusters(), Some(g.total_clusters), "{width:?} back to empty");
    }
}
