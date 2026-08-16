//! Claiming clusters: the scan order, the wrap, and the shortfall.

use super::geo;
use crate::chain;
use crate::cluster_alloc::{alloc_clusters, allocate, count_free, end_mark, free_chain,
    write_entry};
use crate::fsinfo::FreeState;
use crate::geometry::{FatWidth, FAT_START_ENT};
use ::alloc::vec;
use syscall::errno::Errno;

/// The scan starts AFTER the previous allocation's last cluster, so repeated
/// allocations walk forward instead of rescanning the same head.
#[test]
fn the_scan_starts_after_the_hint() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    st.set_hint(5);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 3), Ok(vec![6, 7, 8]));
    assert_eq!(st.hint(), 8, "the hint followed the last cluster taken");
    // The next request continues from there rather than going back to 2.
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 2), Ok(vec![9, 10]));
}

/// A fresh state's hint is the first data cluster, so the reference's first
/// allocation on an empty volume begins at the cluster AFTER it.
#[test]
fn a_fresh_state_starts_one_past_the_first_data_cluster() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    assert_eq!(st.hint(), FAT_START_ENT);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 2), Ok(vec![3, 4]));
}

/// The search WRAPS. A volume whose tail is full still allocates from its
/// head; without the wrap it reports ENOSPC with the volume half empty.
#[test]
fn the_search_wraps_so_a_full_tail_still_allocates() {
    let (g, mut t) = geo(FatWidth::Fat16);
    for cluster in 10..g.max_cluster { write_entry(g.width, &mut t, cluster, end_mark(g.width)).unwrap(); }
    let mut st = FreeState::new();
    st.set_hint(g.max_cluster - 5);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 2), Ok(vec![2, 3]), "wrapped to the head");
}

/// Entries are marked AS THEY ARE FOUND, not decided first and committed
/// second: the state's hint and free count move with each cluster taken.
#[test]
fn each_cluster_is_marked_as_it_is_found() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    st.set_counted(count_free(&g, &t));
    let total = st.free_clusters().unwrap();
    let got = alloc_clusters(&g, &mut t, &mut st, 4).expect("allocate");
    assert_eq!(st.free_clusters(), Some(total - 4), "the count dropped per cluster");
    assert_eq!(st.hint(), *got.last().unwrap());
    assert!(st.is_dirty(), "the information sector needs rewriting");
    // Every claimed entry is live in the table, and the run is one chain.
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(got.clone()));
}

/// An allocation that cannot be satisfied gives back everything it claimed.
///
/// The reference marks entries as it goes and then, on the shortfall, frees
/// the partial chain from its first cluster — so the table ends byte-identical
/// to how it started and nothing is leaked.
#[test]
fn a_shortfall_gives_back_everything_it_claimed() {
    let (g, mut t) = geo(FatWidth::Fat16);
    for cluster in 4..g.max_cluster { write_entry(g.width, &mut t, cluster, end_mark(g.width)).unwrap(); }
    let before = t.clone();
    let mut st = FreeState::new();
    st.set_hint(g.max_cluster - 1);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 5).err(), Some(Errno::Enospc), "only two are free");
    assert_eq!(t, before, "every claimed cluster came back");
    // ...and the two that ARE free can still be had.
    st.set_hint(g.max_cluster - 1);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 2).map(|v| v.len()), Ok(2));
}

/// After a shortfall the free count is known EXACTLY, not left stale: the scan
/// just proved how many clusters the volume has.
#[test]
fn a_shortfall_leaves_the_free_count_exact_and_trusted() {
    let (g, mut t) = geo(FatWidth::Fat16);
    for cluster in 4..g.max_cluster { write_entry(g.width, &mut t, cluster, end_mark(g.width)).unwrap(); }
    let mut st = FreeState::new();
    st.set_hint(g.max_cluster - 1);
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 5).err(), Some(Errno::Enospc));
    assert!(st.is_trusted(), "the count is now derived, not inherited");
    assert_eq!(st.trusted_count(), Some(2), "the two it gave back");
    assert_eq!(st.trusted_count(), Some(count_free(&g, &t)), "and it agrees with a scan");
}

/// A trusted count smaller than the request refuses WITHOUT scanning and
/// without touching the table or the hint.
#[test]
fn a_trusted_short_count_refuses_before_scanning() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let before = t.clone();
    let mut st = FreeState::new();
    st.set_counted(3);
    st.clear_dirty();
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 4).err(), Some(Errno::Enospc));
    assert_eq!(t, before, "nothing was scanned or claimed");
    assert_eq!(st.hint(), FAT_START_ENT, "the hint did not move");
    assert!(!st.is_dirty(), "and the information sector was not dirtied");
}

/// An UNTRUSTED count that is too small does not refuse: the stored number may
/// be stale, so the scan settles it.
#[test]
fn an_untrusted_short_count_still_scans() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let mut st = FreeState::new();
    st.adopt(&crate::fsinfo::FsInfo { free_clusters: Some(1), next_cluster: Some(2),
                                      trailer_ok: true }, false);
    assert_eq!(st.free_clusters(), Some(1));
    assert!(!st.is_trusted());
    assert_eq!(alloc_clusters(&g, &mut t, &mut st, 4).map(|v| v.len()), Ok(4));
}

/// A fresh allocation is a chain the reader walks in order and ends.
#[test]
fn an_allocated_run_is_a_walkable_chain() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(got, vec![2, 3, 4]);
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(vec![2, 3, 4]));
}

/// Appending attaches to an existing chain's last cluster, and the whole thing
/// walks as one.
#[test]
fn appending_extends_an_existing_chain() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let first = allocate(&g, &mut t, 0, 2, None).expect("allocate");
    let more = allocate(&g, &mut t, *first.last().unwrap(), 2, Some(*first.last().unwrap()))
        .expect("append");
    let whole = chain::walk(&g, &t, first[0]).expect("walk");
    assert_eq!(whole, vec![first[0], first[1], more[0], more[1]]);
}

/// Two allocations never hand out the same cluster, which is the failure that
/// silently corrupts two files at once.
#[test]
fn two_allocations_never_overlap() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let a = allocate(&g, &mut t, 0, 4, None).expect("a");
    let b = allocate(&g, &mut t, *a.last().unwrap(), 4, None).expect("b");
    for cluster in &b { assert!(!a.contains(cluster), "cluster {cluster} handed out twice"); }
}

/// A twelve-bit volume allocates, walks and frees through its shared bytes.
#[test]
fn a_twelve_bit_volume_allocates_and_frees_correctly() {
    let (g, mut t) = geo(FatWidth::Fat12);
    let got = allocate(&g, &mut t, 0, 4, None).expect("allocate");
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(got.clone()));
    assert_eq!(free_chain(&g, &mut t, got[0]), Ok(4));
    assert_eq!(count_free(&g, &t), g.total_clusters, "every cluster free again");
}

/// Asking for nothing succeeds and changes nothing.
#[test]
fn allocating_nothing_is_a_no_op() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let before = t.clone();
    assert_eq!(allocate(&g, &mut t, 0, 0, None), Ok(vec![]));
    assert_eq!(t, before);
}

/// The state-free wrapper's "no hint" convention reaches the first data
/// cluster by wrapping, which is the only way the reference's scan gets there.
#[test]
fn the_stateless_wrapper_treats_a_low_hint_as_no_hint() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, mut t) = geo(width);
        assert_eq!(allocate(&g, &mut t, 0, 3, None), Ok(vec![2, 3, 4]), "{width:?}");
    }
}
