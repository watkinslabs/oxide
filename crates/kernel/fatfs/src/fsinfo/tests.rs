//! The information sector, and the free-cluster accounting it seeds.

use super::layout::{encode, off, parse, sector_number, write_back, FSINFO_FREE_UNKNOWN,
    FSINFO_MIN_BYTES, FSINFO_SIG1, FSINFO_SIG2, FSINFO_TRAIL_SIG};
use super::state::FreeState;
use super::FsInfo;
use crate::bpb::Bpb;
use crate::geometry::{resolve, Geometry, FAT_START_ENT};
use alloc::vec;
use alloc::vec::Vec;

fn volume() -> Geometry {
    let b = Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1, dir_entries: 0,
        media: 0xf8, fat_length16: 0, fat_length32: 256, total_sect16: 0, total_sect32: 20_000,
        root_cluster: 2, fsinfo_sector: 1 };
    resolve(&b).expect("valid volume")
}

fn sector(free: Option<u32>, next: Option<u32>) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    assert!(encode(&mut s, free, next));
    s
}

/// A well-formed sector yields both counters.
#[test]
fn a_valid_sector_yields_both_counters() {
    let s = sector(Some(1234), Some(56));
    let got = parse(&s).expect("valid");
    assert_eq!(got.free_clusters, Some(1234));
    assert_eq!(got.next_cluster, Some(56));
    assert!(got.trailer_ok);
}

/// Either guarding signature being wrong rejects the sector outright — the
/// counters in it belong to something else.
#[test]
fn a_wrong_signature_rejects_the_sector() {
    for at in [off::SIG1, off::SIG2] {
        let mut s = sector(Some(1), Some(2));
        s[at] ^= 0xFF;
        assert!(parse(&s).is_none(), "signature at {at}");
    }
}

/// The TRAILING signature is reported, not enforced. Rejecting on it would
/// discard usable state on media whose formatter omitted it, and the reference
/// never looks at it.
#[test]
fn a_wrong_trailing_signature_is_reported_not_enforced() {
    let mut s = sector(Some(9), Some(3));
    s[off::TRAIL_SIG] ^= 0xFF;
    let got = parse(&s).expect("still accepted");
    assert!(!got.trailer_ok, "but the caller can see it");
    assert_eq!(got.free_clusters, Some(9), "and the counters are still usable");
    assert_eq!(FSINFO_TRAIL_SIG, 0xAA55_0000);
}

/// The unknown sentinel is not a count. Reading it as one would report a
/// four-billion-cluster volume as nearly empty.
#[test]
fn the_unknown_sentinel_is_not_a_count() {
    let mut s = sector(None, None);
    let got = parse(&s).expect("valid");
    assert_eq!(got.free_clusters, None);
    assert_eq!(got.next_cluster, None);
    let raw = u32::from_le_bytes([s[off::FREE_CLUSTERS], s[off::FREE_CLUSTERS + 1],
                                  s[off::FREE_CLUSTERS + 2], s[off::FREE_CLUSTERS + 3]]);
    assert_eq!(raw, FSINFO_FREE_UNKNOWN, "and that IS what the sector holds");
    s[off::FREE_CLUSTERS] = 0xFE;
    assert_eq!(parse(&s).unwrap().free_clusters, Some(0xFFFF_FFFE), "one below is a real count");
}

/// A sector too short to hold the fields is rejected rather than read past.
#[test]
fn a_short_sector_is_rejected() {
    let s = vec![0u8; FSINFO_MIN_BYTES - 1];
    assert!(parse(&s).is_none());
    let mut short = vec![0u8; 16];
    assert!(!encode(&mut short, Some(1), Some(2)));
}

/// The boot sector's zero means "not stated", not sector zero — sector zero is
/// the boot sector itself.
#[test]
fn a_declared_sector_of_zero_means_sector_one() {
    assert_eq!(sector_number(0), 1);
    assert_eq!(sector_number(1), 1);
    assert_eq!(sector_number(6), 6);
}

/// Writing back updates the counters in place and leaves the signatures.
#[test]
fn writing_back_updates_the_counters_in_place() {
    let mut s = sector(Some(1), Some(2));
    assert!(write_back(&mut s, Some(4242), Some(77)));
    let got = parse(&s).expect("still valid");
    assert_eq!(got.free_clusters, Some(4242));
    assert_eq!(got.next_cluster, Some(77));
    assert_eq!(u32::from_le_bytes([s[0], s[1], s[2], s[3]]), FSINFO_SIG1);
    assert_eq!(u32::from_le_bytes([s[off::SIG2], s[off::SIG2 + 1], s[off::SIG2 + 2],
                                   s[off::SIG2 + 3]]), FSINFO_SIG2);
}

/// A counter this volume does not know is left as it was found rather than
/// replaced with the sentinel: a stale value is no worse, and the reference
/// writes only what it knows.
#[test]
fn an_unknown_counter_is_left_alone() {
    let mut s = sector(Some(500), Some(9));
    assert!(write_back(&mut s, None, Some(11)));
    let got = parse(&s).expect("valid");
    assert_eq!(got.free_clusters, Some(500), "untouched");
    assert_eq!(got.next_cluster, Some(11));
}

/// An unrecognised sector is never overwritten — whatever it holds is not ours.
#[test]
fn an_invalid_sector_is_not_written_back() {
    let mut s = sector(Some(1), Some(2));
    s[off::SIG2] ^= 0xFF;
    let before = s.clone();
    assert!(!write_back(&mut s, Some(9), Some(9)));
    assert_eq!(s, before);
}

/// A fresh volume knows nothing and starts its search at the first data
/// cluster.
#[test]
fn a_fresh_state_knows_nothing() {
    let st = FreeState::new();
    assert_eq!(st.free_clusters(), None);
    assert!(!st.is_trusted());
    assert_eq!(st.hint(), FAT_START_ENT);
    assert!(!st.is_dirty());
}

/// Adopting the sector's counters records both, and trusts the count only when
/// asked to.
#[test]
fn adoption_records_both_and_trusts_only_on_request() {
    let info = FsInfo { free_clusters: Some(100), next_cluster: Some(40), trailer_ok: true };
    let mut untrusted = FreeState::new();
    untrusted.adopt(&info, false);
    assert_eq!(untrusted.free_clusters(), Some(100));
    assert_eq!(untrusted.trusted_count(), None, "recorded but not actionable");
    assert_eq!(untrusted.hint(), 40, "the hint is used either way");

    let mut trusted = FreeState::new();
    trusted.adopt(&info, true);
    assert_eq!(trusted.trusted_count(), Some(100));
}

/// A count larger than the volume has clusters is impossible, so it is thrown
/// away rather than clamped: a wrong number is worse than none.
#[test]
fn an_impossible_count_is_discarded() {
    let g = volume();
    let mut st = FreeState::new();
    st.adopt(&FsInfo { free_clusters: Some(g.total_clusters + 1), next_cluster: Some(3),
                       trailer_ok: true }, true);
    st.sanitize(&g);
    assert_eq!(st.free_clusters(), None);

    let mut exact = FreeState::new();
    exact.adopt(&FsInfo { free_clusters: Some(g.total_clusters), next_cluster: Some(3),
                          trailer_ok: true }, true);
    exact.sanitize(&g);
    assert_eq!(exact.free_clusters(), Some(g.total_clusters), "the exact total is possible");
}

/// A hint outside the volume is wrapped into range rather than discarded: any
/// cluster is a legitimate place to start searching.
#[test]
fn an_out_of_range_hint_is_wrapped_into_range() {
    let g = volume();
    let mut st = FreeState::new();
    st.adopt(&FsInfo { free_clusters: None, next_cluster: Some(g.max_cluster + 5),
                       trailer_ok: true }, false);
    st.sanitize(&g);
    assert_eq!(st.hint(), 5);

    let mut low = FreeState::new();
    low.adopt(&FsInfo { free_clusters: None, next_cluster: Some(0), trailer_ok: true }, false);
    low.sanitize(&g);
    assert_eq!(low.hint(), FAT_START_ENT, "below the first data cluster is not a hint");
}

/// A sentinel hint leaves the default rather than becoming a huge number.
#[test]
fn a_sentinel_hint_leaves_the_default() {
    let g = volume();
    let mut st = FreeState::new();
    st.adopt(&FsInfo { free_clusters: None, next_cluster: None, trailer_ok: true }, false);
    st.sanitize(&g);
    assert_eq!(st.hint(), FAT_START_ENT);
}

/// An unknown count stays unknown across allocation and freeing rather than
/// becoming a guess counted from nothing.
#[test]
fn an_unknown_count_stays_unknown() {
    let mut st = FreeState::new();
    st.took(9);
    st.gave_back();
    assert_eq!(st.free_clusters(), None);
    assert_eq!(st.hint(), 9, "the hint moves regardless");
}

/// A derived count is trusted and wants writing back; a write-back clears that.
#[test]
fn a_derived_count_is_trusted_and_dirty() {
    let mut st = FreeState::new();
    st.set_counted(42);
    assert_eq!(st.trusted_count(), Some(42));
    assert!(st.is_dirty());
    st.clear_dirty();
    assert!(!st.is_dirty());
}
