// The destination metrics cache: what it keeps, what it refuses to keep, how
// it ages out, how a chain stops growing, and how a path's metrics and its
// fast-open state share one row.

use super::*;
use crate::addr::{Ipv4Addr, Ipv6Addr};

const NOW: u64 = 10 * NS_PER_SEC;

fn src() -> IpAddr { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)) }
fn dst() -> IpAddr { IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)) }
fn other() -> IpAddr { IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)) }

fn cookie(byte: u8) -> Cookie { Cookie::minted([byte; 8], false) }

#[test]
fn a_learned_cookie_is_returned_for_the_same_pair() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 1400, Some(cookie(1)), false, TRY_EXP_NONE);
    let got = cache.get(src(), dst(), NOW);
    assert_eq!(got.cookie, Some(cookie(1)));
    assert_eq!(got.mss, 1400, "a SYN carrying data must be sized before the SYN-ACK sizes it");
}

#[test]
fn a_cookie_names_the_host_pair_so_a_different_source_is_a_different_entry() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, Some(cookie(1)), false, TRY_EXP_NONE);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    assert_eq!(cache.get(elsewhere, dst(), NOW).cookie, None);
    assert_eq!(cache.get(src(), other(), NOW).cookie, None);
}

#[test]
fn a_miss_reads_as_no_cookie_rather_than_as_an_error() {
    assert_eq!(MetricsCache::new().get(src(), dst(), NOW), Cached::default());
}

#[test]
fn a_later_cookie_replaces_the_one_held() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, Some(cookie(1)), false, TRY_EXP_NONE);
    cache.set(src(), dst(), NOW + 1, 0, Some(cookie(2)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), dst(), NOW + 1).cookie, Some(cookie(2)));
}

#[test]
fn a_handshake_that_learned_nothing_leaves_the_held_cookie_alone() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, Some(cookie(1)), false, TRY_EXP_NONE);
    cache.set(src(), dst(), NOW + 1, 0, None, false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), dst(), NOW + 1).cookie, Some(cookie(1)));
}

#[test]
fn an_empty_cookie_is_the_absence_of_one_and_is_never_stored_as_one() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, Some(Cookie::request(false)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), dst(), NOW).cookie, None);
}

#[test]
fn the_request_kind_is_recorded_only_while_no_cookie_is_held() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, None, false, TRY_EXP_EXPERIMENTAL);
    assert!(cache.get(src(), dst(), NOW).try_exp);
    cache.set(src(), dst(), NOW, 0, Some(cookie(1)), false, TRY_EXP_NONE);
    cache.set(src(), dst(), NOW, 0, None, false, TRY_EXP_ASSIGNED);
    assert!(!cache.get(src(), dst(), NOW).try_exp,
        "a cookie in hand ends the search for a request kind that gets through");
}

#[test]
fn the_request_kind_only_ever_advances() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, None, false, TRY_EXP_ASSIGNED);
    cache.set(src(), dst(), NOW, 0, None, false, TRY_EXP_EXPERIMENTAL);
    assert!(!cache.get(src(), dst(), NOW).try_exp,
        "having settled on the assigned kind, a later suggestion of the older one is stale");
}

#[test]
fn recurring_unanswered_fast_open_syns_are_counted_and_a_success_clears_them() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 0, None, true, TRY_EXP_NONE);
    cache.set(src(), dst(), NOW, 0, None, true, TRY_EXP_NONE);
    assert_eq!(cache.syn_loss(src(), dst()), 2);
    cache.set(src(), dst(), NOW, 0, None, false, TRY_EXP_NONE);
    assert_eq!(cache.syn_loss(src(), dst()), 0);
}

#[test]
fn an_entry_past_the_staleness_horizon_reads_as_a_miss() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 1400, Some(cookie(1)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), dst(), NOW + ENTRY_TIMEOUT_NS - 1).cookie, Some(cookie(1)));
    assert_eq!(cache.get(src(), dst(), NOW + ENTRY_TIMEOUT_NS), Cached::default(),
        "a cookie that old names a key the server has rotated away from");
}

#[test]
fn a_stamp_from_a_future_clock_domain_fails_closed_as_a_miss() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW + 1, 1400, Some(cookie(1)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), dst(), NOW), Cached::default(),
        "a mismatched clock must not make a cookie look freshly learned");
}

#[test]
fn a_stale_entry_is_refreshed_empty_rather_than_amended() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 1400, Some(cookie(1)), true, TRY_EXP_NONE);
    let later = NOW + ENTRY_TIMEOUT_NS;
    cache.set(src(), dst(), later, 0, None, false, TRY_EXP_NONE);
    let got = cache.get(src(), dst(), later);
    assert_eq!(got.cookie, None);
    assert_eq!(got.mss, 0);
    assert_eq!(cache.syn_loss(src(), dst()), 0);
    assert_eq!(cache.chain_len(dst()), 1, "the entry was reused, not duplicated");
}

/// Destinations sharing a chain. The reference hashes the destination alone,
/// so this is built by finding real addresses that collide rather than by
/// reaching into the hash.
fn colliding(count: usize) -> alloc::vec::Vec<IpAddr> {
    let target = bucket(dst());
    let mut found = alloc::vec::Vec::new();
    for high in 0..=255u8 {
        for low in 0..=255u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, high, low));
            if bucket(ip) == target { found.push(ip); }
            if found.len() == count { return found; }
        }
    }
    panic!("the bucket count is small enough that collisions exist");
}

#[test]
fn a_chain_stops_growing_at_the_reclaim_depth() {
    let cache = MetricsCache::new();
    let peers = colliding(RECLAIM_DEPTH + 4);
    for (index, peer) in peers.iter().enumerate() {
        cache.set(src(), *peer, NOW + index as u64, 0, Some(cookie(index as u8 + 1)), false,
            TRY_EXP_NONE);
    }
    assert_eq!(cache.chain_len(peers[0]), RECLAIM_DEPTH + 1,
        "the walk that finds an entry is the walk that would evict, so it stays short");
}

#[test]
fn the_chain_reclaims_its_least_recently_refreshed_entry() {
    let cache = MetricsCache::new();
    let peers = colliding(RECLAIM_DEPTH + 2);
    for (index, peer) in peers.iter().enumerate() {
        cache.set(src(), *peer, NOW + index as u64, 0, Some(cookie(index as u8 + 1)), false,
            TRY_EXP_NONE);
    }
    // Everything held after the chain filled, refreshed newest-last; the one
    // that fell out is the one nothing touched most recently.
    let last = NOW + peers.len() as u64;
    assert_eq!(cache.get(src(), peers[0], last).cookie, None);
    for peer in &peers[1..] {
        assert!(cache.get(src(), *peer, last).cookie.is_some());
    }
}

#[test]
fn refreshing_an_entry_saves_it_from_the_next_reclaim() {
    let cache = MetricsCache::new();
    let peers = colliding(RECLAIM_DEPTH + 2);
    for (index, peer) in peers.iter().enumerate() {
        cache.set(src(), *peer, NOW + index as u64, 0, Some(cookie(index as u8 + 1)), false,
            TRY_EXP_NONE);
    }
    let touched = NOW + 100;
    cache.set(src(), peers[1], touched, 0, Some(cookie(99)), false, TRY_EXP_NONE);
    cache.set(src(), other(), touched + 1, 0, Some(cookie(50)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src(), peers[1], touched + 1).cookie, Some(cookie(99)));
}

#[test]
fn an_ipv6_destination_keeps_its_own_entry() {
    let cache = MetricsCache::new();
    let v6 = IpAddr::V6(Ipv6Addr::LOOPBACK);
    let src6 = IpAddr::V6(Ipv6Addr::ANY);
    cache.set(src6, v6, NOW, 0, Some(cookie(7)), false, TRY_EXP_NONE);
    assert_eq!(cache.get(src6, v6, NOW).cookie, Some(cookie(7)));
    assert_eq!(cache.get(src(), dst(), NOW).cookie, None);
}

/// The bucket array must stay a separate allocation. Inline it was 8192 B, and
/// embedding it in the per-namespace state gave that state's constructor a
/// stack frame over half the size of a kernel stack, on a path softirq receive
/// can reach. A handle is two words; anything near `BUCKETS * 32` means the
/// array moved back inline.
#[test]
fn the_bucket_array_is_not_stored_inline() {
    assert!(core::mem::size_of::<MetricsCache>() <= 32,
        "MetricsCache is {} B — the bucket array is inline again",
        core::mem::size_of::<MetricsCache>());
    assert_eq!(MetricsCache::new().chains.len(), BUCKETS);
}

fn conn() -> super::super::update::Closing {
    super::super::update::Closing {
        srtt: 50_000, mdev: 5_000, cwnd: 40, ssthresh: 20, reordering: 3,
        phase: super::super::update::Phase::Open, backing_off: false,
        no_ssthresh_save: false, default_reordering: 3,
    }
}

#[test]
fn a_destination_nothing_is_known_about_holds_no_metrics_and_vouches_for_nobody() {
    let cache = MetricsCache::new();
    assert!(cache.cached(src(), dst()).is_empty());
    assert!(!cache.peer_is_proven(src(), dst()));
}

#[test]
fn a_closed_connection_leaves_its_measurements_for_the_next_one() {
    let cache = MetricsCache::new();
    cache.record(src(), dst(), NOW, conn());
    let held = cache.cached(src(), dst());
    assert_eq!(held.get(ids::RTT), 50_000);
    assert_eq!(held.get(ids::CWND), 20, "the stored window and the measured one, averaged");
    assert!(cache.peer_is_proven(src(), dst()),
        "a stored round trip can only have come from a completed connection");
    // The record names one pair; a different destination is untouched.
    assert!(!cache.peer_is_proven(src(), other()));
}

#[test]
fn a_connection_that_measured_nothing_leaves_no_row_behind() {
    let cache = MetricsCache::new();
    cache.record(src(), dst(), NOW, super::super::update::Closing { srtt: 0, ..conn() });
    assert_eq!(cache.chain_len(dst()), 0, "an empty row reads the same as no row");
    assert!(!cache.peer_is_proven(src(), dst()));
    // On an existing row it clears the round trip and nothing else.
    cache.record(src(), dst(), NOW, conn());
    cache.record(src(), dst(), NOW, super::super::update::Closing { srtt: 0, ..conn() });
    assert!(!cache.peer_is_proven(src(), dst()));
    assert_eq!(cache.cached(src(), dst()).get(ids::CWND), 20);
}

#[test]
fn a_pinned_metric_survives_the_connections_that_follow_it() {
    let cache = MetricsCache::new();
    let mut vals = [None; ids::COUNT];
    vals[ids::CWND] = Some(99);
    cache.pin(src(), dst(), NOW, vals);
    assert_eq!(cache.cached(src(), dst()).get(ids::CWND), 99);
    assert!(cache.cached(src(), dst()).locked(ids::CWND));
    cache.record(src(), dst(), NOW, conn());
    assert_eq!(cache.cached(src(), dst()).get(ids::CWND), 99);
    assert_eq!(cache.cached(src(), dst()).get(ids::RTT), 50_000,
        "an unpinned slot still takes the measurement");
}

#[test]
fn a_pinned_round_trip_survives_even_a_connection_that_measured_nothing() {
    let cache = MetricsCache::new();
    let mut vals = [None; ids::COUNT];
    vals[ids::RTT] = Some(77_000);
    cache.pin(src(), dst(), NOW, vals);
    cache.record(src(), dst(), NOW, super::super::update::Closing { srtt: 0, ..conn() });
    assert_eq!(cache.cached(src(), dst()).get(ids::RTT), 77_000);
}

#[test]
fn one_row_carries_both_a_paths_metrics_and_its_fast_open_state() {
    let cache = MetricsCache::new();
    cache.set(src(), dst(), NOW, 1400, Some(cookie(3)), false, TRY_EXP_NONE);
    cache.record(src(), dst(), NOW, conn());
    assert_eq!(cache.chain_len(dst()), 1, "a destination has one home, not two");
    let row = cache.metrics(Some(src()), dst(), NOW).expect("the row is held");
    assert_eq!(row.cookie, Some(cookie(3)));
    assert_eq!(row.mss, 1400);
    assert_eq!(row.vals[ids::RTT], 50_000);
    assert_eq!(cache.get(src(), dst(), NOW).cookie, Some(cookie(3)),
        "recording metrics must not disturb the cookie");
}

#[test]
fn forgetting_a_destination_reports_whether_anything_was_held() {
    let cache = MetricsCache::new();
    cache.record(src(), dst(), NOW, conn());
    assert!(!cache.forget(Some(other()), dst()), "a source that names no row holds nothing");
    assert!(cache.forget(Some(src()), dst()));
    assert!(!cache.forget(Some(src()), dst()));
    assert_eq!(cache.chain_len(dst()), 0);
    // Without a source every row naming the destination goes.
    cache.record(src(), dst(), NOW, conn());
    cache.record(other(), dst(), NOW, conn());
    assert_eq!(cache.chain_len(dst()), 2);
    assert!(cache.forget(None, dst()));
    assert_eq!(cache.chain_len(dst()), 0);
}

#[test]
fn forgetting_everything_empties_every_chain() {
    let cache = MetricsCache::new();
    cache.record(src(), dst(), NOW, conn());
    cache.record(src(), other(), NOW, conn());
    cache.forget_all();
    assert_eq!(cache.chain_len(dst()), 0);
    assert_eq!(cache.chain_len(other()), 0);
}
