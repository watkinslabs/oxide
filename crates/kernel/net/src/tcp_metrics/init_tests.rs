//! What a cached destination row seeds into a fresh connection.

use super::*;

const MS: u32 = 1_000;

fn fresh() -> Fresh {
    Fresh { srtt: 50 * MS, cwnd_clamp: 200, reordering: 3, rto_min_ns: 200_000_000,
        no_ssthresh_save: false }
}

fn cached(vals: [u32; ids::COUNT]) -> CachedMetrics { CachedMetrics { vals, lock: 0 } }

const NONE: [u32; ids::COUNT] = [0; ids::COUNT];

#[test]
fn an_empty_cache_restores_the_default_threshold_and_changes_nothing_else() {
    let seeded = seed(cached(NONE), fresh());
    assert_eq!(seeded.ssthresh, INFINITE_SSTHRESH,
        "a handshake may have cut the threshold; nothing cached means the default");
    assert_eq!(seeded.cwnd_clamp, 200);
    assert_eq!(seeded.reordering, 3);
    assert_eq!(seeded.rto_ns, None, "a measured handshake keeps its own timeout");
    assert!(!seeded.reset_rttvar);
}

#[test]
fn a_cached_threshold_is_adopted_and_never_exceeds_the_window_ceiling() {
    let mut vals = NONE;
    vals[ids::SSTHRESH] = 64;
    assert_eq!(seed(cached(vals), fresh()).ssthresh, 64);
    vals[ids::SSTHRESH] = 4_000;
    assert_eq!(seed(cached(vals), fresh()).ssthresh, 200, "clamped to the window ceiling");
}

#[test]
fn the_threshold_is_ignored_when_the_namespace_asks_for_it_to_be() {
    let mut vals = NONE;
    vals[ids::SSTHRESH] = 64;
    let asked = Fresh { no_ssthresh_save: true, ..fresh() };
    assert_eq!(seed(cached(vals), asked).ssthresh, INFINITE_SSTHRESH);
}

#[test]
fn only_a_pinned_window_replaces_the_connections_own_ceiling() {
    let mut vals = NONE;
    vals[ids::CWND] = 32;
    assert_eq!(seed(cached(vals), fresh()).cwnd_clamp, 200,
        "an ordinary cached window is a measurement, not a ceiling");
    let pinned = CachedMetrics { vals, lock: ids::with_lock(0, ids::CWND) };
    assert_eq!(seed(pinned, fresh()).cwnd_clamp, 32);
    // The ceiling moves before the threshold is clamped against it.
    let mut vals = vals;
    vals[ids::SSTHRESH] = 4_000;
    let pinned = CachedMetrics { vals, lock: ids::with_lock(0, ids::CWND) };
    assert_eq!(seed(pinned, fresh()).ssthresh, 32);
}

#[test]
fn a_cached_reordering_degree_replaces_the_namespace_default() {
    let mut vals = NONE;
    vals[ids::REORDERING] = 11;
    assert_eq!(seed(cached(vals), fresh()).reordering, 11);
    vals[ids::REORDERING] = 0;
    assert_eq!(seed(cached(vals), fresh()).reordering, 3);
}

#[test]
fn a_longer_cached_round_trip_seeds_the_first_retransmit_timeout() {
    let mut vals = NONE;
    vals[ids::RTT] = 120 * MS;
    let seeded = seed(cached(vals), fresh());
    // One round trip plus twice its own, in nanoseconds.
    assert_eq!(seeded.rto_ns, Some(360_000_000));
    assert!(!seeded.reset_rttvar, "the estimator's own variables are left alone");
    // A cached round trip no longer than the handshake's teaches nothing.
    vals[ids::RTT] = 50 * MS;
    assert_eq!(seed(cached(vals), fresh()).rto_ns, None);
}

#[test]
fn the_seeded_timeout_is_floored_at_the_routes_minimum() {
    let mut vals = NONE;
    vals[ids::RTT] = 1;
    let seeded = seed(cached(vals), Fresh { srtt: 0, ..fresh() });
    // Twice a microsecond is far under the 200 ms floor, so the floor wins.
    assert_eq!(seeded.rto_ns, Some(200_001_000));
}

#[test]
fn a_connection_that_measured_nothing_falls_back_to_a_conservative_timeout() {
    let seeded = seed(cached(NONE), Fresh { srtt: 0, ..fresh() });
    assert_eq!(seeded.rto_ns, Some(TIMEOUT_FALLBACK_NS));
    assert!(seeded.reset_rttvar, "no sample means the estimator has nothing either");
    // A cached round trip answers instead, and leaves the estimator alone.
    let mut vals = NONE;
    vals[ids::RTT] = 200 * MS;
    let seeded = seed(cached(vals), Fresh { srtt: 0, ..fresh() });
    assert_eq!(seeded.rto_ns, Some(600_000_000));
    assert!(!seeded.reset_rttvar);
}

#[test]
fn a_row_holding_nothing_reads_as_empty() {
    assert!(cached(NONE).is_empty());
    let mut vals = NONE;
    vals[ids::CWND] = 1;
    assert!(!cached(vals).is_empty());
}
