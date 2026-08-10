//! What a closing connection writes back about its destination.

use super::*;

const MS: u32 = 1_000;

fn closing() -> Closing {
    Closing { srtt: 50 * MS, mdev: 5 * MS, cwnd: 40, ssthresh: 20, reordering: 3,
        phase: Phase::Open, backing_off: false, no_ssthresh_save: false,
        default_reordering: 3 }
}

fn row(vals: [u32; ids::COUNT]) -> Row { Row { vals, lock: 0 } }

const NONE: [u32; ids::COUNT] = [0; ids::COUNT];

fn stored(update: Update) -> Row {
    match update { Update::Store(row) => row, Update::ForgetRtt => panic!("expected a store") }
}

#[test]
fn a_connection_that_measured_nothing_clears_the_stored_round_trip() {
    let mut vals = NONE;
    vals[ids::RTT] = 90 * MS;
    assert_eq!(update(row(vals), Closing { srtt: 0, ..closing() }), Update::ForgetRtt);
    assert_eq!(update(row(vals), Closing { backing_off: true, ..closing() }),
        Update::ForgetRtt);
    // Anything else about the destination is left alone; only the round trip
    // was ever this connection's to claim.
    assert_ne!(update(row(vals), closing()), Update::ForgetRtt);
}

#[test]
fn a_longer_round_trip_replaces_and_a_shorter_one_only_decays_the_stored_value() {
    let mut vals = NONE;
    vals[ids::RTT] = 40 * MS;
    // The new sample is longer, so it is taken outright: overestimating a
    // path costs throughput, underestimating it costs retransmits.
    assert_eq!(stored(update(row(vals), closing())).get(ids::RTT), 50 * MS);
    vals[ids::RTT] = 90 * MS;
    // Shorter: the stored value moves an eighth of the way down, not all.
    assert_eq!(stored(update(row(vals), closing())).get(ids::RTT), 90 * MS - (40 * MS >> 3));
}

#[test]
fn variation_is_floored_at_the_connections_own_deviation() {
    // The two round trips agree, so the only variation on offer is the
    // connection's own.
    let mut vals = NONE;
    vals[ids::RTT] = 50 * MS;
    assert_eq!(stored(update(row(vals), closing())).get(ids::RTTVAR), 5 * MS);
    // A large disagreement between stored and measured is half of it.
    vals[ids::RTT] = 150 * MS;
    assert_eq!(stored(update(row(vals), closing())).get(ids::RTTVAR), 50 * MS);
}

#[test]
fn a_smaller_variation_decays_the_stored_one_by_a_quarter() {
    let mut vals = NONE;
    vals[ids::RTT] = 50 * MS;
    vals[ids::RTTVAR] = 25 * MS;
    // Measured variation is the connection's 5 ms; stored is 25 ms.
    assert_eq!(stored(update(row(vals), closing())).get(ids::RTTVAR),
        25 * MS - ((25 * MS - 5 * MS) >> 2));
}

#[test]
fn slow_start_treats_the_window_it_reached_as_a_floor() {
    let conn = Closing { phase: Phase::InitialSlowStart, cwnd: 40, ..closing() };
    let mut vals = NONE;
    vals[ids::CWND] = 10;
    vals[ids::SSTHRESH] = 8;
    let out = stored(update(row(vals), conn));
    assert_eq!(out.get(ids::CWND), 40, "the larger window is remembered");
    assert_eq!(out.get(ids::SSTHRESH), 20, "half the window, since it beats the stored one");
    // A smaller window than the stored one teaches nothing, and a threshold
    // that was never stored is not invented in slow start.
    let conn = Closing { phase: Phase::InitialSlowStart, cwnd: 4, ..closing() };
    let out = stored(update(row(vals), conn));
    assert_eq!(out.get(ids::CWND), 10);
    assert_eq!(out.get(ids::SSTHRESH), 8);
    let mut empty = NONE;
    empty[ids::RTT] = 50 * MS;
    let conn = Closing { phase: Phase::InitialSlowStart, ..closing() };
    assert_eq!(stored(update(row(empty), conn)).get(ids::SSTHRESH), 0);
}

#[test]
fn a_loss_free_connection_past_slow_start_averages_its_window_in() {
    let mut vals = NONE;
    vals[ids::CWND] = 60;
    let out = stored(update(row(vals), closing()));
    assert_eq!(out.get(ids::CWND), 50, "the stored window and the measured one, averaged");
    assert_eq!(out.get(ids::SSTHRESH), 20, "half the window, or the connection's own");
    let conn = Closing { cwnd: 8, ssthresh: 30, ..closing() };
    assert_eq!(stored(update(row(vals), conn)).get(ids::SSTHRESH), 30);
}

#[test]
fn a_connection_that_lost_its_way_keeps_only_its_threshold_and_reordering() {
    let mut vals = NONE;
    vals[ids::CWND] = 60;
    vals[ids::SSTHRESH] = 8;
    vals[ids::REORDERING] = 4;
    let conn = Closing { phase: Phase::Lossy, ssthresh: 20, reordering: 9, ..closing() };
    let out = stored(update(row(vals), conn));
    assert_eq!(out.get(ids::CWND), 40, "the window is meaningless; the threshold stands in");
    assert_eq!(out.get(ids::SSTHRESH), 20);
    assert_eq!(out.get(ids::REORDERING), 9);
}

#[test]
fn a_connection_still_carrying_the_default_reordering_observed_none() {
    let mut vals = NONE;
    vals[ids::REORDERING] = 4;
    let conn = Closing { phase: Phase::Lossy, reordering: 9, default_reordering: 9,
        ..closing() };
    assert_eq!(stored(update(row(vals), conn)).get(ids::REORDERING), 4,
        "the namespace default is not an observation");
    // A degree lower than the stored one is not an improvement worth keeping.
    let conn = Closing { phase: Phase::Lossy, reordering: 2, ..closing() };
    assert_eq!(stored(update(row(vals), conn)).get(ids::REORDERING), 4);
}

#[test]
fn the_namespace_can_refuse_to_remember_a_threshold_at_all() {
    let conn = Closing { no_ssthresh_save: true, ..closing() };
    for phase in [Phase::InitialSlowStart, Phase::Open, Phase::Lossy] {
        let mut vals = NONE;
        vals[ids::SSTHRESH] = 8;
        let out = stored(update(row(vals), Closing { phase, ..conn }));
        assert_eq!(out.get(ids::SSTHRESH), 8, "{phase:?} must leave it alone");
    }
}

#[test]
fn a_pinned_slot_survives_every_write_back() {
    let mut vals = NONE;
    vals[ids::RTT] = 90 * MS;
    vals[ids::CWND] = 60;
    vals[ids::SSTHRESH] = 8;
    vals[ids::RTTVAR] = 25 * MS;
    let mut lock = 0;
    for metric in [ids::RTT, ids::RTTVAR, ids::SSTHRESH, ids::CWND, ids::REORDERING] {
        lock = ids::with_lock(lock, metric);
    }
    for phase in [Phase::InitialSlowStart, Phase::Open, Phase::Lossy] {
        let out = stored(update(Row { vals, lock }, Closing { phase, ..closing() }));
        assert_eq!(out.vals, vals, "{phase:?} must change nothing pinned");
    }
}
