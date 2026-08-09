//! The unit boundary between a connection and the destination metrics cache.


use crate::addr::{IpAddr, Ipv4Addr};
use crate::tcp_conn::{Endpoint, TcpConn};
use crate::tcp_metrics::ids;

const MSS: u16 = 1_000;

fn conn() -> TcpConn {
    let ip = IpAddr::V4(Ipv4Addr::LOOPBACK);
    let mut conn = TcpConn::new_client(Endpoint { ip, port: 40_000 },
        Endpoint { ip, port: 80 }, 1);
    conn.peer_mss = MSS;
    conn.srtt_ns = 50_000_000;
    conn.rttvar_ns = 5_000_000;
    conn.cwnd = 40 * u32::from(MSS);
    conn.cwnd_clamp = 200 * u32::from(MSS);
    conn.ssthresh = 20 * u32::from(MSS);
    conn
}

#[test]
fn the_cache_is_told_windows_in_segments_and_the_round_trip_in_microseconds() {
    let conn = conn();
    let closing = conn.metrics_closing(3, false);
    assert_eq!(closing.srtt, 50_000, "nanoseconds become microseconds");
    assert_eq!(closing.mdev, 5_000);
    assert_eq!(closing.cwnd, 40, "bytes become segments");
    assert_eq!(closing.ssthresh, 20);
    let fresh = conn.metrics_fresh(3, false);
    assert_eq!(fresh.cwnd_clamp, 200);
    assert_eq!(fresh.srtt, 50_000);
}

#[test]
fn a_seed_in_segments_comes_back_as_bytes() {
    let mut conn = conn();
    conn.apply_metrics_seed(crate::tcp_metrics::Seed {
        ssthresh: 64, cwnd_clamp: 100, reordering: 7,
        rto_ns: Some(300_000_000), reset_rttvar: false,
    });
    assert_eq!(conn.ssthresh, 64 * u32::from(MSS));
    assert_eq!(conn.cwnd_clamp, 100 * u32::from(MSS));
    assert_eq!(conn.reordering, 7);
    assert_eq!(conn.rto_ns, 300_000_000);
}

#[test]
fn an_empty_cache_leaves_the_connection_in_slow_start() {
    let mut conn = conn();
    let seed = crate::tcp_metrics::seed(crate::tcp_metrics::CachedMetrics::default(),
        conn.metrics_fresh(3, false));
    let clamp = conn.cwnd_clamp;
    conn.apply_metrics_seed(seed);
    assert_eq!(conn.ssthresh, u32::MAX, "the threshold the stack reads as infinite");
    assert_eq!(conn.cwnd_clamp, clamp);
    assert_eq!(conn.reordering, 3);
}

#[test]
fn the_seeded_timeout_never_exceeds_the_connections_own_ceiling() {
    let mut conn = conn();
    conn.rto_max_ns = 1_000_000;
    conn.apply_metrics_seed(crate::tcp_metrics::Seed {
        ssthresh: 0, cwnd_clamp: 0, reordering: 0,
        rto_ns: Some(u64::MAX), reset_rttvar: false,
    });
    assert_eq!(conn.rto_ns, 1_000_000);
}

#[test]
fn an_unreduced_threshold_means_slow_start_never_finished() {
    let mut conn = conn();
    conn.ssthresh = u32::MAX;
    let closing = conn.metrics_closing(3, false);
    assert_eq!(closing.phase, crate::tcp_metrics::Phase::InitialSlowStart);
    assert_eq!(closing.ssthresh, 0, "an infinite threshold is no measurement");
}

#[test]
fn a_connection_past_slow_start_is_lossy_only_while_something_is_outstanding() {
    let mut conn = conn();
    conn.cwnd = 40 * u32::from(MSS);
    conn.ssthresh = 20 * u32::from(MSS);
    assert_eq!(conn.metrics_closing(3, false).phase, crate::tcp_metrics::Phase::Open);
    conn.dup_acks = 2;
    assert_eq!(conn.metrics_closing(3, false).phase, crate::tcp_metrics::Phase::Lossy);
    conn.dup_acks = 0;
    conn.cwnd = 4 * u32::from(MSS);
    assert_eq!(conn.metrics_closing(3, false).phase, crate::tcp_metrics::Phase::Lossy,
        "a window under the threshold is still slow start, not a measurement");
}

#[test]
fn a_backed_off_retransmit_timer_means_nothing_measured_the_path() {
    let mut conn = conn();
    conn.rto_min_ns = 200_000_000;
    conn.rto_ns = 200_000_000;
    assert!(!conn.metrics_closing(3, false).backing_off);
    conn.rto_ns = 900_000_000;
    assert!(conn.metrics_closing(3, false).backing_off);
}

#[test]
fn a_connection_with_no_segment_size_or_no_sample_tells_the_cache_nothing() {
    let mut conn = conn();
    assert!(conn.metrics_worth_recording());
    conn.srtt_ns = 0;
    assert!(!conn.metrics_worth_recording());
    let mut sizeless = self::conn();
    sizeless.peer_mss = 0;
    sizeless.own_mss = 0;
    assert!(!sizeless.metrics_worth_recording());
    // With no segment size the windows convert to nothing rather than to a
    // number the cache would believe.
    assert_eq!(sizeless.metrics_closing(3, false).cwnd, 0);
}

#[test]
fn a_round_trip_shorter_than_a_microsecond_is_still_carried_as_one_slot() {
    let mut conn = conn();
    conn.srtt_ns = 900;
    assert_eq!(conn.metrics_closing(3, false).srtt, 0);
    conn.srtt_ns = 1_500;
    assert_eq!(conn.metrics_closing(3, false).srtt, 1);
    assert_eq!(ids::millis(1), 1, "and reports as a whole millisecond, never as absent");
}
