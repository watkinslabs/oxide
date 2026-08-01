// `TCP_DEFER_ACCEPT` at the option level: the conversion from the retransmit
// count the option stores to the seconds window the hand-over rule waits out.
//
// The window is not a second stored number — it is the span the stored count
// covers, which is exactly what `getsockopt` reads back, so the wait and the
// reported value cannot drift apart. The rule itself belongs to the connection
// that is being withheld and is re-exported here so there is one name for it.

use super::{TCP_RTO_MAX_SEC, TCP_TIMEOUT_INIT_S, retrans_to_secs};

pub use crate::tcp_conn::defer::{acceptable, deadline_ns};

/// The seconds a listener holding `defer_accept` withholds a silent
/// connection for. # C: O(retransmits)
pub fn window_secs(defer_accept: u8) -> i32 {
    if defer_accept == 0 { return 0; }
    retrans_to_secs(defer_accept, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{NS_PER_S, TCP_DEFER_ACCEPT, secs_to_retrans};
    use super::super::set::{self, Action, Arg, SetEnv};

    #[test]
    fn a_listener_that_did_not_ask_has_no_window() {
        assert_eq!(window_secs(0), 0);
        assert_eq!(deadline_ns(window_secs(0), 1_000), 0);
    }

    #[test]
    fn the_window_is_the_span_the_stored_count_covers() {
        // The same number `getsockopt` reads back drives the wait.
        for requested in [1, 5, 30, 100] {
            let stored = secs_to_retrans(requested, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC);
            let reported = retrans_to_secs(stored, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC);
            assert_eq!(window_secs(stored), reported);
            assert!(reported >= requested, "the window must cover what was asked for");
            assert_eq!(deadline_ns(window_secs(stored), 0), reported as u64 * NS_PER_S);
        }
    }

    #[test]
    fn the_option_write_produces_the_count_the_window_is_built_from() {
        let Ok(Action::DeferAccept(stored)) =
            set::admit(TCP_DEFER_ACCEPT, Arg::Int(10), SetEnv::default()) else { panic!() };
        assert!(deadline_ns(window_secs(stored), 0) >= 10 * NS_PER_S);
        // Clearing the option stops deferring immediately.
        let Ok(Action::DeferAccept(cleared)) =
            set::admit(TCP_DEFER_ACCEPT, Arg::Int(0), SetEnv::default()) else { panic!() };
        assert_eq!(cleared, 0);
        assert_eq!(deadline_ns(window_secs(cleared), 0), 0);
    }

    #[test]
    fn a_longer_request_defers_for_longer() {
        let short = window_secs(secs_to_retrans(1, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC));
        let long = window_secs(secs_to_retrans(60, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC));
        assert!(long > short);
    }
}
