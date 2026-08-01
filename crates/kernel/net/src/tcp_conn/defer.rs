// The `TCP_DEFER_ACCEPT` hand-over rule. A completed passive connection that
// carries no data yet is withheld from `accept` until the client sends
// something, or until the deferral window runs out. A server that only ever
// wants to wake on a request is spared the accept-then-block round trip.
//
// The window arrives here already in seconds, because the option level owns
// the conversion from the retransmit count it stores (`sol_tcp::defer`).

/// The instant a connection deferred at `now_ns` becomes acceptable regardless
/// of what the client has sent. `0` means the listener is not deferring.
/// # C: O(1)
pub fn deadline_ns(window_secs: i32, now_ns: u64) -> u64 {
    if window_secs <= 0 { return 0; }
    // A deferred connection never carries the zero that means "not deferring".
    now_ns.saturating_add(window_secs as u64 * 1_000_000_000).max(1)
}

/// Whether a completed passive connection may be handed to `accept`.
/// # C: O(1)
pub fn acceptable(deadline_ns: u64, queued_bytes: usize, now_ns: u64) -> bool {
    if deadline_ns == 0 { return true; }
    if queued_bytes != 0 { return true; }
    now_ns >= deadline_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_that_did_not_ask_defers_nothing() {
        assert_eq!(deadline_ns(0, 1_000), 0);
        assert_eq!(deadline_ns(-1, 1_000), 0);
        assert!(acceptable(0, 0, 0), "an undeferred connection is acceptable at once");
    }

    #[test]
    fn a_deferred_connection_waits_for_data() {
        let deadline = deadline_ns(3, 0);
        assert!(deadline > 0);
        assert!(!acceptable(deadline, 0, 0), "nothing sent yet");
        assert!(acceptable(deadline, 1, 0), "one byte is enough to hand it over");
    }

    #[test]
    fn a_client_that_never_sends_is_handed_over_when_the_window_runs_out() {
        // Otherwise a silent client would hold a backlog slot forever without
        // the server ever being able to observe or close it.
        let deadline = deadline_ns(1, 0);
        assert!(!acceptable(deadline, 0, deadline - 1));
        assert!(acceptable(deadline, 0, deadline));
    }

    #[test]
    fn a_longer_window_defers_for_longer() {
        assert!(deadline_ns(60, 0) > deadline_ns(1, 0));
    }

    #[test]
    fn a_deadline_taken_at_the_clock_origin_is_still_a_deferral() {
        // Zero is the "not deferring" sentinel, so a deferral stamped before
        // the clock has advanced must not read as one.
        assert_ne!(deadline_ns(1, 0), 0);
    }
}
