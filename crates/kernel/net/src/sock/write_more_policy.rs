// B275: the splice/`sendfile` MORE-DATA hint's socket-side decision, split
// out of `io.rs` (which is `#[cfg(target_os = "oxide-kernel")]`-gated end to
// end, and so — per the phantom-test rule — cannot carry a hosted `cargo
// test` of its own logic; a `#[cfg(test)]` module nested inside it compiles
// out silently under a hosted build). This file carries NO target gate, so
// the decision `write_more` makes is checkable without a boot.
//
// Only TCP has a cork mechanism to plug the hint into (Linux corks only the
// TCP send path; AF_UNIX/UDP/raw sockets have no cork-shaped queue for a
// spliced `MSG_MORE` write to hold data in). `write_more` in `io.rs` matches
// the socket kind, then calls `plan_write_more` with the sticky `TCP_CORK`
// sockopt value and this call's `more` hint.

/// What one `write_more` call should do with the hint. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WriteMorePlan {
    /// No cork machinery for this socket kind — fall back to the plain
    /// blocking/non-blocking write; the hint is dropped exactly as it is for
    /// every other backend that ignores it (`FileOps::write_more_file`'s
    /// documented default).
    PlainWrite,
    /// TCP: corked THIS call when `cork` is true — the sticky `TCP_CORK`
    /// sockopt and the transient splice hint are the same mechanism, ORed
    /// together so neither can undercut the other (setting `TCP_CORK` still
    /// holds data after a `more == false` final splice segment, and a
    /// `more == true` intermediate segment corks even with `TCP_CORK` off).
    Tcp { cork: bool },
}

/// Decide `write_more`'s plan for one call. # C: O(1)
pub fn plan_write_more(is_tcp: bool, sockopt_cork: bool, more: bool) -> WriteMorePlan {
    if !is_tcp { return WriteMorePlan::PlainWrite; }
    WriteMorePlan::Tcp { cork: tcp_cork_for(sockopt_cork, more) }
}

/// The single OR both TCP write entry points (plain and `write_more`) apply:
/// the sticky `TCP_CORK` sockopt and this call's transient cork request are
/// the same mechanism, so neither can undercut the other. `extra` is `false`
/// for a plain `write`/`write_nonblock` and the splice `more` hint for
/// `write_more`. # C: O(1)
fn tcp_cork_for(sockopt_cork: bool, extra: bool) -> bool { sockopt_cork || extra }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_tcp_kinds_never_cork_the_hint_is_dropped() {
        for sockopt_cork in [false, true] {
            for more in [false, true] {
                assert_eq!(plan_write_more(false, sockopt_cork, more), WriteMorePlan::PlainWrite);
            }
        }
    }

    #[test]
    fn tcp_with_neither_cork_source_flushes_normally() {
        assert_eq!(plan_write_more(true, false, false), WriteMorePlan::Tcp { cork: false });
    }

    #[test]
    fn tcp_splice_more_hint_corks_even_with_cork_sockopt_off() {
        // The bug this row fixes: a spliced intermediate segment must cork
        // regardless of the sticky sockopt, or every pipe segment goes out
        // as its own small TCP segment.
        assert_eq!(plan_write_more(true, false, true), WriteMorePlan::Tcp { cork: true });
    }

    #[test]
    fn tcp_cork_sockopt_corks_even_with_the_hint_false() {
        // The final splice segment (`more == false`) must still respect an
        // application-level `TCP_CORK`, matching Linux's persistent
        // `TCP_NAGLE_CORK` until the sockopt is explicitly cleared.
        assert_eq!(plan_write_more(true, true, false), WriteMorePlan::Tcp { cork: true });
    }

    #[test]
    fn tcp_both_cork_sources_still_collapse_to_one_cork_state() {
        assert_eq!(plan_write_more(true, true, true), WriteMorePlan::Tcp { cork: true });
    }
}
