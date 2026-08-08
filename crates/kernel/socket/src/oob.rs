// How one `MSG_OOB` send is split across a byte stream.
//
// Only `SOCK_STREAM` has an out-of-band channel, and it carries exactly one
// byte. A `MSG_OOB` send of `n` bytes therefore puts the first `n - 1` bytes
// into the ordinary stream and the LAST byte into the out-of-band record, and
// reports `n` — the out-of-band byte counts toward the return just like an
// in-band one. A zero-length `MSG_OOB` send has no byte to put there and
// reports EOPNOTSUPP, the same answer the datagram and seqpacket flavours give
// for any length.
//
// The ancillary data is parsed before any of this: a malformed control buffer
// or an unusable descriptor is reported ahead of the absent out-of-band
// channel, so EOPNOTSUPP never masks EINVAL/EBADF/EPERM.
//
// The out-of-band tail is also the one stream send that reports EPIPE WITHOUT
// raising SIGPIPE: the in-band body owns that signal, and a send whose body
// already succeeded reports the body's byte count instead of the failure.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

/// How a send divides between the ordinary stream and the out-of-band record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OobPlan {
    /// Not an out-of-band send; every byte rides the ordinary path.
    Inband,
    /// This socket kind, or this length, has no out-of-band byte to send.
    Unsupported,
    /// `body` ordinary bytes followed by one out-of-band byte.
    Split { body: usize },
}

/// The plan for one AF_UNIX send. `stream` is whether the socket is
/// `SOCK_STREAM`, `oob` whether `MSG_OOB` was asked for, `len` the requested
/// payload length. # C: O(1)
pub fn unix_oob_plan(stream: bool, oob: bool, len: usize) -> OobPlan {
    if !oob { return OobPlan::Inband; }
    if !stream || len == 0 { return OobPlan::Unsupported; }
    OobPlan::Split { body: len - 1 }
}

/// The plan for one TCP send.
///
/// The urgent pointer is set just past the last byte written, so every byte
/// goes through the ordinary stream and it is the LAST one the receiver reads
/// out of band — the same division AF_UNIX makes, reached a different way. A
/// zero-length out-of-band send marks a pointer with nothing behind it: it
/// reports zero rather than refusing, which is where the two families differ.
/// # C: O(1)
pub fn tcp_oob_plan(oob: bool, len: usize) -> OobPlan {
    if !oob { return OobPlan::Inband; }
    if len == 0 { return OobPlan::Unsupported; }
    OobPlan::Split { body: len - 1 }
}

/// Bytes the ordinary stream loop must transfer before the out-of-band tail.
/// # C: O(1)
pub fn plan_body(plan: OobPlan, len: usize) -> usize {
    match plan { OobPlan::Split { body } => body, _ => len }
}

/// Whether the send still owes an out-of-band byte once `sent` bytes have gone
/// through the ordinary path. # C: O(1)
pub fn owes_oob(plan: OobPlan, sent: usize) -> bool {
    matches!(plan, OobPlan::Split { body } if sent == body)
}

/// Whether a failed AF_UNIX send raises SIGPIPE. The out-of-band tail never
/// does: the in-band body owns that signal, so a send whose only failure was
/// the urgent byte reports EPIPE alone. `pipe_kind` is whether the socket kind
/// raises it at all (stream and seqpacket do, datagram does not).
/// # C: O(1)
pub fn signals_pipe(pipe_kind: bool, tail: bool) -> bool { pipe_kind && !tail }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_send_is_untouched() {
        assert_eq!(unix_oob_plan(true, false, 0), OobPlan::Inband);
        assert_eq!(unix_oob_plan(false, false, 9), OobPlan::Inband);
        assert_eq!(plan_body(OobPlan::Inband, 9), 9);
        assert!(!owes_oob(OobPlan::Inband, 9));
    }

    #[test]
    fn stream_send_puts_its_last_byte_out_of_band() {
        assert_eq!(unix_oob_plan(true, true, 1), OobPlan::Split { body: 0 });
        assert_eq!(unix_oob_plan(true, true, 4), OobPlan::Split { body: 3 });
        assert_eq!(plan_body(OobPlan::Split { body: 3 }, 4), 3);
    }

    #[test]
    fn out_of_band_byte_is_owed_once_the_body_is_through() {
        let plan = unix_oob_plan(true, true, 4);
        assert!(!owes_oob(plan, 0));
        assert!(!owes_oob(plan, 2));
        assert!(owes_oob(plan, 3), "the tail follows the last body byte");
        // A one-byte send has no body at all, so the tail is owed immediately.
        assert!(owes_oob(unix_oob_plan(true, true, 1), 0));
    }

    #[test]
    fn only_the_in_band_body_raises_sigpipe() {
        assert!(signals_pipe(true, false));
        assert!(!signals_pipe(true, true), "an urgent-byte failure reports EPIPE alone");
        assert!(!signals_pipe(false, false));
    }

    #[test]
    fn a_tcp_send_marks_its_last_byte_and_reports_zero_for_an_empty_one() {
        assert_eq!(tcp_oob_plan(false, 4), OobPlan::Inband);
        assert_eq!(tcp_oob_plan(true, 1), OobPlan::Split { body: 0 });
        assert_eq!(tcp_oob_plan(true, 4), OobPlan::Split { body: 3 });
        // Nothing to mark: the stream refuses nothing and sends nothing.
        assert_eq!(tcp_oob_plan(true, 0), OobPlan::Unsupported);
    }

    #[test]
    fn zero_length_and_non_stream_have_no_out_of_band_channel() {
        assert_eq!(unix_oob_plan(true, true, 0), OobPlan::Unsupported);
        assert_eq!(unix_oob_plan(false, true, 1), OobPlan::Unsupported);
        assert_eq!(unix_oob_plan(false, true, 0), OobPlan::Unsupported);
    }
}
