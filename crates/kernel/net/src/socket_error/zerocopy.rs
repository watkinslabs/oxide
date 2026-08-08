//! `MSG_ZEROCOPY` send completion, shared by every family that offers
//! `SO_ZEROCOPY`.

use super::queue::SocketError;

/// Whether one send produces a zero-copy completion.
///
/// `SO_ZEROCOPY` gates the feature; `MSG_ZEROCOPY` requests it per send; an
/// empty transfer produced no identifier to report. # C: O(1)
pub const fn notifies(enabled: bool, requested: bool, bytes: usize) -> bool {
    enabled && requested && bytes != 0
}

/// Publish the completion one send owes its error queue, and report whether a
/// record was queued.
///
/// The transmit path copies the payload before returning, so every completion
/// carries the copy-fallback code. # C: O(1) amortized
pub fn complete_send(error: &SocketError, enabled: bool, requested: bool, bytes: usize,
    v6: bool) -> bool
{
    if !notifies(enabled, requested, bytes) { return false; }
    let id = error.next_zerocopy_id();
    error.publish_zerocopy(id, 1, true, v6)
}

#[cfg(test)]
mod tests {
    use super::{complete_send, notifies};
    use crate::socket_error::{SocketError, SO_EE_CODE_ZEROCOPY_COPIED, SO_EE_ORIGIN_ZEROCOPY};

    #[test]
    fn a_completion_needs_the_option_the_flag_and_a_transfer() {
        assert!(notifies(true, true, 1));
        assert!(!notifies(false, true, 1));
        assert!(!notifies(true, false, 1));
        assert!(!notifies(true, true, 0));
    }

    #[test]
    fn consecutive_sends_claim_consecutive_identifiers_and_coalesce() {
        let error = SocketError::new();
        assert!(!complete_send(&error, false, true, 4, false));
        assert!(complete_send(&error, true, true, 4, false));
        assert!(complete_send(&error, true, true, 4, false));
        let record = error.take_extended().expect("one coalesced completion");
        assert_eq!(record.origin, SO_EE_ORIGIN_ZEROCOPY);
        assert_eq!((record.info, record.data), (0, 1));
        assert_eq!(record.code, SO_EE_CODE_ZEROCOPY_COPIED);
        assert_eq!(record.errno, 0);
        assert!(!error.has_extended());
    }

    #[test]
    fn a_skipped_send_leaves_a_gap_that_stops_coalescing() {
        let error = SocketError::new();
        assert!(complete_send(&error, true, true, 4, false));
        assert!(!complete_send(&error, true, false, 4, false), "no flag, no identifier");
        assert!(complete_send(&error, true, true, 4, false));
        assert_eq!(error.take_extended().map(|r| (r.info, r.data)), Some((0, 1)),
            "an unrequested send claims no identifier, so the range stays contiguous");
    }
}
