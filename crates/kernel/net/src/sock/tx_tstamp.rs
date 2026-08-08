// The transmit-timestamp record a completed send owes its own error queue.
//
// `SO_TIMESTAMPING` — the socket option and the per-message SOL_SOCKET
// override that replaces its transmit-record bits — asks for a record on the
// sending socket's error queue when the message leaves. Without this the bits
// were admitted, screened for validity, and then had nothing to ask.

use core::sync::atomic::Ordering;

use crate::socket_error::uapi::SCM_TSTAMP_SND;
use crate::uapi::{SOF_TIMESTAMPING_OPT_ID, SOF_TIMESTAMPING_SOFTWARE,
    SOF_TIMESTAMPING_TX_SOFTWARE};

use super::InetSocket;

/// The key one send's transmit record is reported under, or `None` when the
/// send owes no record.
///
/// Both the request AND the generation method must be asked for: the transmit
/// bit alone names WHEN a record is wanted, and the software bit names WHO
/// takes the reading. `named` is the message's own identifier, which is only
/// consulted when the socket asked for identified records. # C: O(1)
pub fn tx_record_key(tsflags: u32, named: Option<u32>, next: u32) -> Option<u32> {
    if tsflags & SOF_TIMESTAMPING_TX_SOFTWARE == 0 { return None; }
    if tsflags & SOF_TIMESTAMPING_SOFTWARE as u32 == 0 { return None; }
    if tsflags & SOF_TIMESTAMPING_OPT_ID == 0 { return Some(0); }
    Some(named.unwrap_or(next))
}

/// Publish the record this completed send owes, if it owes one. The socket's
/// own key advances only when the socket generates it — a message that named
/// its own identifier does not move the counter. # C: O(1)
pub fn publish(sock: &InetSocket, tsflags: u32, named: Option<u32>, v6: bool) {
    let next = sock.opts.base.tskey.load(Ordering::Acquire);
    let Some(key) = tx_record_key(tsflags, named, next) else { return; };
    if tsflags & SOF_TIMESTAMPING_OPT_ID != 0 && named.is_none() {
        sock.opts.base.tskey.store(next.wrapping_add(1), Ordering::Release);
    }
    sock.error.publish_timestamping(SCM_TSTAMP_SND, key, v6, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TX: u32 = SOF_TIMESTAMPING_TX_SOFTWARE;
    const SW: u32 = SOF_TIMESTAMPING_SOFTWARE as u32;

    /// Asking WHEN without asking WHO leaves nothing to take the reading, and
    /// the reverse asks for a reading nobody wanted.
    #[test]
    fn a_record_needs_both_the_transmit_request_and_a_generation_method() {
        assert_eq!(tx_record_key(0, None, 0), None);
        assert_eq!(tx_record_key(TX, None, 0), None);
        assert_eq!(tx_record_key(SW, None, 0), None);
        assert_eq!(tx_record_key(TX | SW, None, 0), Some(0));
    }

    /// Without identified records every record carries the zero key; with
    /// them the socket's counter supplies it, and a message that named its own
    /// identifier outranks the counter.
    #[test]
    fn the_key_comes_from_the_message_then_the_socket_counter() {
        assert_eq!(tx_record_key(TX | SW, Some(0x1234), 9), Some(0));
        let identified = TX | SW | SOF_TIMESTAMPING_OPT_ID;
        assert_eq!(tx_record_key(identified, None, 9), Some(9));
        assert_eq!(tx_record_key(identified, Some(0x1234), 9), Some(0x1234));
    }
}
