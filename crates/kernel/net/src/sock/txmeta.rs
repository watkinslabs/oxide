// The transmit metadata one message leaves with, and the ONE place it is built.
//
// `SO_MARK`, `SO_PRIORITY` and the departure-time request each have two
// possible sources — the socket's own option, and an override this message
// carried as SOL_SOCKET ancillary data — and exactly one answer per packet.
// Resolving them here, from the option table and the message's settled
// overrides, is what keeps that answer single: nothing downstream re-reads the
// option, and the override is never copied into a second holder.

use core::sync::atomic::Ordering;

use super::InetSocket;
use crate::send_control::SockCm;
use crate::TxMeta;

/// `SO_MARK` as the option table holds it. # C: O(1)
pub fn sock_mark(sock: &InetSocket) -> u32 { sock.opts.mark.load(Ordering::Acquire) as u32 }

/// `SO_PRIORITY` as the option table holds it. # C: O(1)
pub fn sock_priority(sock: &InetSocket) -> u32 {
    sock.opts.priority.load(Ordering::Acquire) as u32
}

/// The metadata this message's packets carry: the socket's own choices, each
/// replaced by the override the message settled for its own duration.
/// # C: O(1)
pub fn tx_meta(sock: &InetSocket, sockcm: &SockCm) -> TxMeta {
    TxMeta {
        mark: sockcm.mark(sock_mark(sock)),
        priority: sockcm.priority(sock_priority(sock)),
        transmit_time: sockcm.transmit_time.unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each field takes the message's override when it made one and the
    /// socket's own value otherwise — the two are never added or ORed.
    #[test]
    fn a_message_override_replaces_the_socket_value_field_by_field() {
        let socket = TxMeta { mark: 7, priority: 2, transmit_time: 0 };
        let none = SockCm::default();
        assert_eq!(none.mark(socket.mark), 7);
        assert_eq!(none.priority(socket.priority), 2);
        let named = SockCm { mark: Some(0x1234), priority: Some(6),
            transmit_time: Some(99), ..SockCm::default() };
        assert_eq!(named.mark(socket.mark), 0x1234);
        assert_eq!(named.priority(socket.priority), 6);
        // An override of ZERO is an override, not an absent one.
        let zeroed = SockCm { mark: Some(0), priority: Some(0), ..SockCm::default() };
        assert_eq!(zeroed.mark(socket.mark), 0);
        assert_eq!(zeroed.priority(socket.priority), 0);
    }

    /// The timestamping override replaces the socket's transmit-record bits and
    /// leaves every other bit of its timestamping state standing.
    #[test]
    fn the_timestamping_override_replaces_only_the_transmit_record_bits() {
        let socket = crate::uapi::SOF_TIMESTAMPING_TX_SOFTWARE
            | crate::uapi::SOF_TIMESTAMPING_SOFTWARE as u32
            | crate::uapi::SOF_TIMESTAMPING_OPT_ID;
        assert_eq!(SockCm::default().tsflags(socket), socket);
        let cleared = SockCm { tsflags: Some(0), ..SockCm::default() };
        assert_eq!(cleared.tsflags(socket), crate::uapi::SOF_TIMESTAMPING_SOFTWARE as u32
            | crate::uapi::SOF_TIMESTAMPING_OPT_ID);
        let acked = SockCm { tsflags: Some(crate::uapi::SOF_TIMESTAMPING_TX_ACK),
            ..SockCm::default() };
        assert_eq!(acked.tsflags(socket), crate::uapi::SOF_TIMESTAMPING_TX_ACK
            | crate::uapi::SOF_TIMESTAMPING_SOFTWARE as u32
            | crate::uapi::SOF_TIMESTAMPING_OPT_ID);
    }
}
