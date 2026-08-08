// `IPV6_RECVPATHMTU`: the path-MTU notification a socket that forbade
// fragmentation receives instead of the datagram it could not send.
//
// This is NOT the extended-error queue. The notification lives in a single
// replace-in-place cell on the socket, an ordinary receive drains it before it
// looks at the datagram queue, and no receive flag selects it — a reader that
// asked for the option simply gets the notification first. Routing it through
// the error queue would require `MSG_ERRQUEUE` and would let notifications
// queue up behind one another; neither is the contract.

use alloc::vec::Vec;

use crate::cmsg::payload;

/// One pending path-MTU notification. The cell holds at most one: a later
/// refusal replaces an unread earlier one rather than queueing behind it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathMtu {
    /// The MTU the datagram would have had to fit, with the extension headers
    /// the socket carries already subtracted and the fixed header added back.
    pub mtu: u32,
    /// The destination that could not be reached.
    pub dst: [u8; 16],
    /// The outgoing interface, published as the address scope.
    pub scope_id: u32,
}

/// Whether a failed transmit produces a notification.
///
/// Three conditions, all required: the socket asked for the option, the socket
/// forbade fragmentation for this send, and the refusal was a size refusal. A
/// size refusal on a socket that permits fragmentation is an ordinary error,
/// and a socket that never asked stores nothing at all. # C: O(1)
pub fn notifies(recvpathmtu: bool, dontfrag: bool, failure: crate::NetError) -> bool {
    recvpathmtu && dontfrag && failure == crate::NetError::Emsgsize
}

/// The MTU a notification reports: the path MTU with the extension-header
/// bytes this send would have carried taken off. A send with no extension
/// headers reports the path MTU itself. # C: O(1)
pub fn reported_mtu(path_mtu: u32, extension_bytes: u32) -> u32 {
    path_mtu.saturating_sub(extension_bytes)
}

/// The extension-header bytes one send would have carried, which is what the
/// reported MTU has to leave room for. # C: O(1)
pub fn extension_bytes(control: &crate::send_control::Raw6Control) -> u32 {
    let len = |bytes: &Option<Vec<u8>>| bytes.as_ref().map_or(0, Vec::len);
    (len(&control.hop_options) + len(&control.dst_before_routing) + len(&control.routing)
        + len(&control.dst_after_routing)) as u32
}

/// Whether an ordinary receive drains the cell before the datagram queue. No
/// receive flag takes part: the option bit and a full cell are the whole
/// condition. # C: O(1)
pub fn drains_before_queue(recvpathmtu: bool, pending: bool) -> bool {
    recvpathmtu && pending
}

/// `struct ip6_mtuinfo`: the destination as a socket address — family, no
/// port, no flow info, the interface as the scope — then the MTU. # C: O(1)
pub fn mtuinfo(note: &PathMtu) -> Vec<u8> {
    let mut out = Vec::with_capacity(super::uapi::IP6_MTUINFO_SIZE);
    out.extend_from_slice(&payload::sockaddr_in6(note.dst, 0, note.scope_id));
    out.extend_from_slice(&note.mtu.to_ne_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetError;

    const DST: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    // All three conditions are load-bearing: drop any one and no notification
    // is produced.
    #[test]
    fn a_notification_needs_the_option_the_refusal_and_the_fragmentation_ban() {
        assert!(notifies(true, true, NetError::Emsgsize));
        assert!(!notifies(false, true, NetError::Emsgsize));
        assert!(!notifies(true, false, NetError::Emsgsize));
        assert!(!notifies(true, true, NetError::Enodev));
    }

    // The reported MTU is what the payload would have had to fit, so the
    // extension headers this send carries come off it.
    #[test]
    fn the_reported_mtu_excludes_the_extension_headers_the_send_carried() {
        assert_eq!(reported_mtu(1500, 0), 1500);
        assert_eq!(reported_mtu(1500, 24), 1476);
        assert_eq!(reported_mtu(8, 24), 0, "never wraps below zero");
    }

    #[test]
    fn the_extension_bytes_are_every_header_the_send_would_have_carried() {
        use crate::send_control::Raw6Control;
        assert_eq!(extension_bytes(&Raw6Control::default()), 0);
        let control = Raw6Control { hop_options: Some(alloc::vec![0; 8]),
            dst_before_routing: Some(alloc::vec![0; 16]), routing: Some(alloc::vec![0; 24]),
            dst_after_routing: Some(alloc::vec![0; 8]), ..Default::default() };
        assert_eq!(extension_bytes(&control), 56);
    }

    // No receive flag takes part — an ordinary receive drains the cell.
    #[test]
    fn an_ordinary_receive_drains_the_cell_and_an_unset_option_does_not() {
        assert!(drains_before_queue(true, true));
        assert!(!drains_before_queue(true, false));
        assert!(!drains_before_queue(false, true));
    }

    // A drained notification is the WHOLE control answer: it displaces every
    // per-datagram message, because this receive consumed no datagram. And it
    // is published even by a socket that turned on no other receive option,
    // which the ordinary "did anything get asked for" shortcut would drop.
    #[test]
    fn a_drained_notification_is_the_whole_control_answer() {
        let note = PathMtu { mtu: 1280, dst: DST, scope_id: 4 };
        let rcv = crate::recv_result::Received::path_mtu(note);
        let meta = rcv.rx_meta(None);
        let plan = crate::cmsg::plan(&crate::cmsg::Want::default(), &meta);
        assert_eq!(plan.len(), 1);
        assert_eq!((plan[0].level, plan[0].kind), (crate::cmsg::SOL_IPV6, crate::cmsg::IPV6_PATHMTU));
        assert_eq!(plan[0].bytes, mtuinfo(&note));

        let noisy = crate::cmsg::Want { pktinfo6: true, hoplimit6: true, tclass6: true,
            ..Default::default() };
        assert_eq!(crate::cmsg::plan(&noisy, &meta).len(), 1);
    }

    // The receive names the destination the notification is about, so a caller
    // that passed `msg_name` learns which peer could not be reached.
    #[test]
    fn the_notification_receive_carries_no_payload_and_names_the_destination() {
        let rcv = crate::recv_result::Received::path_mtu(
            PathMtu { mtu: 1280, dst: DST, scope_id: 4 });
        assert!(rcv.payload.is_empty());
        assert_eq!(rcv.full_len, 0);
        assert_eq!(rcv.peer6, Some((crate::Ipv6Addr(DST), 0, 4)));
    }

    #[test]
    fn the_notification_encodes_a_scoped_address_then_the_mtu() {
        let note = PathMtu { mtu: 1280, dst: DST, scope_id: 4 };
        let bytes = mtuinfo(&note);
        assert_eq!(bytes.len(), super::super::uapi::IP6_MTUINFO_SIZE);
        assert_eq!(u16::from_ne_bytes(bytes[..2].try_into().unwrap()),
            crate::socket_args::AF_INET6 as u16);
        assert_eq!(&bytes[2..4], &0u16.to_be_bytes(), "no port");
        assert_eq!(&bytes[4..8], &0u32.to_ne_bytes(), "no flow info");
        assert_eq!(&bytes[8..24], &DST);
        assert_eq!(u32::from_ne_bytes(bytes[24..28].try_into().unwrap()), 4);
        assert_eq!(u32::from_ne_bytes(bytes[28..32].try_into().unwrap()), 1280);
    }
}
