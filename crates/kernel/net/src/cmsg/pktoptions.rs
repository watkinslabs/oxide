// `IP_PKTOPTIONS`: the ancillary messages a STREAM socket publishes on demand
// instead of per datagram. Same message numbers and same order as a receive,
// read out of what the socket recorded when the connection opened.

use alloc::vec::Vec;

use super::{IP_PKTINFO, IP_TOS, IP_TTL, Msg, SOL_IP, Want, payload};

/// What a stream socket recorded about the packet that opened it. A socket
/// that never accepted a connection carries the defaults, which is what a
/// connecting socket publishes.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamRx {
    /// The local address the connection was accepted on, published as BOTH
    /// halves of the packet-info message — the address a reply comes from is
    /// the address this end answered on.
    pub saddr: [u8; 4],
    pub ifindex: u32,
    pub ttl: i32,
    pub tos: i32,
}

/// The messages `IP_PKTOPTIONS` publishes, gated by the same receive options
/// that would have produced them per datagram.
///
/// The type-of-service byte is an `int` here, unlike the one-byte form the
/// per-datagram receive publishes: this option reports a stored value, not a
/// header field. # C: O(1)
pub fn plan(want: &Want, rx: &StreamRx) -> Vec<Msg> {
    let mut out = Vec::new();
    if want.pktinfo {
        out.push(Msg::raw(SOL_IP, IP_PKTINFO, &payload::in_pktinfo(rx.saddr, rx.ifindex)));
    }
    if want.ttl { out.push(Msg::int(SOL_IP, IP_TTL, rx.ttl)); }
    if want.tos { out.push(Msg::int(SOL_IP, IP_TOS, rx.tos)); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{IP_PKTINFO, IP_TOS, IP_TTL};

    const SADDR: [u8; 4] = [192, 0, 2, 5];

    fn rx() -> StreamRx { StreamRx { saddr: SADDR, ifindex: 7, ttl: 61, tos: 0x2c } }
    fn all() -> Want { Want { pktinfo: true, ttl: true, tos: true, ..Default::default() } }

    #[test]
    fn a_socket_that_asked_for_nothing_publishes_nothing() {
        assert!(plan(&Want::default(), &rx()).is_empty());
    }

    #[test]
    fn each_receive_option_gates_its_own_message() {
        let kinds = |w: Want| plan(&w, &rx()).iter().map(|m| m.kind).collect::<Vec<_>>();
        assert_eq!(kinds(Want { pktinfo: true, ..Default::default() }), alloc::vec![IP_PKTINFO]);
        assert_eq!(kinds(Want { ttl: true, ..Default::default() }), alloc::vec![IP_TTL]);
        assert_eq!(kinds(Want { tos: true, ..Default::default() }), alloc::vec![IP_TOS]);
        assert_eq!(kinds(all()), alloc::vec![IP_PKTINFO, IP_TTL, IP_TOS]);
    }

    #[test]
    fn the_packet_info_names_the_interface_then_the_local_address_twice() {
        let msgs = plan(&Want { pktinfo: true, ..Default::default() }, &rx());
        assert_eq!(&msgs[0].bytes[..4], &7i32.to_ne_bytes());
        assert_eq!(&msgs[0].bytes[4..8], &SADDR);
        assert_eq!(&msgs[0].bytes[8..12], &SADDR);
    }

    #[test]
    fn the_recorded_hop_limit_and_service_class_ride_back_as_ints() {
        let msgs = plan(&all(), &rx());
        assert_eq!(msgs[1].bytes, Vec::from(61i32.to_ne_bytes()));
        // NOT the one-byte form the per-datagram receive publishes.
        assert_eq!(msgs[2].bytes, Vec::from(0x2ci32.to_ne_bytes()));
        assert_eq!(msgs[2].bytes.len(), 4);
    }

    #[test]
    fn a_socket_that_never_accepted_a_connection_publishes_the_defaults() {
        let msgs = plan(&all(), &StreamRx::default());
        assert_eq!(&msgs[0].bytes[..4], &0i32.to_ne_bytes());
        assert_eq!(msgs[1].bytes, Vec::from(0i32.to_ne_bytes()));
    }
}
