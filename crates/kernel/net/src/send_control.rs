extern crate alloc;

use alloc::vec::Vec;

use crate::{Ipv4Addr, Ipv6Addr, NetIfaceId};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SendControl {
    pub raw4: Raw4Control,
    pub raw6: Raw6Control,
    /// Message-level out-of-band request. The ICMP datagram endpoint class has
    /// no out-of-band channel and reports that before it screens the message
    /// type, so the flag has to reach the transport.
    pub oob: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Raw4Control {
    pub source: Option<Ipv4Addr>,
    pub iface: Option<NetIfaceId>,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub protocol: Option<u8>,
    /// `IP_OPTIONS` control message — the same compiled area the socket-level
    /// option installs, admitted by the same compile pass.
    pub options: Option<crate::ipv4_options::Compiled>,
    pub dont_route: bool,
    pub multicast_loop: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Raw6Control {
    pub source: Option<Ipv6Addr>,
    pub iface: Option<NetIfaceId>,
    pub hop_limit: Option<i32>,
    pub traffic_class: Option<i32>,
    pub flowinfo: Option<u32>,
    /// Socket `IPV6_AUTOFLOWLABEL` applies only when the message named no
    /// explicit flowinfo label.
    pub automatic_flow_label: bool,
    pub dontfrag: Option<bool>,
    pub hop_options: Option<Vec<u8>>,
    pub dst_before_routing: Option<Vec<u8>>,
    pub routing: Option<Vec<u8>>,
    pub dst_after_routing: Option<Vec<u8>>,
    pub multicast_loop: Option<bool>,
}

impl SendControl {
    /// Apply message flags whose semantics belong to raw transmit. # C: O(1)
    pub fn apply_flags(&mut self, flags: u64) {
        self.raw4.dont_route = flags & crate::uapi::MSG_DONTROUTE != 0;
        self.oob = flags & crate::uapi::MSG_OOB != 0;
    }
}

impl Raw4Control {
    /// `IP_PKTINFO`'s `ipi_spec_dst` stands in for the bound source. # C: O(1)
    pub fn v4_source(&self, socket: Ipv4Addr) -> Ipv4Addr { self.source.unwrap_or(socket) }
    /// `IP_TTL`. # C: O(1)
    pub fn v4_ttl(&self, socket: u8) -> u8 { self.ttl.unwrap_or(socket) }
    /// `IP_TOS`. # C: O(1)
    pub fn v4_tos(&self, socket: u8) -> u8 { self.tos.unwrap_or(socket) }
    /// `IP_RETOPTS` replaces the sticky `IP_OPTIONS` area outright rather than
    /// adding to it. # C: O(option bytes)
    pub fn v4_options(&self, socket: Option<crate::ipv4_options::Compiled>)
        -> Option<crate::ipv4_options::Compiled>
    { self.options.clone().or(socket) }
}

impl Raw6Control {
    /// `IPV6_HOPLIMIT`; `-1` restores the socket's own choice. # C: O(1)
    pub fn v6_hop_limit(&self, socket: u8) -> u8 {
        match self.hop_limit { Some(value) if value >= 0 => value as u8, _ => socket }
    }
    /// `IPV6_TCLASS`; `-1` restores the socket's own choice. # C: O(1)
    pub fn v6_traffic_class(&self, socket: u8) -> u8 {
        match self.traffic_class { Some(value) if value >= 0 => value as u8, _ => socket }
    }
    /// `IPV6_FLOWINFO`. A message that named a label also suppresses the
    /// socket's automatic one, which exists to fill an unnamed label. # C: O(1)
    pub fn v6_flow_label(&self, socket: u32) -> u32 { self.flowinfo.unwrap_or(socket) }
    /// # C: O(1)
    pub fn v6_autoflowlabel(&self, socket: bool) -> bool { self.flowinfo.is_none() && socket }
    /// `IPV6_PKTINFO` on the message outranks the sticky one it mirrors, field
    /// by field. # C: O(1)
    pub fn v6_pktinfo(&self, sticky: ([u8; 16], u32)) -> ([u8; 16], u32) {
        (self.source.map(|ip| ip.0).unwrap_or(sticky.0),
            self.iface.map(|iface| iface.raw()).unwrap_or(sticky.1))
    }

    /// Fill absent extension-header controls from one socket's canonical sticky state.
    /// # C: O(total header bytes)
    pub fn merge_sticky_headers(&mut self, opts: &crate::sock_opts::sol_ipv6::Ipv6Opts) {
        use crate::sock_opts::sol_ipv6::Sticky;
        if self.hop_options.is_none() { self.hop_options = opts.header(Sticky::HopOpts); }
        if self.dst_before_routing.is_none() {
            self.dst_before_routing = opts.header(Sticky::RthdrDstOpts);
        }
        if self.routing.is_none() { self.routing = opts.header(Sticky::Rthdr); }
        if self.dst_after_routing.is_none() { self.dst_after_routing = opts.header(Sticky::DstOpts); }
    }

    /// Destination used for route lookup before a type-2 routing header is emitted. # C: O(1)
    pub fn route_destination(&self, final_dst: Ipv6Addr) -> Ipv6Addr {
        let Some(header) = self.routing.as_ref() else { return final_dst };
        if header.len() < 24 { return final_dst; }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&header[8..24]);
        Ipv6Addr(bytes)
    }
}

/// Decide whether a completed send may drain locally queued multicast. # C: O(1)
pub fn should_drain_loopback(multicast: bool, message: Option<bool>, socket: bool) -> bool {
    !multicast || message.unwrap_or(socket)
}

#[cfg(test)]
mod tests {
    use super::{should_drain_loopback, Raw4Control, Raw6Control};
    use crate::{Ipv4Addr, Ipv6Addr, NetIfaceId};

    #[test]
    fn absent_ipv4_message_controls_leave_every_socket_choice_alone() {
        let none = Raw4Control::default();
        assert_eq!(none.v4_source(Ipv4Addr::new(10, 0, 0, 1)), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(none.v4_ttl(64), 64);
        assert_eq!(none.v4_tos(0x20), 0x20);
        assert!(none.v4_options(None).is_none());
    }

    #[test]
    fn each_ipv4_message_control_replaces_exactly_its_own_socket_choice() {
        let message = Raw4Control { source: Some(Ipv4Addr::new(192, 0, 2, 9)), ttl: Some(3),
            tos: Some(0x10), ..Raw4Control::default() };
        assert_eq!(message.v4_source(Ipv4Addr::new(10, 0, 0, 1)), Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(message.v4_ttl(64), 3);
        assert_eq!(message.v4_tos(0x20), 0x10);
        // The option area is the one that replaces rather than merges: a socket
        // area survives only when the message named none.
        let socket_area = crate::ipv4_options::Compiled::default();
        assert!(message.v4_options(Some(socket_area)).is_some());
    }

    #[test]
    fn the_ipv6_scalars_treat_minus_one_as_the_socket_choice() {
        let restore = Raw6Control { hop_limit: Some(-1), traffic_class: Some(-1),
            ..Raw6Control::default() };
        assert_eq!(restore.v6_hop_limit(64), 64);
        assert_eq!(restore.v6_traffic_class(0x20), 0x20);
        let named = Raw6Control { hop_limit: Some(7), traffic_class: Some(0x10),
            ..Raw6Control::default() };
        assert_eq!(named.v6_hop_limit(64), 7);
        assert_eq!(named.v6_traffic_class(0x20), 0x10);
    }

    #[test]
    fn a_named_flow_label_suppresses_the_sockets_automatic_one() {
        let none = Raw6Control::default();
        assert_eq!(none.v6_flow_label(0x11111), 0x11111);
        assert!(none.v6_autoflowlabel(true));
        let named = Raw6Control { flowinfo: Some(0x22222), ..Raw6Control::default() };
        assert_eq!(named.v6_flow_label(0x11111), 0x22222);
        assert!(!named.v6_autoflowlabel(true));
    }

    #[test]
    fn the_message_pktinfo_outranks_the_sticky_one_field_by_field() {
        let sticky = ([9u8; 16], 4u32);
        assert_eq!(Raw6Control::default().v6_pktinfo(sticky), sticky);
        let source = Raw6Control { source: Some(Ipv6Addr([1; 16])), ..Raw6Control::default() };
        assert_eq!(source.v6_pktinfo(sticky), ([1u8; 16], 4));
        let iface = Raw6Control { iface: Some(NetIfaceId::from_raw(7)), ..Raw6Control::default() };
        assert_eq!(iface.v6_pktinfo(sticky), ([9u8; 16], 7));
    }

    #[test]
    fn multicast_loop_policy_honors_message_then_socket() {
        assert!(should_drain_loopback(false, Some(false), false));
        assert!(!should_drain_loopback(true, None, false));
        assert!(should_drain_loopback(true, None, true));
        assert!(!should_drain_loopback(true, Some(false), true));
        assert!(should_drain_loopback(true, Some(true), false));
    }

    #[test]
    fn sticky_extension_headers_fill_only_absent_message_slots() {
        use crate::sock_opts::sol_ipv6::{Ipv6Opts, Sticky};
        let opts = Ipv6Opts::default();
        opts.set_header(Sticky::HopOpts, Some(alloc::vec![0; 8]));
        opts.set_header(Sticky::DstOpts, Some(alloc::vec![0; 8]));
        let message_hop = alloc::vec![1; 8];
        let mut control = Raw6Control { hop_options: Some(message_hop.clone()),
            ..Raw6Control::default() };
        control.merge_sticky_headers(&opts);
        assert_eq!(control.hop_options, Some(message_hop));
        assert_eq!(control.dst_after_routing, Some(alloc::vec![0; 8]));
    }
}
