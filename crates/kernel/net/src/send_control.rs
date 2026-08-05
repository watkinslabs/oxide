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

impl Raw6Control {
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
    use super::should_drain_loopback;

    #[test]
    fn multicast_loop_policy_honors_message_then_socket() {
        assert!(should_drain_loopback(false, Some(false), false));
        assert!(!should_drain_loopback(true, None, false));
        assert!(should_drain_loopback(true, None, true));
        assert!(!should_drain_loopback(true, Some(false), true));
        assert!(should_drain_loopback(true, Some(true), false));
    }
}
