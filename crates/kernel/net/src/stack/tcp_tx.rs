use super::*;

pub(super) enum TcpTxPolicy<'a> {
    Entry(&'a TcpEntry),
    Listener(&'a TcpListenEntry),
}

impl TcpTxPolicy<'_> {
    fn ipv4_mode(&self) -> i32 {
        use ::core::sync::atomic::Ordering;
        match self {
            Self::Entry(entry) => entry.ip_mtu_discover.load(Ordering::Acquire),
            Self::Listener(listener) => listener.ip_mtu_discover.load(Ordering::Acquire),
        }
    }

    fn ipv6_mode(&self) -> i32 {
        use ::core::sync::atomic::Ordering;
        match self {
            Self::Entry(entry) => entry.ipv6_mtu_discover.load(Ordering::Acquire),
            Self::Listener(listener) => listener.ipv6_mtu_discover.load(Ordering::Acquire),
        }
    }
}

impl NetStack {
    /// Transmit a segment owned by an established socket's canonical policy. # C: O(payload + N)
    pub(crate) fn send_tcp_entry_segment_in(&self, entry: &TcpEntry, src: IpAddr, dst: IpAddr,
        segment: &[u8], tos: u8) -> NetResult<()>
    {
        self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, tos, entry.bound_iface(),
            TcpTxPolicy::Entry(entry))
    }

    /// Canonical TCP segment transmit with family-specific socket PMTU policy. # C: O(payload + N)
    pub(super) fn send_tcp_segment_in(&self, net_ns: u64, src: IpAddr, dst: IpAddr,
        segment: &[u8], tos: u8, bound: Option<NetIfaceId>, policy: TcpTxPolicy<'_>)
        -> NetResult<()>
    {
        match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.send_tcp_ipv4_segment_in(
                net_ns, src, dst, segment, tos, bound, policy.ipv4_mode(),
            ),
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst, bound)?;
                let mode = policy.ipv6_mode();
                let mtu = self.path_mtu_in(net_ns, IpAddr::V6(dst), Some(iface_id),
                    crate::uapi::ipv6_pmtudisc_uses_interface(mode))? as usize;
                self.xmit_ipv6_l4_with_policy(
                    iface_id, iface, next_hop, src, dst, IpProto::Tcp, segment,
                    crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0, mtu,
                    crate::uapi::ipv6_pmtudisc_allows_fragmentation(mode),
                )
            }
            _ => Err(NetError::Einval),
        }
    }
}
