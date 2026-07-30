use super::*;

pub(super) enum TcpTxPolicy<'a> {
    Entry(&'a TcpEntry),
}

impl TcpTxPolicy<'_> {
    fn owner(&self) -> &crate::SocketOwner {
        match self {
            Self::Entry(entry) => &entry.owner,
        }
    }

    fn ipv4_mode(&self) -> i32 {
        use ::core::sync::atomic::Ordering;
        match self {
            Self::Entry(entry) => entry.ip_mtu_discover.load(Ordering::Acquire),
        }
    }

    fn ipv6_mode(&self) -> i32 {
        use ::core::sync::atomic::Ordering;
        match self {
            Self::Entry(entry) => entry.ipv6_mtu_discover.load(Ordering::Acquire),
        }
    }

    fn note_congestion(&self) {
        match self {
            Self::Entry(entry) => crate::tcp_cc::on_ece(&mut entry.conn.lock()),
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
        let verdict = match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.send_tcp_ipv4_segment_in(
                net_ns, src, dst, segment, tos, bound, policy.ipv4_mode(), Some(policy.owner()),
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
                    Some(policy.owner()),
                )
            }
            _ => Err(NetError::Einval),
        }?;
        if verdict == crate::cgroup_bpf::EgressVerdict::Congestion {
            policy.note_congestion();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_notification_reaches_tcp_congestion_control() {
        let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_001 };
        let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_002 };
        let mut conn = TcpConn::new_client(local, remote, 1);
        conn.cwnd = 16_000;
        let entry = TcpEntry::new(conn);
        TcpTxPolicy::Entry(&entry).note_congestion();
        let conn = entry.conn.lock();
        assert!(conn.send_cwr);
        assert!(conn.cwnd < 16_000);
    }
}
