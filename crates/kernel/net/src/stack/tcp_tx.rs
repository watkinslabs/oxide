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

    fn ipv6_frag_size(&self) -> i32 {
        use ::core::sync::atomic::Ordering;
        match self {
            Self::Entry(entry) => entry.ipv6_frag_size.load(Ordering::Acquire),
        }
    }

    fn ipv6_flow_label(&self) -> (u32, bool) {
        match self {
            Self::Entry(entry) => (entry.ipv6_opts.flow_label(),
                entry.ipv6_opts.flag(crate::sock_opts::sol_ipv6::flag::AUTOFLOWLABEL)),
        }
    }

    /// The sticky IPv4 option area every segment this socket emits carries.
    /// # C: O(optlen)
    fn ipv4_options(&self) -> Option<crate::ipv4_options::Compiled> {
        match self {
            Self::Entry(entry) => entry.ip_opts.options(),
        }
    }

    fn note_congestion(&self) {
        match self {
            Self::Entry(entry) => crate::tcp_cc::on_ece(&mut entry.conn.lock()),
        }
    }

    /// Account for a segment accepted by the canonical TCP output path. # C: O(1)
    fn note_transmit(&self, segment: &[u8]) {
        let Ok(header) = crate::tcp_hdr::parse_prevalidated(segment) else { return; };
        let payload_len = segment.len().saturating_sub(header.payload_offset());
        match self {
            Self::Entry(entry) => {
                let mut conn = entry.conn.lock();
                conn.segs_out = conn.segs_out.saturating_add(1);
                if payload_len != 0 {
                    conn.data_segs_out = conn.data_segs_out.saturating_add(1);
                    conn.bytes_sent = conn.bytes_sent.saturating_add(payload_len as u64);
                }
            }
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
                policy.ipv4_options().as_ref(),
            ),
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst, bound)?;
                let mode = policy.ipv6_mode();
                let mtu = crate::stack_ipv6::ipv6_output_mtu(
                    self.path_mtu_in(net_ns, IpAddr::V6(dst), Some(iface_id),
                        crate::uapi::ipv6_pmtudisc_uses_interface(mode))? as usize,
                    policy.ipv6_frag_size());
                self.xmit_ipv6_l4_with_policy(
                    iface_id, iface, next_hop, src, dst, IpProto::Tcp, segment,
                    crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0,
                    policy.ipv6_flow_label().0, policy.ipv6_flow_label().1, mtu,
                    crate::uapi::ipv6_pmtudisc_allows_fragmentation(mode),
                    Some(policy.owner()),
                )
            }
            _ => Err(NetError::Einval),
        }?;
        if verdict == crate::cgroup_bpf::EgressVerdict::Congestion {
            policy.note_congestion();
        }
        policy.note_transmit(segment);
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

    #[test]
    fn transmit_accounting_counts_each_accepted_segment_once() {
        let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_003 };
        let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_004 };
        let mut conn = TcpConn::new_client(local, remote, 1);
        conn.state = crate::tcp_state::TcpState::Established;
        let ack = conn.build_segment(crate::tcp_hdr::flags::ACK, &[]);
        let data = conn.build_segment(crate::tcp_hdr::flags::ACK, b"sent");
        let entry = TcpEntry::new(conn);

        let policy = TcpTxPolicy::Entry(&entry);
        policy.note_transmit(&ack);
        policy.note_transmit(&data);

        let conn = entry.conn.lock();
        assert_eq!(conn.segs_out, 2);
        assert_eq!(conn.data_segs_out, 1);
        assert_eq!(conn.bytes_sent, 4);
    }

    #[test]
    fn tcp_transmit_policy_reads_the_shared_ipv6_fragment_cap() {
        use ::core::sync::atomic::Ordering;
        let entry = TcpEntry::new(TcpConn::new_client(
            Endpoint { ip: IpAddr::V6(Ipv6Addr::LOOPBACK), port: 40_001 },
            Endpoint { ip: IpAddr::V6(Ipv6Addr::LOOPBACK), port: 40_002 }, 1));
        entry.ipv6_frag_size.store(1280, Ordering::Release);
        assert_eq!(TcpTxPolicy::Entry(&entry).ipv6_frag_size(), 1280);
    }

    #[test]
    fn tcp_transmit_policy_uses_its_retained_ipv6_option_owner() {
        let entry = TcpEntry::new(TcpConn::new_client(
            Endpoint { ip: IpAddr::V6(Ipv6Addr::LOOPBACK), port: 40_005 },
            Endpoint { ip: IpAddr::V6(Ipv6Addr::LOOPBACK), port: 40_006 }, 1));
        entry.ipv6_opts.set_flow_label(0x34567);
        entry.ipv6_opts.set_flag(crate::sock_opts::sol_ipv6::flag::AUTOFLOWLABEL, true);
        assert_eq!(TcpTxPolicy::Entry(&entry).ipv6_flow_label(), (0x34567, true));
    }
}
