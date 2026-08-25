use super::*;

impl NetStack {
    /// Resolve canonical IPv4 PMTU transmit policy for one selected route. # C: O(log N)
    #[cfg(test)]
    pub(crate) fn ipv4_pmtu_policy(&self, net_ns: u64, iface: NetIfaceId,
        dst: Ipv4Addr, link_mtu: u32, mode: i32) -> (usize, bool, bool) {
        let route = crate::ResolvedRoute {
            iface,
            gateway: None,
            src_hint: None,
            table: crate::policy_rule::RT_TABLE_MAIN,
            priority: 0,
            metrics: crate::RouteMetrics::NONE,
        };
        self.ipv4_route_pmtu_policy(net_ns, route, dst, link_mtu, mode)
    }

    /// Apply configured route MTU/LOCK before learned PMTU state. # C: O(log N)
    pub(crate) fn ipv4_route_pmtu_policy(&self, net_ns: u64, route: crate::ResolvedRoute,
        dst: Ipv4Addr, link_mtu: u32, mode: i32) -> (usize, bool, bool) {
        let state = if crate::uapi::ip_pmtudisc_uses_interface(mode) {
            super::pmtu_cache::PmtuLookup { mtu: link_mtu, locked: false }
        } else if route.metrics.locked(crate::route_metrics::RTAX_MTU) {
            super::pmtu_cache::PmtuLookup {
                mtu: route.metrics.bounded_mtu(link_mtu),
                locked: true,
            }
        } else {
            self.inet_tables(net_ns).pmtu.lookup(
                route.iface, IpAddr::V4(dst), route.metrics.bounded_mtu(link_mtu),
            )
        };
        let df = mode == crate::uapi::IP_PMTUDISC_DO
            || mode == crate::uapi::IP_PMTUDISC_PROBE
            || mode == crate::uapi::IP_PMTUDISC_WANT && !state.locked;
        (state.mtu as usize, df, crate::uapi::ip_pmtudisc_allows_fragmentation(mode))
    }

    /// F190: ECN TOS variant. # C: O(payload)
    pub(crate) fn send_l4_over_ipv4_tos(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()>
    {
        self.send_l4_over_ipv4_tos_in(0, src, dst, proto, l4, tos)
    }

    /// Wrap an L4 segment in IPv4 using one namespace's route table. # C: O(payload + N)
    pub(crate) fn send_l4_over_ipv4_tos_in(&self, net_ns: u64, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()> {
        let route = self.routes.lookup_result_in(net_ns, dst)?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        self.xmit_ipv4_l4_on_iface(
            route, iface, crate::route::RouteRecord::next_hop_for(route.gateway, dst), src, dst, proto, l4, tos, id,
        )
    }

    /// Emit one IPv4 L4 payload on a selected iface, fragmenting when
    /// `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface(&self, route: crate::ResolvedRoute,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, id: u16) -> NetResult<()>
    {
        self.xmit_ipv4_l4_on_iface_opts(
            route, iface, next_hop, src, dst, proto, l4, tos, 0, id,
        )
    }

    /// Emit one IPv4 L4 payload with explicit TOS and TTL on a selected iface,
    /// fragmenting when `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface_opts(&self, route: crate::ResolvedRoute,
        iface: crate::EgressLease, next_hop: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16) -> NetResult<()>
    {
        let mtu = route.metrics.bounded_mtu(iface.mtu()) as usize;
        let ttl = if ttl == 0 {
            route.metrics.ipv4_hoplimit(crate::ipv4::IPV4_DEFAULT_TTL)
        } else { ttl };
        self.xmit_ipv4_l4_with_policy(
            route.iface, iface, next_hop, src, dst, proto, l4, tos, ttl, id, mtu, false, true,
            None, None,
        ).map(|_| ())
    }

    /// Transmit one TCP/IPv4 segment using the selected socket PMTU mode and
    /// the socket's sticky option area. A compiled source route retargets the
    /// route lookup, the path MTU and the wire destination at its first hop;
    /// the segment's own checksum stays bound to the final destination, which
    /// is why it is computed before this call. `mark` is the sending socket's
    /// `SO_MARK`, which selects the routing table this lookup runs against.
    /// # C: O(payload + N)
    #[allow(clippy::too_many_arguments)]
    pub(in crate::stack) fn send_tcp_ipv4_segment_in(&self, net_ns: u64, src: Ipv4Addr,
        dst: Ipv4Addr, l4: &[u8], tos: u8, bound: Option<NetIfaceId>, mode: i32,
        owner: Option<&crate::SocketOwner>,
        opts: Option<&crate::ipv4_options::Compiled>, mark: u32)
        -> NetResult<crate::cgroup_bpf::EgressVerdict>
    {
        let wire_dst = crate::ipv4_options::wire_dst(opts, dst);
        let (route, iface, next_hop) = self.route_v4_xmit_in(net_ns, wire_dst, bound, mark)?;
        if crate::ipv4_options::is_strict_route(opts) && next_hop != wire_dst {
            return Err(NetError::Enetunreach);
        }
        let (mtu, df, may_fragment) = self.ipv4_route_pmtu_policy(
            net_ns, route, wire_dst, iface.mtu(), mode,
        );
        self.xmit_ipv4_l4_with_policy(
            route.iface, iface, next_hop, src, dst, IpProto::Tcp, l4, tos,
            route.metrics.ipv4_hoplimit(crate::ipv4::IPV4_DEFAULT_TTL),
            self.next_ipv4_id(), mtu, df, may_fragment, owner, opts,
        )
    }

    /// Build and transmit UDP/IPv4 using Linux `IP_MTU_DISCOVER` policy. # C: O(payload + N)
    pub fn send_udp_pmtu_to_bound_opts(&self, src: Ipv4Addr, src_port: u16,
        dst: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8, mode: i32) -> NetResult<()>
    {
        self.send_udp_pmtu_to_bound_opts_in(0, src, src_port, dst, dst_port, payload,
            bound, tos, ttl, mode)
    }

    /// Build and transmit UDP/IPv4 using one namespace's PMTU and routes. # C: O(payload + N)
    pub fn send_udp_pmtu_to_bound_opts_in(&self, net_ns: u64, src: Ipv4Addr, src_port: u16,
        dst: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8, mode: i32) -> NetResult<()> {
        self.send_udp_pmtu_to_bound_opts_owner(None, net_ns, src, src_port, dst, dst_port,
            payload, bound, tos, ttl, mode, None, false, crate::TxMeta::NONE)
    }

    /// Build and transmit socket-owned UDP/IPv4. `no_check` is the socket's
    /// `SO_NO_CHECK`: the datagram leaves with a zero checksum field.
    /// # C: O(payload + N)
    #[allow(clippy::too_many_arguments)]
    pub fn send_udp_pmtu_to_bound_opts_owned(&self, owner: &crate::SocketOwner,
        src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, payload: &[u8],
        bound: Option<NetIfaceId>, tos: u8, ttl: u8, mode: i32,
        opts: Option<&crate::ipv4_options::Compiled>, no_check: bool, tx: crate::TxMeta)
        -> NetResult<()> {
        self.send_udp_pmtu_to_bound_opts_owner(Some(owner), owner.net_ns(), src, src_port,
            dst, dst_port, payload, bound, tos, ttl, mode, opts, no_check, tx)
    }

    /// The route, PMTU policy and header a UDP/IPv4 datagram leaves on. A
    /// compiled source route retargets every one of them at its first hop —
    /// route lookup, path MTU, wire destination and transport checksum — while
    /// the option area carries the real destination.
    /// # C: O(payload + N)
    fn send_udp_pmtu_to_bound_opts_owner(&self, owner: Option<&crate::SocketOwner>,
        net_ns: u64, src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16,
        payload: &[u8], bound: Option<NetIfaceId>, tos: u8, ttl: u8, mode: i32,
        opts: Option<&crate::ipv4_options::Compiled>, no_check: bool, tx: crate::TxMeta)
        -> NetResult<()> {
        let wire_dst = crate::ipv4_options::wire_dst(opts, dst);
        let (route, iface, next_hop) = self.route_v4_xmit_in(net_ns, wire_dst, bound, tx.mark)?;
        let (mtu, df, may_fragment) = self.ipv4_route_pmtu_policy(
            net_ns, route, wire_dst, iface.mtu(), mode,
        );
        let udp_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut packet = Pkt::with_capacity(0, udp_len);
        packet.tx = tx;
        let udp = packet.put(udp_len).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into_opts(src_port, dst_port, src, wire_dst, payload, udp, no_check);
        let id = { let mut next = self.next_ip_id.lock(); *next = next.wrapping_add(1); *next };
        self.xmit_ipv4_l4_with_policy(
            route.iface, iface, next_hop, src, dst, IpProto::Udp, packet.data(), tos,
            if ttl == 0 {
                route.metrics.ipv4_hoplimit(crate::ipv4::IPV4_DEFAULT_TTL)
            } else { ttl }, id,
            mtu, df, may_fragment, owner, opts,
        ).map(|_| ())
    }

    // F180b: send_l4 in stack_ipv6.rs.
}
