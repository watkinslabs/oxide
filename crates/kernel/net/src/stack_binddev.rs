use alloc::sync::Arc;

use crate::addr::{IpAddr, IpProto, Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::ipv4::IPV4_HDR_LEN;
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::{RouteEntry, RouteRecord, RTN_BLACKHOLE, RTN_LOCAL, RTN_PROHIBIT,
    RTN_THROW, RTN_UNICAST, RTN_UNREACHABLE};
use crate::stack::{NetStack, TcpEntry};

const IPV4_TCP_OVERHEAD: u32 = 40;
const IPV6_TCP_OVERHEAD: u32 = 60;
pub(crate) const TCP_ISN_STEP: u32 = 0x1000;
pub(crate) const TCP_ISN_INITIAL: u32 = 0x1000_0000;

fn usable_route(record: RouteRecord) -> NetResult<RouteEntry> {
    match record.kind {
        RTN_UNICAST | RTN_LOCAL => Ok(record.route),
        RTN_BLACKHOLE => Err(NetError::Einval),
        RTN_UNREACHABLE => Err(NetError::Ehostunreach),
        RTN_PROHIBIT => Err(NetError::Eacces),
        RTN_THROW => Err(NetError::Enetunreach),
        _ => Err(NetError::Eopnotsupp),
    }
}

impl NetStack {
    /// Resolve a raw SO_BINDTODEVICE ifindex. 0 means unbound. # C: O(N)
    pub fn bound_iface(&self, raw: u32) -> NetResult<Option<NetIfaceId>> {
        self.bound_iface_in(0, raw)
    }

    /// Resolve SO_BINDTODEVICE in one network namespace. # C: O(N)
    pub fn bound_iface_in(&self, net_ns: u64, raw: u32) -> NetResult<Option<NetIfaceId>> {
        if raw == 0 { return Ok(None); }
        let id = NetIfaceId::from_raw(raw);
        self.ifaces.lookup_in_ns(id, net_ns).map(|_| Some(id)).ok_or(NetError::Enodev)
    }

    /// TCP MSS for `dst`, honoring a socket-bound egress interface. # C: O(N)
    pub fn mss_for_dst_on_iface(&self, dst: IpAddr, bound: Option<NetIfaceId>) -> u16 {
        self.mss_for_dst_on_iface_in(0, dst, bound)
    }

    /// TCP MSS in one network namespace, honoring a bound interface. # C: O(N)
    pub fn mss_for_dst_on_iface_in(&self, net_ns: u64, dst: IpAddr, bound: Option<NetIfaceId>) -> u16 {
        self.mss_for_dst_on_iface_pmtu_in(
            net_ns, dst, bound, crate::uapi::IP_PMTUDISC_WANT)
    }

    /// TCP MSS from effective route PMTU and socket discovery policy. # C: O(N)
    pub(crate) fn mss_for_dst_on_iface_pmtu_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>, mode: i32) -> u16
    {
        self.mss_for_dst_on_iface_pmtu_modes_in(net_ns, dst, bound, mode, mode)
    }

    /// TCP MSS using the PMTU owner selected by destination family. # C: O(N)
    pub(crate) fn mss_for_dst_on_iface_pmtu_modes_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>, ip_mode: i32, ipv6_mode: i32) -> u16
    {
        let probe = match dst {
            IpAddr::V4(_) => crate::uapi::ip_pmtudisc_uses_interface(ip_mode),
            IpAddr::V6(_) => crate::uapi::ipv6_pmtudisc_uses_interface(ipv6_mode),
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) {
            IPV6_TCP_OVERHEAD
        } else { IPV4_TCP_OVERHEAD };
        self.path_mtu_in(net_ns, dst, bound, probe).ok()
            .map(|mtu| mtu.saturating_sub(overhead).min(u16::MAX as u32) as u16)
            .unwrap_or(0)
    }

    /// Build + transmit UDP/IPv4, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_udp_to_bound(&self, src_ip: Ipv4Addr, src_port: u16,
        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>)
        -> NetResult<()>
    {
        self.send_udp_to_bound_opts(src_ip, src_port, dst_ip, dst_port, payload, bound, 0, crate::ipv4::IPV4_DEFAULT_TTL)
    }

    /// Build + transmit UDP/IPv4 with explicit TOS/TTL. # C: O(payload + N)
    pub fn send_udp_to_bound_opts(&self, src_ip: Ipv4Addr, src_port: u16,
        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8)
        -> NetResult<()>
    {
        self.send_udp_to_bound_opts_in(0, src_ip, src_port, dst_ip, dst_port, payload, bound, tos, ttl)
    }

    /// Build and transmit UDP/IPv4 in one network namespace. # C: O(payload + N)
    pub fn send_udp_to_bound_opts_in(&self, net_ns: u64, src_ip: Ipv4Addr, src_port: u16,
        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        tos: u8, ttl: u8) -> NetResult<()>
    {
        let (iface_id, iface, next_hop) = self.route_v4_iface_in(net_ns, dst_ip, bound)?;
        let total = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        crate::udp::UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = self.next_ipv4_id();
        self.xmit_ipv4_l4_on_iface_opts(
            iface_id, iface, next_hop, src_ip, dst_ip, IpProto::Udp, p.data(), tos, ttl, id,
        )
    }

    /// Build + transmit UDP/IPv6, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_udp6_to_bound(&self, src_ip: Ipv6Addr, src_port: u16,
        dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>)
        -> NetResult<()>
    {
        self.send_udp6_to_bound_opts(src_ip, src_port, dst_ip, dst_port, payload, bound,
            crate::ipv6::IPV6_DEFAULT_HOP_LIMIT)
    }

    /// `send_udp6_to_bound` with an explicit hop limit resolved from the
    /// socket's IPV6_UNICAST_HOPS / IPV6_MULTICAST_HOPS. # C: O(payload + N)
    pub fn send_udp6_to_bound_opts(&self, src_ip: Ipv6Addr, src_port: u16,
        dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8)
        -> NetResult<()>
    {
        self.send_udp6_to_bound_opts_in(0, src_ip, src_port, dst_ip, dst_port, payload, bound, hop_limit)
    }

    /// Build and transmit UDP/IPv6 in one network namespace. # C: O(payload + N)
    pub fn send_udp6_to_bound_opts_in(&self, net_ns: u64, src_ip: Ipv6Addr, src_port: u16,
        dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8], bound: Option<NetIfaceId>,
        hop_limit: u8) -> NetResult<()>
    {
        let src_ip = if src_ip == Ipv6Addr::ANY && dst_ip == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else {
            src_ip
        };
        let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst_ip, bound)?;
        let src_hint = self.routes6.lookup_policy_iface_in(
            net_ns, dst_ip, iface_id, self.policy_rules()).and_then(|route| route.src_hint);
        let src_ip = if src_ip.is_unspecified() {
            self.v6_select_source(iface_id, dst_ip, src_hint).ok_or(NetError::Eaddrnotavail)?
        } else { src_ip };
        let l4_len = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(0, l4_len);
        let body = p.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src_ip, dst_ip, payload, body);
        self.xmit_ipv6_l4_on_iface_opts(
            iface_id, iface, next_hop, src_ip, dst_ip, IpProto::Udp, p.data(), hop_limit,
        )
    }

    /// Active TCP open with a socket-bound egress interface. # C: O(log N + payload)
    pub fn tcp_connect_ip_bound(&self, local_ip: IpAddr, local_port: u16,
        remote_ip: IpAddr, remote_port: u16, bound: Option<NetIfaceId>,
        error: Arc<crate::SocketError>)
        -> NetResult<Arc<TcpEntry>>
    {
        let bind = self.tcp_reserve(local_ip, local_port, bound, false, false, 0,
            matches!(local_ip, IpAddr::V6(_)))?;
        self.tcp_connect_reserved(&bind, local_ip, remote_ip, remote_port, error)
    }

    /// Family-dispatched L4 transmit, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_l4_over_ip_bound(&self, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], bound: Option<NetIfaceId>) -> NetResult<()>
    {
        self.send_l4_over_ip_bound_in(0, src, dst, proto, l4, bound)
    }

    /// Family-dispatched L4 transmit in one network namespace. # C: O(payload + N)
    pub fn send_l4_over_ip_bound_in(&self, net_ns: u64, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], bound: Option<NetIfaceId>) -> NetResult<()> {
        self.send_l4_over_ip_tos_bound_in(net_ns, src, dst, proto, l4, 0, bound)
    }

    /// TOS/traffic-class L4 transmit, optionally pinned to an iface. # C: O(payload + N)
    pub fn send_l4_over_ip_tos_bound(&self, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], tos: u8, bound: Option<NetIfaceId>) -> NetResult<()>
    {
        self.send_l4_over_ip_tos_bound_in(0, src, dst, proto, l4, tos, bound)
    }

    /// TOS-aware L4 transmit in one network namespace. # C: O(payload + N)
    pub fn send_l4_over_ip_tos_bound_in(&self, net_ns: u64, src: IpAddr, dst: IpAddr,
        proto: IpProto, l4: &[u8], tos: u8, bound: Option<NetIfaceId>) -> NetResult<()> {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => self.send_l4_over_ipv4_bound(net_ns, s, d, proto, l4, tos, bound),
            (IpAddr::V6(s), IpAddr::V6(d)) => self.send_l4_over_ipv6_bound(net_ns, s, d, proto, l4, bound),
            _ => Err(NetError::Einval),
        }
    }

    fn send_l4_over_ipv4_bound(&self, net_ns: u64, src: Ipv4Addr, dst: Ipv4Addr,
        proto: IpProto, l4: &[u8], tos: u8, bound: Option<NetIfaceId>) -> NetResult<()>
    {
        let (iface_id, iface, next_hop) = self.route_v4_iface_in(net_ns, dst, bound)?;
        self.xmit_ipv4_l4_on_iface(
            iface_id, iface, next_hop, src, dst, proto, l4, tos, self.next_ipv4_id(),
        )
    }

    fn send_l4_over_ipv6_bound(&self, net_ns: u64, src: Ipv6Addr, dst: Ipv6Addr,
        proto: IpProto, l4: &[u8], bound: Option<NetIfaceId>) -> NetResult<()>
    {
        let (iface_id, iface, next_hop) = self.route_v6_iface_in(net_ns, dst, bound)?;
        self.xmit_ipv6_l4_on_iface(iface_id, iface, next_hop, src, dst, proto, l4)
    }

    /// Resolve IPv4 egress and capture its route-selected next hop. # C: O(N)
    pub(crate) fn route_v4_iface_in(&self, net_ns: u64, dst: Ipv4Addr, bound: Option<NetIfaceId>)
        -> NetResult<(NetIfaceId, crate::EgressLease, Ipv4Addr)>
    {
        if let Some(id) = bound {
            let iface = self.ifaces.acquire_egress_in_ns(id, net_ns).ok_or(NetError::Enetunreach)?;
            let next_hop = match self.route_v4_on_iface_in(net_ns, dst, id)? {
                Some(route) => route.gateway.unwrap_or(dst),
                None if dst.is_broadcast() => dst,
                None => return Err(NetError::Enetunreach),
            };
            return Ok((id, iface, next_hop));
        }
        match self.routes.lookup_result_in(net_ns, dst) {
            Ok(r) => Ok((r.iface, self.ifaces.acquire_egress_in_ns(r.iface, net_ns)
                .ok_or(NetError::Enetunreach)?, r.gateway.unwrap_or(dst))),
            Err(NetError::Enetunreach) if dst.is_broadcast()
                && self.routes.lookup_record_in(net_ns, dst).is_none() => {
                let devs = self.ifaces.snapshot_devs_in_ns(net_ns);
                let pick = devs.iter().find(|(_, d)| {
                    d.hardware_type() != crate::uapi::ARPHRD_LOOPBACK
                }).ok_or(NetError::Enetunreach)?;
                let iface = self.ifaces.acquire_egress_in_ns(pick.0, net_ns)
                    .ok_or(NetError::Enetunreach)?;
                Ok((pick.0, iface, dst))
            }
            Err(error) => Err(error),
        }
    }

    fn route_v4_on_iface_in(&self, net_ns: u64, dst: Ipv4Addr, iface: NetIfaceId)
        -> NetResult<Option<RouteEntry>>
    {
        match self.routes.lookup_result_in(net_ns, dst) {
            Ok(route) if route.iface == iface => return Ok(Some(route)),
            Err(NetError::Enetunreach) if self.routes.lookup_record_in(net_ns, dst).is_none() => {}
            Err(error) => return Err(error),
            _ => {}
        }
        let records = self.routes.snapshot_records_in(net_ns);
        for rule in self.routes.policy_rules().snapshot_effective(net_ns, crate::policy_rule::AF_INET) {
            let best = records.iter().filter(|record| {
                let route = record.route;
                route.table == rule.table && route.iface == iface && route.matches(dst)
            }).min_by_key(|record| (core::cmp::Reverse(record.route.prefix_len), record.metric));
            if let Some(record) = best {
                if record.kind == RTN_THROW { continue; }
                return usable_route(*record).map(Some);
            }
        }
        Ok(None)
    }

    /// Resolve IPv6 egress and capture its route-selected next hop. # C: O(N)
    pub(crate) fn route_v6_iface_in(&self, net_ns: u64, dst: Ipv6Addr, bound: Option<NetIfaceId>)
        -> NetResult<(NetIfaceId, crate::EgressLease, Ipv6Addr)>
    {
        if let Some(id) = bound {
            let iface = self.ifaces.acquire_egress_in_ns(id, net_ns).ok_or(NetError::Enetunreach)?;
            let next_hop = self.routes6.lookup_policy_iface_in(
                net_ns, dst, id, self.policy_rules())
                .and_then(|route| route.gateway).unwrap_or(dst);
            return Ok((id, iface, next_hop));
        }
        let route = self.routes6.lookup_policy_in(
            net_ns, dst, self.policy_rules()).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?;
        Ok((route.iface, iface, route.gateway.unwrap_or(dst)))
    }

    pub(crate) fn next_ipv4_id(&self) -> u16 {
        let mut s = self.next_ip_id.lock();
        *s = s.wrapping_add(1);
        *s
    }

    pub(crate) fn next_isn_value(&self) -> u32 {
        let mut s = self.next_isn.lock();
        *s = s.wrapping_add(TCP_ISN_STEP);
        *s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> network_namespace::NetworkNamespaceRef {
        crate::net_ns::test_support::allocate_namespace()
    }

    #[test]
    fn wildcard_udp6_checksum_uses_route_selected_source() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (iface, lo) = stack.register_loopback();
        let src = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,1,0,0,0,1]);
        let dst = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,2,0,0,0,1]);
        stack.add_v6_addr(iface, src);
        stack.routes6.add(crate::route6::Route6Entry {
            table: crate::policy_rule::RT_TABLE_MAIN, dst, prefix_len: 128, iface,
            gateway: None, src_hint: None, origin: crate::route6::Route6Origin::Static,
        });

        stack.send_udp6_to_bound_opts_in(0, Ipv6Addr::ANY, 1000, dst, 2000,
            b"checksum", Some(iface), crate::ipv6::IPV6_DEFAULT_HOP_LIMIT).unwrap();

        let packet = lo.rx_pop().unwrap();
        let header = crate::ipv6::Ipv6Hdr::parse(packet.data()).unwrap();
        assert_eq!(header.src, src);
        assert!(crate::udp::udp_checksum_v6_ok(
            &packet.data()[crate::ipv6::IPV6_HDR_LEN..], src, dst));
    }

    #[test]
    fn ipv4_send_surfaces_terminal_route_errors() {
        let cases = [
            (RTN_BLACKHOLE, NetError::Einval),
            (RTN_UNREACHABLE, NetError::Ehostunreach),
            (RTN_PROHIBIT, NetError::Eacces),
            (RTN_THROW, NetError::Enetunreach),
        ];
        for (index, (kind, expected)) in cases.into_iter().enumerate() {
            let stack = NetStack::new();
            let owner = owner();
            let net_ns = owner.id().as_u64();
            let (iface, lo) = stack.register_loopback_in(net_ns);
            let dst = Ipv4Addr::new(198, 51, 100, index as u8 + 1);
            let route = RouteEntry::main(dst, 32, iface, None, None);
            stack.routes.add_record_in(net_ns, RouteRecord {
                kind, ..RouteRecord::kernel(route)
            });

            assert_eq!(stack.send_udp_to_bound_opts_in(
                net_ns, Ipv4Addr::LOOPBACK, 1000, dst, 2000, b"x", None,
                0, crate::ipv4::IPV4_DEFAULT_TTL,
            ), Err(expected));
            assert_eq!(lo.rx_len(), 0);
        }
    }

    #[test]
    fn bound_ipv4_send_does_not_bypass_terminal_route() {
        let stack = NetStack::new();
        let owner = owner();
        let net_ns = owner.id().as_u64();
        let (iface, lo) = stack.register_loopback_in(net_ns);
        let dst = Ipv4Addr::new(203, 0, 113, 7);
        let route = RouteEntry::main(dst, 32, iface, None, None);
        stack.routes.add_record_in(net_ns, RouteRecord {
            kind: RTN_PROHIBIT, ..RouteRecord::kernel(route)
        });

        assert_eq!(stack.send_udp_to_bound_opts_in(
            net_ns, Ipv4Addr::LOOPBACK, 1000, dst, 2000, b"x", Some(iface),
            0, crate::ipv4::IPV4_DEFAULT_TTL,
        ), Err(NetError::Eacces));
        assert_eq!(lo.rx_len(), 0);
    }

    #[test]
    fn bound_ipv4_packet_keeps_iface_gateway_after_route_mutation() {
        let stack = NetStack::new();
        let owner = owner();
        let net_ns = owner.id().as_u64();
        let (iface_a, lo_a) = stack.register_loopback_in(net_ns);
        let (iface_b, lo_b) = stack.register_loopback_in(net_ns);
        let gateway_a = Ipv4Addr::new(10, 0, 0, 1);
        let gateway_b = Ipv4Addr::new(10, 1, 0, 1);
        let changed = Ipv4Addr::new(10, 1, 0, 254);
        let dst = Ipv4Addr::new(203, 0, 113, 9);
        stack.routes.add_in(net_ns, crate::route::RouteEntry::main(
            Ipv4Addr::ANY, 0, iface_a, Some(gateway_a), None,
        ));
        stack.routes.add_in(net_ns, crate::route::RouteEntry::main(
            Ipv4Addr::ANY, 0, iface_b, Some(gateway_b), None,
        ));

        stack.send_udp_to_bound_opts_in(
            net_ns, Ipv4Addr::new(10, 1, 0, 2), 1000, dst, 2000, b"x",
            Some(iface_b), 0, crate::ipv4::IPV4_DEFAULT_TTL,
        ).unwrap();
        stack.routes.retain_in(net_ns, |route| route.iface != iface_b || route.prefix_len != 0);
        stack.routes.add_in(net_ns, crate::route::RouteEntry::main(
            Ipv4Addr::ANY, 0, iface_b, Some(changed), None,
        ));

        assert_eq!(lo_a.rx_len(), 0);
        let packet = lo_b.rx_pop().unwrap();
        assert_eq!(packet.next_hop, Some(crate::pkt::TxNextHop::V4(gateway_b)));
    }

    #[test]
    fn bound_ipv6_packet_keeps_iface_gateway_and_ndp_source() {
        let stack = NetStack::new();
        let owner = owner();
        let net_ns = owner.id().as_u64();
        let (iface_a, lo_a) = stack.register_loopback_in(net_ns);
        let (iface_b, lo_b) = stack.register_loopback_in(net_ns);
        let gateway_a = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
        let gateway_b = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
        let changed = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,3]);
        let src = Ipv6Addr::from_segments([0x2001,0xdb8,1,0,0,0,0,2]);
        let dst = Ipv6Addr::from_segments([0x2001,0xdb8,2,0,0,0,0,9]);
        stack.routes6.add_in(net_ns, crate::route6::Route6Entry {
            table: crate::policy_rule::RT_TABLE_MAIN,
            dst: Ipv6Addr::ANY, prefix_len: 0, iface: iface_a,
            gateway: Some(gateway_a), src_hint: None,
            origin: crate::route6::Route6Origin::Static,
        });
        stack.routes6.add_in(net_ns, crate::route6::Route6Entry {
            table: crate::policy_rule::RT_TABLE_MAIN,
            dst: Ipv6Addr::ANY, prefix_len: 0, iface: iface_b,
            gateway: Some(gateway_b), src_hint: Some(src),
            origin: crate::route6::Route6Origin::Static,
        });

        stack.send_udp6_to_bound_opts_in(
            net_ns, src, 1000, dst, 2000, b"x", Some(iface_b),
            crate::ipv6::IPV6_DEFAULT_HOP_LIMIT,
        ).unwrap();
        stack.routes6.retain_in(net_ns, |route| route.iface != iface_b || route.prefix_len != 0);
        stack.routes6.add_in(net_ns, crate::route6::Route6Entry {
            table: crate::policy_rule::RT_TABLE_MAIN,
            dst: Ipv6Addr::ANY, prefix_len: 0, iface: iface_b,
            gateway: Some(changed), src_hint: None,
            origin: crate::route6::Route6Origin::Static,
        });

        assert_eq!(lo_a.rx_len(), 0);
        let packet = lo_b.rx_pop().unwrap();
        assert_eq!(packet.next_hop, Some(crate::pkt::TxNextHop::V6 {
            addr: gateway_b, src,
        }));
    }
}

#[cfg(test)]
#[path = "stack_binddev_pmtu_tests.rs"]
mod pmtu_tests;
