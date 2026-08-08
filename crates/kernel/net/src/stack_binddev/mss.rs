// The route questions a socket asks that are not a transmit: the metrics its
// connection starts from, the MSS it advertises, and the path MTU it segments
// to. Each is answered by the route the socket's `SO_MARK` selects, because a
// mark that names another routing table names another route.

use super::{IPV4_TCP_OVERHEAD, IPV6_TCP_OVERHEAD, UNMARKED};
use crate::addr::{IpAddr, NetIfaceId};
use crate::netdev::NetResult;
use crate::stack::NetStack;

impl NetStack {
    /// Metrics from the exact IPv4 route selected for a new transport TCB. # C: O(N)
    pub(crate) fn route_metrics_for_dst_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>) -> crate::RouteMetrics {
        self.route_metrics_for_dst_mark_in(net_ns, dst, bound, UNMARKED)
    }

    /// Metrics from the IPv4 route this socket's `SO_MARK` selects. A mark
    /// that names another routing table names another route, whose metrics are
    /// the ones the connection actually runs under. # C: O(N)
    pub(crate) fn route_metrics_for_dst_mark_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>, mark: u32) -> crate::RouteMetrics {
        let IpAddr::V4(dst) = dst else { return crate::RouteMetrics::NONE; };
        match bound {
            Some(iface) => self.route_v4_on_iface_in(net_ns, dst, iface, mark)
                .ok().flatten().map(|route| route.metrics),
            None => self.routes.lookup_result_mark_in(net_ns, dst, mark).ok()
                .map(|route| route.metrics),
        }.unwrap_or(crate::RouteMetrics::NONE)
    }

    /// TCP MSS for `dst`, honoring a socket-bound egress interface. # C: O(N)
    pub fn mss_for_dst_on_iface(&self, dst: IpAddr, bound: Option<NetIfaceId>) -> u16 {
        self.mss_for_dst_on_iface_in(0, dst, bound)
    }

    /// TCP MSS in one network namespace, honoring a bound interface. # C: O(N)
    pub fn mss_for_dst_on_iface_in(&self, net_ns: u64, dst: IpAddr, bound: Option<NetIfaceId>) -> u16 {
        self.mss_for_dst_on_iface_pmtu_in(
            net_ns, dst, bound, crate::uapi::IP_PMTUDISC_WANT, UNMARKED)
    }

    /// TCP MSS from effective route PMTU and socket discovery policy. # C: O(N)
    pub(crate) fn mss_for_dst_on_iface_pmtu_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>, mode: i32, mark: u32) -> u16
    {
        self.mss_for_dst_on_iface_pmtu_modes_in(net_ns, dst, bound, mode, mode, mark)
    }

    /// TCP MSS using the PMTU owner selected by destination family, over the
    /// route the socket's `SO_MARK` selects. # C: O(N)
    pub(crate) fn mss_for_dst_on_iface_pmtu_modes_in(&self, net_ns: u64, dst: IpAddr,
        bound: Option<NetIfaceId>, ip_mode: i32, ipv6_mode: i32, mark: u32) -> u16
    {
        let overhead = if matches!(dst, IpAddr::V6(_)) {
            IPV6_TCP_OVERHEAD
        } else { IPV4_TCP_OVERHEAD };
        let route_advmss = match dst {
            IpAddr::V4(dst) => match bound {
                Some(iface) => self.route_v4_on_iface_in(net_ns, dst, iface, mark)
                    .ok().flatten().map(|route| route.metrics.advmss),
                None => self.routes.lookup_result_mark_in(net_ns, dst, mark)
                    .ok().map(|route| route.metrics.advmss),
            }.unwrap_or(0),
            IpAddr::V6(_) => 0,
        };
        self.tcp_path_mtu_in(net_ns, dst, bound, ip_mode, ipv6_mode, mark).ok()
            .map(|mtu| mtu.saturating_sub(overhead).min(u16::MAX as u32) as u16)
            .map(|mss| if route_advmss == 0 {
                mss
            } else {
                mss.min(route_advmss.min(u16::MAX as u32) as u16)
            })
            .unwrap_or(0)
    }

    /// Path MTU selected by this TCP socket's destination family and PMTU mode. # C: O(N)
    pub(crate) fn tcp_path_mtu_in(&self, net_ns: u64, dst: IpAddr, bound: Option<NetIfaceId>,
        ip_mode: i32, ipv6_mode: i32, mark: u32) -> NetResult<u32>
    {
        let probe = match dst {
            IpAddr::V4(_) => crate::uapi::ip_pmtudisc_uses_interface(ip_mode),
            IpAddr::V6(_) => crate::uapi::ipv6_pmtudisc_uses_interface(ipv6_mode),
        };
        self.path_mtu_mark_in(net_ns, dst, bound, probe, mark)
    }
}
