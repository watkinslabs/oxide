#![allow(unused_imports)]
use super::super::*;

impl NetStack {
    /// Canonical policy-rule table owned by this network stack. # C: O(1)
    pub fn policy_rules(&self) -> &crate::policy_rule::PolicyRuleTable { self.routes.policy_rules() }

    /// F184: MSS for `dst` = egress iface MTU − (v4:40, v6:60). 0 if
    /// no iface — caller falls back to OWN_MSS_DEFAULT. # C: O(log N).
    pub fn mss_for_dst(&self, dst: IpAddr) -> u16 {
        self.mss_for_dst_in(0, dst)
    }

    /// MSS for a destination in one network namespace. # C: O(N routes)
    pub fn mss_for_dst_in(&self, net_ns: u64, dst: IpAddr) -> u16 {
        let mtu = match dst {
            IpAddr::V4(d) => self.routes.lookup_in(net_ns, d)
                .and_then(|r| self.ifaces.lookup_in_ns(r.iface, net_ns))
                .map(|i| i.mtu()),
            IpAddr::V6(d) => self.route6_iface_in(net_ns, d).map(|(_, i)| i.mtu()),
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// Resolve IPv6 egress within one network namespace. # C: O(N routes + N ifaces)
    pub(crate) fn route6_iface_in(&self, net_ns: u64, dst: Ipv6Addr)
        -> Option<(NetIfaceId, crate::EgressLease)>
    {
        let route = self.routes6.lookup_policy_in(net_ns, dst, self.policy_rules())?;
        let iface = self.ifaces.acquire_egress_in_ns(route.iface, net_ns)?;
        Some((route.iface, iface))
    }
}

