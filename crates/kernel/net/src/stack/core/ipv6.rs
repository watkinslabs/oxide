#![allow(unused_imports)]
use super::super::*;

impl NetStack {
    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        let now_ns = self.ra_now_ns();
        self.v6_addrs.lock().get(&iface)
            .map(|rows| rows.iter().any(|row| row.addr == ip && row.owned_at(now_ns)))
            .unwrap_or(false)
    }
    /// True when an interface has active ownership of an IPv6 multicast group. # C: O(N groups)
    fn v6_mcast_owned_by(&self, iface: NetIfaceId, group: crate::addr::Ipv6Addr) -> bool {
        if group == crate::ndp::IPV6_ALL_NODES { return true; }
        let now_ns = self.ra_now_ns();
        if self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter().any(|row| {
            row.valid_at(now_ns) && crate::ndp::solicited_node_multicast(row.addr) == group
        })) { return true; }
        self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.group == group && !state.is_empty()))
    }
    /// True when an IPv4 multicast packet belongs to the ingress interface. # C: O(N groups + sources)
    pub(crate) fn v4_mcast_owned_by(&self, net_ns: u64, iface: NetIfaceId,
                                    group: crate::addr::Ipv4Addr, src: crate::addr::Ipv4Addr,
                                    proto: u8) -> bool {
        if group == crate::igmp::IPV4_ALL_HOSTS { return true; }
        let Some(generation) = self.ifaces.control_generation_in_ns_rx(iface, net_ns) else {
            return false;
        };
        self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|state|
            state.iface_generation() == generation && state.group == group
                && state.admits_rx(src, proto)))
    }
    /// IPv6 local-input decision with link-local interface scoping. # C: O(N addrs)
    pub(crate) fn v6_dst_is_local(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        let now_ns = self.ra_now_ns();
        if ip.is_multicast() { return self.v6_mcast_owned_by(iface, ip); }
        if self.v6_anycast_owned_by(iface, ip) { return true; }
        if ip.is_link_local() { return self.v6_addr_owned_by(iface, ip); }
        let Some(net_ns) = self.ifaces.namespace(iface) else { return false };
        self.v6_addrs.lock().iter().any(|(id, addrs)| {
            self.ifaces.namespace(*id) == Some(net_ns)
                && addrs.iter().any(|addr| addr.addr == ip && addr.owned_at(now_ns))
        })
    }
    /// Pick an IPv6 source address bound to `iface`, if one exists. # C: O(N addrs)
    pub fn v6_src_on_iface(&self, iface: NetIfaceId) -> Option<crate::addr::Ipv6Addr> {
        self.v6_select_source(iface, crate::Ipv6Addr::ANY, None)
    }

    /// Resolve an advisory route source against live address preference. # C: O(N addrs)
    pub(crate) fn v6_select_source(&self, iface: NetIfaceId, dst: crate::addr::Ipv6Addr,
        hint: Option<crate::addr::Ipv6Addr>) -> Option<crate::addr::Ipv6Addr>
    {
        self.v6_select_source_with_prefs(iface, dst, hint, 0)
    }

    /// Select a source using this socket's `IPV6_ADDR_PREFERENCES` policy.
    /// # C: O(N addrs)
    pub(crate) fn v6_select_source_with_prefs(&self, iface: NetIfaceId,
        dst: crate::addr::Ipv6Addr, hint: Option<crate::addr::Ipv6Addr>, prefs: i32)
        -> Option<crate::addr::Ipv6Addr>
    {
        self.v6_select_source_current(iface, dst, hint, prefs)
    }

    /// Learn or update an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_insert(&self, iface: NetIfaceId, ip: Ipv6Addr, mac: MacAddr) {
        // Learning releases whatever was parked on this neighbour, exactly as
        // the IPv4 half does: the packets waiting for the address are handed
        // back with it attached rather than dropped.
        if let Some(cache) = self.ifaces.ndp_cache_for(iface) {
            for job in cache.learn_at(ip, mac, crate::neigh::NudState::Reachable,
                crate::stack::net_now_ns()) { job.resume(mac); }
        }
        self.bridge_neighbour_resolved(iface, IpAddr::V6(ip));
    }

    /// Lookup an IPv6 neighbor binding scoped to `iface`.
    /// # C: O(log N)
    pub fn ndp_lookup(&self, iface: NetIfaceId, ip: Ipv6Addr) -> Option<MacAddr> {
        self.ifaces.ndp_cache_for(iface).and_then(|cache| cache.lookup(ip))
    }

    /// Remove one IPv6 neighbor binding scoped to `iface`, returning its prior
    /// link address when present (RTM_DELNEIGH). # C: O(log N)
    pub fn ndp_remove(&self, iface: NetIfaceId, ip: Ipv6Addr) -> Option<MacAddr> {
        let cache = self.ifaces.ndp_cache_for(iface)?;
        let entry = cache.remove(ip)?;
        for job in entry.pending { job.complete(Err(crate::NetError::Ehostunreach)); }
        entry.mac
    }

    /// Snapshot every IPv6 neighbor binding live in `ns`, paired with each
    /// owning interface's namespace-local index (RTM_GETNEIGH). # C: O(N)
    pub fn ndp_snapshot_in_ns(&self, ns: u64) -> Vec<(u32, Ipv6Addr, MacAddr)> {
        let mut rows: Vec<(NetIfaceId, Ipv6Addr, MacAddr)> = Vec::new();
        for (iface, _) in self.ifaces.snapshot_devs_in_ns(ns) {
            let Some(cache) = self.ifaces.ndp_cache_for(iface) else { continue };
            for (ip, mac) in cache.snapshot_bindings() { rows.push((iface, ip, mac)); }
        }
        rows.into_iter().filter_map(|(iface, ip, mac)| {
            self.ifaces.ifindex_in_ns(iface, ns).map(|ifindex| (ifindex, ip, mac))
        }).collect()
    }

}

