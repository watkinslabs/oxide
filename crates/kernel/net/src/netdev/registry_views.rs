use super::*;

impl IfaceRegistry {
    /// Apply `conf/all/disable_ipv6` to every live interface in one namespace.
    /// A concurrently created interface copies the already-updated default. # C: O(N)
    pub fn set_ipv6_disabled_all_in(&self, ns: u64, value: i64) {
        let g = self.inner.lock();
        for entry in g.entries.iter().filter(|entry| entry.ns == ns && entry.ingress.live()) {
            entry.ipv6_conf.set_value(Ipv6ConfKey::DisableIpv6, value);
        }
    }

    /// Whether IPv6 is disabled on this exact interface. # C: O(N)
    pub fn ipv6_disabled_in(&self, iface: NetIfaceId, ns: u64) -> bool {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == iface && e.ns == ns && e.ingress.live())
            .is_some_and(|e| e.ipv6_conf.value(Ipv6ConfKey::DisableIpv6) != 0)
    }

    /// Retain one live interface's IPv6 configuration owner. # C: O(N)
    pub fn ipv6_conf_by_name_in(&self, name: &str, ns: u64) -> Option<Arc<Ipv6DevConf>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.name == name && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| Arc::clone(&e.ipv6_conf))
    }

    /// Whether this interface permits an optimistic-DAD address. # C: O(N)
    pub fn ipv6_optimistic_dad_in(&self, iface: NetIfaceId, ns: u64) -> bool {
        if crate::sysctl::value_in(ns, crate::net_ns::NetSysctlKey::Ipv6OptimisticDadAll)
            .unwrap_or(0) != 0 { return true; }
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == iface && e.ns == ns && e.ingress.live())
            .is_some_and(|e| e.ipv6_conf.value(Ipv6ConfKey::OptimisticDad) != 0)
    }

    /// Whether source selection may use this interface's optimistic address. # C: O(N)
    pub fn ipv6_use_optimistic_in(&self, iface: NetIfaceId, ns: u64) -> bool {
        if crate::sysctl::value_in(ns, crate::net_ns::NetSysctlKey::Ipv6UseOptimisticAll)
            .unwrap_or(0) != 0 { return true; }
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == iface && e.ns == ns && e.ingress.live())
            .is_some_and(|e| e.ipv6_conf.value(Ipv6ConfKey::UseOptimistic) != 0)
    }

    /// Resolve one Linux-visible interface index to its device AND its receive
    /// queues — Linux `netdev_get_by_index_lock` followed by
    /// `__netif_get_rx_queue`. Both come out together because a caller that
    /// took them separately could bind a provider to the queues of a device
    /// that had already been replaced under it. # C: O(N)
    pub fn lookup_rx_queues_in_ns(&self, ifindex: u32, ns: u64)
        -> Option<(NetIfaceId, Arc<dyn NetDev>, Arc<RxQueues>)> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.ifindex == ifindex && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, Arc::clone(&e.dev), Arc::clone(&e.rx_queues)))
    }

    /// Snapshot interface identity/state in the given namespace. # C: O(N)
    pub fn snapshot_in_ns(&self, ns: u64) -> Vec<IfaceSnapshot> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| IfaceSnapshot { id: e.id, ifindex: e.ifindex, name: e.name.clone(),
                mtu: e.dev.mtu(),
                // Reported flags, not stored ones: carrier is driver state and
                // `IFF_RUNNING`/`IFF_LOWER_UP` are derived from it, as the
                // reference's `dev_get_flags` does for every reader.
                flags: super::iff::dev_get_flags(e.flags.load(Ordering::Acquire),
                                                 e.carrier.load(Ordering::Acquire)),
                stats: e.dev.stats() }).collect()
    }

    /// Init-NS snapshot compatibility shim. # C: O(N)
    pub fn snapshot(&self) -> Vec<IfaceSnapshot> { self.snapshot_in_ns(0) }

    /// Full-device snapshot for RTM_GETLINK within one namespace. # C: O(N)
    pub fn snapshot_devs_in_ns(&self, ns: u64) -> Vec<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, e.dev.clone())).collect()
    }

    /// Snapshot each live interface with its exact driver-model parent for
    /// sysfs placement. # C: O(N)
    pub fn snapshot_sysfs_in_ns(&self, ns: u64)
        -> Vec<(NetIfaceId, String, Arc<dyn NetDev>, Option<Arc<drv::Device>>)> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, e.name.clone(), e.dev.clone(), e.parent.clone())).collect()
    }

    /// Init-NS device snapshot compatibility shim. # C: O(N)
    pub fn snapshot_devs(&self) -> Vec<(NetIfaceId, Arc<dyn NetDev>)> {
        self.snapshot_devs_in_ns(0)
    }

    /// Snapshot each canonical ARP owner for one live interface generation. # C: O(N)
    pub(crate) fn arp_caches(&self) -> Vec<Arc<crate::arp::ArpCache>> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ingress.live() && e.ingress.ready())
            .map(|e| e.arp.clone()).collect()
    }
}
