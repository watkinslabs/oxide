use super::*;

impl IfaceRegistry {
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
