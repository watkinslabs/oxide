use super::*;

impl IfaceRegistry {
    /// Snapshot interface identity/state in the given namespace. # C: O(N)
    pub fn snapshot_in_ns(&self, ns: u64) -> Vec<IfaceSnapshot> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| IfaceSnapshot { id: e.id, name: e.name.clone(), mtu: e.dev.mtu(),
                flags: e.flags.load(Ordering::Acquire), stats: e.dev.stats() }).collect()
    }

    /// Init-NS snapshot compatibility shim. # C: O(N)
    pub fn snapshot(&self) -> Vec<IfaceSnapshot> { self.snapshot_in_ns(0) }

    /// Full-device snapshot for RTM_GETLINK within one namespace. # C: O(N)
    pub fn snapshot_devs_in_ns(&self, ns: u64) -> Vec<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter().filter(|e| e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, e.dev.clone())).collect()
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
