use super::*;

impl IfaceRegistry {
    /// Look up a registered iface by id, restricted to the given namespace. # C: O(N)
    pub fn lookup_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<dyn NetDev>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| Arc::clone(&e.dev))
    }

    /// Canonical IPv4 neighbour cache for one live interface generation. # C: O(N)
    pub fn arp_cache_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<crate::arp::ArpCache>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| e.arp.clone())
    }

    /// The IPv6 half of one interface's neighbour table. # C: O(N)
    pub fn ndp_cache_for(&self, id: NetIfaceId) -> Option<Arc<crate::neigh::NeighCache<crate::Ipv6Addr>>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live()).map(|e| e.ndp.clone())
    }

    /// Resolve one Linux-visible interface index in its owning namespace. # C: O(N)
    pub fn lookup_ifindex_in_ns(&self, ifindex: u32, ns: u64) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.ifindex == ifindex && e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Return the namespace-local index for an internal handle. # C: O(N)
    pub fn ifindex_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns && e.ingress.live() && e.ingress.ready()).map(|e| e.ifindex)
    }

    /// Return an interface's current index across teardown fallback paths. # C: O(N)
    pub fn ifindex(&self, id: NetIfaceId) -> Option<u32> {
        let g = self.inner.lock(); g.entries.iter().find(|e| e.id == id && e.ingress.live()).map(|e| e.ifindex)
    }

    /// Return the canonical registry-owned name for one live interface. # C: O(N)
    pub fn name_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<String> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns && e.ingress.live() && e.ingress.ready()).map(|e| e.name.clone())
    }

    /// Network namespace that canonically owns `id`. # C: O(N)
    pub fn namespace(&self, id: NetIfaceId) -> Option<u64> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live() && e.ingress.ready()).map(|e| e.ns)
    }

    #[cfg(test)]
    pub(crate) fn registered(&self, id: NetIfaceId) -> bool { self.inner.lock().entries.iter().any(|entry| entry.id == id) }

    /// Interface-owned multicast transition ordering in one namespace. # C: O(N)
    pub(crate) fn mcast_report_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<McastReportState>> {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == id && entry.ns == ns && entry.ingress.live() && entry.ingress.ready())
            .map(|entry| entry.mcast_report.clone())
    }

    /// Init-NS lookup compatibility shim. # C: O(N)
    pub fn lookup(&self, id: NetIfaceId) -> Option<Arc<dyn NetDev>> { self.lookup_in_ns(id, 0) }

    /// Look up by stable name within the given namespace. # C: O(N)
    pub fn lookup_name_in_ns(&self, name: &str, ns: u64) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.name == name && e.ns == ns && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Init-NS name lookup compatibility shim. # C: O(N)
    pub fn lookup_name(&self, name: &str) -> Option<(NetIfaceId, Arc<dyn NetDev>)> { self.lookup_name_in_ns(name, 0) }
}
