//! RTM_*NEIGH control-plane bridge to the canonical neighbour caches.
//!
//! No new table: AF_INET reads/writes the per-interface `arp::ArpCache`
//! (the same NUD owner `SIOCSARP` mutates); AF_INET6 reads/writes the
//! stack-level NDP binding map (`ndp_insert`/`ndp_lookup`).

use super::*;

/// One IPv4 neighbour row for RTM_GETNEIGH, keyed by namespace-local ifindex.
pub struct NeighV4 {
    pub ifindex: u32,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub state: crate::arp::NudState,
}

/// Outcome of one RTM_NEWNEIGH / RTM_DELNEIGH mutation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NeighAdminError {
    /// `ndm_ifindex` resolves to no live interface in the caller's namespace.
    NoDev,
    /// RTM_DELNEIGH named an entry the canonical cache does not hold.
    NotFound,
}

impl NetStack {
    /// Snapshot every IPv4 neighbour live in `ns`, reading each interface's
    /// canonical `ArpCache` (RTM_GETNEIGH). # C: O(N ifaces * N entries)
    pub fn neigh_snapshot_v4_ns(&self, ns: u64) -> Vec<NeighV4> {
        let mut out = Vec::new();
        for snap in self.ifaces.snapshot_in_ns(ns) {
            let Some(cache) = self.ifaces.arp_cache_in_ns(snap.id, ns) else { continue };
            for (ip, mac, state) in cache.snapshot_states() {
                out.push(NeighV4 { ifindex: snap.ifindex, ip, mac, state });
            }
        }
        out
    }

    /// Snapshot every IPv6 neighbour live in `ns` (RTM_GETNEIGH). # C: O(N)
    pub fn neigh_snapshot_v6_ns(&self, ns: u64) -> Vec<(u32, Ipv6Addr, MacAddr)> {
        self.ndp_snapshot_in_ns(ns)
    }

    /// Install/refresh one IPv4 neighbour from the control plane (RTM_NEWNEIGH),
    /// resuming any TX jobs the resolution unblocks. # C: O(log N)
    pub fn neigh_add_v4(&self, ns: u64, ifindex: u32, ip: Ipv4Addr, mac: MacAddr,
                        permanent: bool) -> Result<(), NeighAdminError> {
        let _rtnl = self.rtnl_lock();
        let (id, _) = self.ifaces.lookup_ifindex_in_ns(ifindex, ns).ok_or(NeighAdminError::NoDev)?;
        let cache = self.ifaces.arp_cache_in_ns(id, ns).ok_or(NeighAdminError::NoDev)?;
        for job in cache.admin_set(ip, Some(mac), permanent, super::net_now_ns()) { job.resume(); }
        Ok(())
    }

    /// Remove one IPv4 neighbour from the control plane (RTM_DELNEIGH),
    /// failing queued packets its resolution can no longer complete. # C: O(log N)
    pub fn neigh_del_v4(&self, ns: u64, ifindex: u32, ip: Ipv4Addr)
        -> Result<(), NeighAdminError> {
        let _rtnl = self.rtnl_lock();
        let (id, _) = self.ifaces.lookup_ifindex_in_ns(ifindex, ns).ok_or(NeighAdminError::NoDev)?;
        let cache = self.ifaces.arp_cache_in_ns(id, ns).ok_or(NeighAdminError::NoDev)?;
        let pending = cache.admin_remove(ip).ok_or(NeighAdminError::NotFound)?;
        for job in pending { job.complete(Err(NetError::Ehostunreach)); }
        Ok(())
    }

    /// Install/refresh one IPv6 neighbour from the control plane (RTM_NEWNEIGH). # C: O(log N)
    pub fn neigh_add_v6(&self, ns: u64, ifindex: u32, ip: Ipv6Addr, mac: MacAddr)
        -> Result<(), NeighAdminError> {
        let _rtnl = self.rtnl_lock();
        let (id, _) = self.ifaces.lookup_ifindex_in_ns(ifindex, ns).ok_or(NeighAdminError::NoDev)?;
        self.ndp_insert(id, ip, mac);
        Ok(())
    }

    /// Remove one IPv6 neighbour from the control plane (RTM_DELNEIGH). # C: O(log N)
    pub fn neigh_del_v6(&self, ns: u64, ifindex: u32, ip: Ipv6Addr)
        -> Result<(), NeighAdminError> {
        let _rtnl = self.rtnl_lock();
        let (id, _) = self.ifaces.lookup_ifindex_in_ns(ifindex, ns).ok_or(NeighAdminError::NoDev)?;
        self.ndp_remove(id, ip).map(|_| ()).ok_or(NeighAdminError::NotFound)
    }
}
