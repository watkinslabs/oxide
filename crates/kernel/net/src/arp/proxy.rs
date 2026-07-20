// IPv4 proxy-neighbour ownership — exact `pneigh` keys scoped by net namespace/device.

use alloc::collections::BTreeSet;

use sync::{Socket as ArpLockClass, Spinlock};

use crate::{Ipv4Addr, NetIfaceId};

/// Linux ARP proxy-neighbour table. An absent device means the netns-wide key.
pub(crate) struct ProxyTable {
    entries: Spinlock<BTreeSet<(u64, Option<NetIfaceId>, Ipv4Addr)>, ArpLockClass>,
}

impl ProxyTable {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: Spinlock::new(BTreeSet::new()) } }

    /// Create one exact proxy-neighbour key. # C: O(log N)
    pub(crate) fn insert(&self, net_ns: u64, iface: Option<NetIfaceId>, ip: Ipv4Addr) {
        self.entries.lock().insert((net_ns, iface, ip));
    }

    /// Remove one exact proxy-neighbour key. # C: O(log N)
    pub(crate) fn remove(&self, net_ns: u64, iface: Option<NetIfaceId>, ip: Ipv4Addr) -> bool {
        self.entries.lock().remove(&(net_ns, iface, ip))
    }

    /// Match a request against its ingress-interface or netns-wide proxy key. # C: O(log N)
    pub(crate) fn contains(&self, net_ns: u64, iface: NetIfaceId, ip: Ipv4Addr) -> bool {
        let entries = self.entries.lock();
        entries.contains(&(net_ns, Some(iface), ip)) || entries.contains(&(net_ns, None, ip))
    }

    /// Remove all proxy keys attached to a departing interface generation. # C: O(N)
    pub(crate) fn remove_iface(&self, net_ns: u64, iface: NetIfaceId) {
        self.entries.lock().retain(|(ns, id, _)| *ns != net_ns || *id != Some(iface));
    }
}
