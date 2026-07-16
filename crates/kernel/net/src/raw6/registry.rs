use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, Socket as LockClass};

use super::Raw6Endpoint;
use crate::stack::NetStack;

/// Canonical exact-protocol raw IPv6 table owned by one network namespace.
pub(crate) struct Raw6Table {
    endpoints: Spinlock<BTreeMap<u8, Vec<Weak<Raw6Endpoint>>>, LockClass>,
}

impl NetStack {
    /// Publish one raw IPv6 endpoint in its namespace-owned table. # C: O(N)
    pub fn register_raw6(&self, endpoint: &Arc<Raw6Endpoint>) {
        self.inet_tables(endpoint.net_ns()).raw6.register(endpoint);
    }

    /// Remove and close one exact raw IPv6 endpoint. # C: O(N)
    pub fn unregister_raw6(&self, endpoint: &Arc<Raw6Endpoint>) {
        endpoint.close();
        if let Some(tables) = self.try_inet_tables(endpoint.net_ns()) {
            tables.raw6.unregister(endpoint);
        }
    }
}

impl Raw6Table {
    /// Build an empty namespace-local raw IPv6 table. # C: O(1)
    pub(crate) fn new() -> Self {
        Self { endpoints: Spinlock::new(BTreeMap::new()) }
    }

    /// Publish one endpoint exactly once in its exact-protocol bucket. # C: O(N)
    pub(crate) fn register(&self, endpoint: &Arc<Raw6Endpoint>) {
        let mut all = self.endpoints.lock();
        let bucket = all.entry(endpoint.protocol()).or_default();
        bucket.retain(|weak| weak.upgrade().is_some());
        if bucket.iter().filter_map(Weak::upgrade).any(|live| Arc::ptr_eq(&live, endpoint)) {
            return;
        }
        bucket.push(Arc::downgrade(endpoint));
    }

    /// Remove one exact endpoint while preserving its protocol peers. # C: O(N)
    pub(crate) fn unregister(&self, endpoint: &Arc<Raw6Endpoint>) {
        let protocol = endpoint.protocol();
        let mut all = self.endpoints.lock();
        let mut remove = false;
        if let Some(bucket) = all.get_mut(&protocol) {
            bucket.retain(|weak| weak.upgrade().is_some_and(|live| !Arc::ptr_eq(&live, endpoint)));
            remove = bucket.is_empty();
        }
        if remove { all.remove(&protocol); }
    }

    /// Snapshot live exact-protocol endpoints without retaining the table lock. # C: O(N)
    pub(crate) fn endpoints(&self, protocol: u8) -> Vec<Arc<Raw6Endpoint>> {
        let mut all = self.endpoints.lock();
        let Some(bucket) = all.get_mut(&protocol) else { return Vec::new() };
        bucket.retain(|weak| weak.upgrade().is_some());
        bucket.iter().filter_map(Weak::upgrade).collect()
    }

    /// Snapshot every live endpoint without retaining the registry lock. # C: O(N)
    pub(crate) fn all_endpoints(&self) -> Vec<Arc<Raw6Endpoint>> {
        let mut all = self.endpoints.lock();
        let mut out = Vec::new();
        all.retain(|_, bucket| {
            bucket.retain(|weak| weak.upgrade().is_some());
            out.extend(bucket.iter().filter_map(Weak::upgrade));
            !bucket.is_empty()
        });
        out
    }

    pub(crate) fn teardown(&self) {
        for endpoint in self.all_endpoints() { endpoint.close(); }
    }

    #[cfg(test)]
    pub(crate) fn endpoint_count(&self, protocol: u8) -> usize {
        self.endpoints(protocol).len()
    }
}
