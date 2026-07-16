use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use super::reassembly::Raw4Reassembly;
use super::Raw4Endpoint;
use crate::stack::NetStack;

pub(crate) struct Raw4Table {
    endpoints: Spinlock<BTreeMap<u8, Vec<Weak<Raw4Endpoint>>>, LockClass>,
    pub(crate) reassembly: Raw4Reassembly,
}

impl Raw4Table {
    /// Build an empty protocol table for one network namespace. # C: O(1)
    pub(crate) fn new() -> Self {
        Self {
            endpoints: Spinlock::new(BTreeMap::new()),
            reassembly: Raw4Reassembly::new(),
        }
    }

    /// Publish one endpoint exactly once in its protocol bucket. # C: O(N)
    pub(crate) fn register(&self, endpoint: &Arc<Raw4Endpoint>) {
        let mut all = self.endpoints.lock();
        let bucket = all.entry(endpoint.protocol()).or_default();
        bucket.retain(|weak| weak.upgrade().is_some());
        if bucket.iter().filter_map(Weak::upgrade).any(|live| Arc::ptr_eq(&live, endpoint)) {
            return;
        }
        bucket.push(Arc::downgrade(endpoint));
    }

    /// Remove one exact endpoint while preserving protocol peers. # C: O(N)
    pub(crate) fn unregister(&self, endpoint: &Arc<Raw4Endpoint>) {
        let mut all = self.endpoints.lock();
        let mut remove = false;
        if let Some(bucket) = all.get_mut(&endpoint.protocol()) {
            bucket.retain(|weak| weak.upgrade().is_some_and(|live| !Arc::ptr_eq(&live, endpoint)));
            remove = bucket.is_empty();
        }
        if remove { all.remove(&endpoint.protocol()); }
    }

    /// Snapshot live exact-protocol endpoints without holding registry locks. # C: O(N)
    pub(crate) fn endpoints(&self, protocol: u8) -> Vec<Arc<Raw4Endpoint>> {
        let mut all = self.endpoints.lock();
        let Some(bucket) = all.get_mut(&protocol) else { return Vec::new() };
        bucket.retain(|weak| weak.upgrade().is_some());
        bucket.iter().filter_map(Weak::upgrade).collect()
    }

    /// Snapshot every live endpoint without retaining the registry lock. # C: O(N)
    pub(crate) fn all_endpoints(&self) -> Vec<Arc<Raw4Endpoint>> {
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

impl NetStack {
    /// Publish a raw endpoint in its namespace-owned table. # C: O(N)
    pub fn register_raw4(&self, endpoint: &Arc<Raw4Endpoint>) {
        self.inet_tables(endpoint.net_ns()).raw4.register(endpoint);
    }

    /// Unpublish and deactivate one exact raw endpoint. # C: O(N)
    pub fn unregister_raw4(&self, endpoint: &Arc<Raw4Endpoint>) {
        endpoint.close();
        if let Some(tables) = self.try_inet_tables(endpoint.net_ns()) {
            tables.raw4.unregister(endpoint);
        }
    }
}
