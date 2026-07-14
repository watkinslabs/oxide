use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct IngressGate {
    net_ns:     u64,
    pub(super) generation: u64,
    state:      AtomicUsize,
}

impl IngressGate {
    const LIVE: usize = 1usize << (usize::BITS - 1);
    const ACTIVE: usize = !Self::LIVE;

    pub(super) fn new(net_ns: u64, generation: u64) -> Self {
        Self { net_ns, generation, state: AtomicUsize::new(Self::LIVE) }
    }

    fn acquire(self: &Arc<Self>, iface: NetIfaceId,
               owner: network_namespace::NetworkNamespaceRef) -> Option<IngressLease> {
        let state = self.state.load(Ordering::Acquire);
        if state & Self::LIVE == 0 || state & Self::ACTIVE == Self::ACTIVE { return None; }
        self.state.fetch_add(1, Ordering::AcqRel);
        Some(IngressLease { iface, gate: self.clone(), _owner: owner })
    }

    pub(super) fn close(&self) -> bool {
        self.state.fetch_and(Self::ACTIVE, Ordering::AcqRel) & Self::LIVE != 0
    }

    pub(super) fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::LIVE != 0
    }

    pub(super) fn drained(&self) -> bool { self.state.load(Ordering::Acquire) == 0 }

    pub(super) fn wait(&self) {
        while !self.drained() { core::hint::spin_loop(); }
    }
}

/// Active ingress ownership for one immutable interface namespace generation.
pub struct IngressLease {
    iface: NetIfaceId,
    gate:  Arc<IngressGate>,
    _owner: network_namespace::NetworkNamespaceRef,
}

impl IngressLease {
    /// # C: O(1)
    pub fn iface(&self) -> NetIfaceId { self.iface }
    /// # C: O(1)
    pub fn net_ns(&self) -> u64 { self.gate.net_ns }
    /// # C: O(1)
    pub fn generation(&self) -> u64 { self.gate.generation }
}

impl Drop for IngressLease {
    fn drop(&mut self) { self.gate.state.fetch_sub(1, Ordering::Release); }
}

pub(crate) struct IfaceTeardown {
    iface:       NetIfaceId,
    net_ns:      u64,
    generation:  u64,
    gate:        Arc<IngressGate>,
    pub(crate) dev: Arc<dyn NetDev>,
    pub(crate) mcast_report: Arc<McastReportState>,
}

impl IfaceTeardown {
    pub(crate) fn wait(&self) { self.gate.wait(); }
}

impl IfaceRegistry {
    /// Acquire live ingress ownership for the interface's current generation. # C: O(N)
    pub fn acquire_ingress(&self, iface: NetIfaceId) -> Option<IngressLease> {
        let (net_ns, gate) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == iface
                && entry.ingress.live())?;
            (entry.ns, entry.ingress.clone())
        };
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)? };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.ns == net_ns && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, owner)
    }

    #[cfg(test)]
    pub(crate) fn acquire_ingress_generation(&self, iface: NetIfaceId, generation: u64)
        -> Option<IngressLease>
    {
        let lease = self.acquire_ingress(iface)?;
        if lease.generation() == generation { Some(lease) } else { None }
    }

    pub(crate) fn begin_teardown(&self, iface: NetIfaceId, net_ns: u64)
        -> Option<IfaceTeardown>
    {
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns)?;
        if !entry.ingress.close() { return None; }
        Some(IfaceTeardown { iface, net_ns, generation: entry.ingress.generation,
            gate: entry.ingress.clone(), dev: entry.dev.clone(),
            mcast_report: entry.mcast_report.clone() })
    }

    pub(crate) fn finish_destroy(&self, teardown: &IfaceTeardown)
        -> Option<Arc<dyn NetDev>>
    {
        let dev = {
            let mut g = self.inner.lock();
            let pos = g.entries.iter().position(|entry| entry.id == teardown.iface
                && entry.ns == teardown.net_ns
                && entry.ingress.generation == teardown.generation
                && Arc::ptr_eq(&entry.ingress, &teardown.gate)
                && teardown.gate.drained())?;
            g.entries.remove(pos).dev
        };
        let hook = *NETDEV_REMOVE_HOOK.lock();
        if let Some(f) = hook { f(dev.name()); }
        Some(dev)
    }

    pub(crate) fn finish_move_to_initial(&self, teardown: &IfaceTeardown) -> bool {
        let next_generation = teardown.generation.wrapping_add(1);
        let mut g = self.inner.lock();
        let Some(entry) = g.entries.iter_mut().find(|entry| entry.id == teardown.iface
            && entry.ns == teardown.net_ns
            && entry.ingress.generation == teardown.generation
            && Arc::ptr_eq(&entry.ingress, &teardown.gate)
            && teardown.gate.drained()) else { return false };
        entry.ns = 0;
        entry.mcast_report = Arc::new(McastReportState::new());
        entry.ingress = Arc::new(IngressGate::new(0, next_generation));
        true
    }
}
