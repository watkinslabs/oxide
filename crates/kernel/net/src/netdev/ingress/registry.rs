use super::*;

impl IfaceRegistry {
    /// Acquire a device handle whose generation cannot retire before drop. # C: O(N)
    pub fn acquire_egress_in_ns(&self, iface: NetIfaceId, net_ns: u64) -> Option<EgressLease> {
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns
            && entry.ingress.live() && entry.ingress.ready())?;
        if !entry.ingress.try_enter() { return None; }
        let Some(owner) = entry.ingress.namespace_owner() else {
            entry.ingress.state.fetch_sub(1, Ordering::Release);
            return None;
        };
        Some(EgressLease { iface, dev: entry.dev.clone(), arp: entry.arp.clone(), ndp: entry.ndp.clone(),
            hold: Arc::new(EgressAdmission {
                gate: entry.ingress.clone(), _owner: owner,
                flags: entry.flags.load(Ordering::Acquire),
            }) })
    }

    /// Admit a driver side effect against one control-ready generation. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub(crate) fn admit_control_effect_in_ns(&self, rtnl: &crate::RtnlGuard<'_>,
                                             iface: NetIfaceId, net_ns: u64)
        -> Option<ControlEffectLease>
    {
        if !self.guard_matches(rtnl) { return None; }
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns
            && entry.ingress.live() && entry.ingress.ready())?;
        if !entry.ingress.try_enter() { return None; }
        let ticket = entry.ingress.effect_next.fetch_add(1, Ordering::Relaxed);
        Some(ControlEffectLease {
            dev: entry.dev.clone(), gate: entry.ingress.clone(), ticket, served: false,
        })
    }

    /// Acquire live ingress ownership by namespace-qualified interface name. # C: O(N)
    pub fn acquire_ingress_name_in_ns(&self, name: &str, net_ns: u64) -> Option<IngressLease> {
        let (iface, gate) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.name == name
                && entry.ns == net_ns && entry.ingress.live() && entry.ingress.ready())?;
            (entry.id, entry.ingress.clone())
        };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.name == name && entry.ns == net_ns
            && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone())
    }

    /// Acquire live ingress ownership for the interface's current generation. # C: O(N)
    pub fn acquire_ingress(&self, iface: NetIfaceId) -> Option<IngressLease> {
        let (net_ns, gate) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == iface
                && entry.ingress.live() && entry.ingress.ready())?;
            (entry.ns, entry.ingress.clone())
        };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.ns == net_ns && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone())
    }

    /// Acquire ingress only when `dev` is the exact registered device owner. # C: O(N)
    pub fn acquire_ingress_for(&self, iface: NetIfaceId,
                               dev: &Arc<dyn NetDev>) -> Option<IngressLease> {
        let (net_ns, gate) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == iface
                && Arc::ptr_eq(&entry.dev, dev)
                && entry.ingress.live() && entry.ingress.ready())?;
            (entry.ns, entry.ingress.clone())
        };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.ns == net_ns && Arc::ptr_eq(&entry.dev, dev)
            && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone())
    }

    /// Acquire ingress only for the interface's exact current generation. # C: O(N)
    pub fn acquire_ingress_generation(&self, iface: NetIfaceId, generation: u64)
        -> Option<IngressLease>
    {
        let lease = self.acquire_ingress(iface)?;
        if lease.generation() == generation { Some(lease) } else { None }
    }

    pub(crate) fn claim_unregister(&self, iface: NetIfaceId) -> IfaceUnregisterClaim {
        self.claim_unregister_in(iface, None)
    }

    pub(crate) fn claim_unregister_in(&self, iface: NetIfaceId, net_ns: Option<u64>)
        -> IfaceUnregisterClaim
    {
        let g = self.inner.lock();
        let Some(entry) = g.entries.iter().find(|entry| entry.id == iface
            && net_ns.map(|ns| entry.ns == ns).unwrap_or(true)) else {
            return IfaceUnregisterClaim::Gone;
        };
        if !entry.ingress.ready() {
            #[cfg(test)]
            entry.ingress.resume_waiters.fetch_add(1, Ordering::AcqRel);
            return IfaceUnregisterClaim::WaitResume(entry.ingress.clone());
        }
        if !entry.ingress.close() {
            #[cfg(test)]
            entry.ingress.unregister_waiters.fetch_add(1, Ordering::AcqRel);
            return IfaceUnregisterClaim::WaitComplete(entry.ingress.clone());
        }
        IfaceUnregisterClaim::Teardown(IfaceTeardown {
            iface, net_ns: entry.ns, generation: entry.ingress.generation,
            ifindex: entry.ifindex,
            flags: entry.flags.load(Ordering::Acquire),
            gate: entry.ingress.clone(), dev: entry.dev.clone(), arp: entry.arp.clone(), ndp: entry.ndp.clone(),
            mcast_report: entry.mcast_report.clone(),
        })
    }

    pub(crate) fn wait_unregister(claim: &Arc<IngressGate>) { claim.wait_complete(); }

    pub(crate) fn wait_resume(claim: &Arc<IngressGate>) { claim.wait_ready(); }

    #[cfg(test)]
    pub(crate) fn unregister_waiters(&self, iface: NetIfaceId, generation: u64) -> usize {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == iface
            && entry.ingress.generation == generation)
            .map(|entry| entry.ingress.unregister_waiters.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn resume_waiters(&self, iface: NetIfaceId) -> usize {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == iface)
            .map(|entry| entry.ingress.resume_waiters.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub(crate) fn finish_destroy(&self, teardown: &IfaceTeardown)
        -> Option<(Arc<dyn NetDev>, Option<Arc<drv::Device>>)>
    {
        let (dev, rxq) = {
            let mut g = self.inner.lock();
            let pos = g.entries.iter().position(|entry| entry.id == teardown.iface
                && entry.ns == teardown.net_ns
                && entry.ingress.generation == teardown.generation
                && Arc::ptr_eq(&entry.ingress, &teardown.gate)
                && teardown.gate.drained())?;
            let entry = g.entries.remove(pos);
            ((entry.dev, entry.parent), entry.rx_queues)
        };
        // Off the registry lock, per `IfaceRegistry::unregister`.
        super::rx_queue::uninstall_all(&rxq);
        Some(dev)
    }

    pub(crate) fn complete_destroy(teardown: &IfaceTeardown) { teardown.gate.finish(); }

    pub(crate) fn notify_destroyed(dev: &Arc<dyn NetDev>, parent: Option<&Arc<drv::Device>>) {
        super::notify_changed(dev.name(), parent);
    }

    pub(crate) fn begin_move_to_initial(&self, teardown: &IfaceTeardown)
        -> Option<Arc<IngressGate>>
    {
        let next_generation = teardown.generation.wrapping_add(1);
        let initial_owner = network_namespace::initial();
        let mut g = self.inner.lock();
        let entry = g.entries.iter_mut().find(|entry| entry.id == teardown.iface
            && entry.ns == teardown.net_ns
            && entry.ingress.generation == teardown.generation
            && Arc::ptr_eq(&entry.ingress, &teardown.gate)
            && teardown.gate.drained())?;
        let next = Arc::new(IngressGate::resume_pending(initial_owner, next_generation));
        entry.ns = 0;
        entry.arp = Arc::new(crate::arp::ArpCache::new());
        entry.ndp = Arc::new(crate::neigh::NeighCache::new());
        entry.mcast_report = Arc::new(McastReportState::new());
        entry.ingress = next.clone();
        Some(next)
    }

    pub(crate) fn finish_move_to_initial(&self, teardown: &IfaceTeardown,
                                         next: &Arc<IngressGate>) -> bool {
        let g = self.inner.lock();
        let Some(entry) = g.entries.iter().find(|entry| entry.id == teardown.iface
            && entry.ns == 0 && Arc::ptr_eq(&entry.ingress, next)) else { return false };
        entry.ingress.finish_resume();
        true
    }

    pub(crate) fn complete_move(teardown: &IfaceTeardown) { teardown.gate.finish(); }
}

