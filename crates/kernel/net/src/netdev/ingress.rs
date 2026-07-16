use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub(crate) struct IngressGate {
    net_ns:     u64,
    pub(super) generation: u64,
    state:      AtomicUsize,
    ready:      AtomicBool,
    complete:   AtomicBool,
    effect_next: AtomicU64,
    effect_serving: AtomicU64,
    #[cfg(test)]
    unregister_waiters: AtomicUsize,
    #[cfg(test)]
    resume_waiters: AtomicUsize,
}

impl IngressGate {
    const LIVE: usize = 1usize << (usize::BITS - 1);
    const ACTIVE: usize = !Self::LIVE;

    pub(super) fn new(net_ns: u64, generation: u64) -> Self {
        Self { net_ns, generation, state: AtomicUsize::new(Self::LIVE),
            ready: AtomicBool::new(true), complete: AtomicBool::new(false),
            effect_next: AtomicU64::new(0), effect_serving: AtomicU64::new(0),
            #[cfg(test)] unregister_waiters: AtomicUsize::new(0),
            #[cfg(test)] resume_waiters: AtomicUsize::new(0) }
    }

    fn resume_pending(net_ns: u64, generation: u64) -> Self {
        Self { net_ns, generation, state: AtomicUsize::new(Self::LIVE),
            ready: AtomicBool::new(false), complete: AtomicBool::new(false),
            effect_next: AtomicU64::new(0), effect_serving: AtomicU64::new(0),
            #[cfg(test)] unregister_waiters: AtomicUsize::new(0),
            #[cfg(test)] resume_waiters: AtomicUsize::new(0) }
    }

    pub(super) fn registration_pending(net_ns: u64, generation: u64) -> Self {
        Self::resume_pending(net_ns, generation)
    }

    fn acquire(self: &Arc<Self>, iface: NetIfaceId, dev: Arc<dyn NetDev>,
               owner: network_namespace::NetworkNamespaceRef) -> Option<IngressLease> {
        if !self.ready() { return None; }
        if !self.try_enter() { return None; }
        Some(IngressLease { iface, dev, gate: self.clone(), _owner: owner })
    }

    fn try_enter(&self) -> bool {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & Self::LIVE == 0 || state & Self::ACTIVE == Self::ACTIVE { return false; }
            match self.state.compare_exchange_weak(state, state + 1,
                Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(next) => state = next,
            }
        }
    }

    pub(super) fn close(&self) -> bool {
        self.state.fetch_and(Self::ACTIVE, Ordering::AcqRel) & Self::LIVE != 0
    }

    pub(super) fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::LIVE != 0
    }

    pub(super) fn ready(&self) -> bool { self.ready.load(Ordering::Acquire) }

    pub(super) fn drained(&self) -> bool { self.state.load(Ordering::Acquire) == 0 }

    pub(super) fn wait(&self) {
        while !self.drained() { lifecycle_yield(); }
    }

    pub(super) fn finish(&self) { self.complete.store(true, Ordering::Release); }

    fn wait_complete(&self) {
        while !self.complete.load(Ordering::Acquire) { lifecycle_yield(); }
    }

    pub(super) fn finish_resume(&self) { self.ready.store(true, Ordering::Release); }

    fn wait_ready(&self) {
        while !self.ready.load(Ordering::Acquire) && !self.complete.load(Ordering::Acquire) {
            lifecycle_yield();
        }
    }
}

fn lifecycle_yield() {
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: lifecycle teardown runs only from schedulable process context.
    unsafe { sched::live::tick_yield(); }
    #[cfg(test)]
    std::thread::yield_now();
    #[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
    core::hint::spin_loop();
}

/// Active ingress ownership for one immutable interface namespace generation.
pub struct IngressLease {
    iface: NetIfaceId,
    dev:   Arc<dyn NetDev>,
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
    /// Exact device retained by this admitted interface generation. # C: O(1)
    pub fn device(&self) -> &dyn NetDev { self.dev.as_ref() }
    /// Retained concrete namespace owner for this generation. # C: O(1)
    pub fn namespace(&self) -> network_namespace::NetworkNamespaceRef {
        self._owner.clone()
    }
}

impl Drop for IngressLease {
    fn drop(&mut self) { self.gate.state.fetch_sub(1, Ordering::Release); }
}

struct EgressAdmission {
    gate:   Arc<IngressGate>,
    _owner: network_namespace::NetworkNamespaceRef,
}

impl Drop for EgressAdmission {
    fn drop(&mut self) { self.gate.state.fetch_sub(1, Ordering::Release); }
}

/// Live device handle admitted against one immutable interface generation.
#[derive(Clone)]
pub struct EgressLease {
    iface: NetIfaceId,
    dev:   Arc<dyn NetDev>,
    hold:  Arc<EgressAdmission>,
}

impl EgressLease {
    /// # C: O(1)
    pub fn iface(&self) -> NetIfaceId { self.iface }
    /// # C: O(1)
    pub fn net_ns(&self) -> u64 { self.hold.gate.net_ns }
    /// # C: O(1)
    pub fn generation(&self) -> u64 { self.hold.gate.generation }
    /// Exact device retained by this admitted interface generation. # C: O(1)
    pub fn device(&self) -> &dyn NetDev { self.dev.as_ref() }

    /// Transmit and publish one exact AF_PACKET outgoing observation. # C: O(packet + N sockets)
    pub fn xmit(&self, pkt: crate::Pkt) -> NetResult<()> {
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        {
            let mut observe = |bytes: &[u8], protocol: u16, link_header_len: usize| {
                crate::sock::deliver_packet_egress_in(self, bytes, protocol, link_header_len, None);
            };
            return self.dev.xmit_observed(pkt, &mut observe);
        }
        #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
        self.dev.xmit(pkt)
    }

    /// Transmit a caller-built link frame while suppressing its originating packet socket. # C: O(frame + N sockets)
    pub fn xmit_raw_from(&self, frame: &[u8], _origin: Option<usize>) -> NetResult<()> {
        if frame.len() < crate::ethernet::ETH_HDR_LEN { return Err(crate::NetError::Einval); }
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        crate::sock::deliver_packet_egress_in(self, frame,
            frame.get(12..14).map_or(0, |raw| u16::from_be_bytes([raw[0], raw[1]])),
            if frame.len() >= 14 { 14 } else { 0 }, _origin);
        self.dev.xmit_raw(frame)
    }

    /// Transmit a caller-built link frame with no packet-socket origin. # C: O(frame + N sockets)
    pub fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.xmit_raw_from(frame, None) }
}

impl core::ops::Deref for EgressLease {
    type Target = dyn NetDev;
    fn deref(&self) -> &Self::Target { self.dev.as_ref() }
}

/// Admitted device side effect for one immutable interface generation.
pub(crate) struct ControlEffectLease {
    pub(crate) dev: Arc<dyn NetDev>,
    gate: Arc<IngressGate>,
    ticket: u64,
    served: bool,
}

impl ControlEffectLease {
    pub(crate) fn apply_ipv4(mut self, addr: Option<crate::Ipv4Addr>) {
        self.wait_turn();
        self.dev.ipv4_addr_changed(addr);
        self.finish_turn();
    }

    fn wait_turn(&self) {
        while self.gate.effect_serving.load(Ordering::Acquire) != self.ticket {
            lifecycle_yield();
        }
    }

    fn finish_turn(&mut self) {
        self.gate.effect_serving.store(self.ticket.wrapping_add(1), Ordering::Release);
        self.served = true;
    }
}

impl Drop for ControlEffectLease {
    fn drop(&mut self) {
        if !self.served {
            self.wait_turn();
            self.finish_turn();
        }
        self.gate.state.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) struct IfaceTeardown {
    iface:       NetIfaceId,
    net_ns:      u64,
    generation:  u64,
    flags:       u32,
    gate:        Arc<IngressGate>,
    pub(crate) dev: Arc<dyn NetDev>,
    pub(crate) mcast_report: Arc<McastReportState>,
}

impl IfaceTeardown {
    pub(crate) fn wait(&self) { self.gate.wait(); }
    pub(crate) fn iface(&self) -> NetIfaceId { self.iface }
    pub(crate) fn net_ns(&self) -> u64 { self.net_ns }
    pub(crate) fn generation(&self) -> u64 { self.generation }
    pub(crate) fn flags(&self) -> u32 { self.flags }
}

pub(crate) enum IfaceUnregisterClaim {
    Teardown(IfaceTeardown),
    WaitComplete(Arc<IngressGate>),
    WaitResume(Arc<IngressGate>),
    Gone,
}

impl IfaceRegistry {
    /// Acquire a device handle whose generation cannot retire before drop. # C: O(N)
    pub fn acquire_egress_in_ns(&self, iface: NetIfaceId, net_ns: u64) -> Option<EgressLease> {
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)? };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface && entry.ns == net_ns
            && entry.ingress.live() && entry.ingress.ready())?;
        if !entry.ingress.try_enter() { return None; }
        Some(EgressLease { iface, dev: entry.dev.clone(),
            hold: Arc::new(EgressAdmission { gate: entry.ingress.clone(), _owner: owner }) })
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
            let entry = g.entries.iter().find(|entry| entry.dev.name() == name
                && entry.ns == net_ns && entry.ingress.live() && entry.ingress.ready())?;
            (entry.id, entry.ingress.clone())
        };
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)? };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.dev.name() == name && entry.ns == net_ns
            && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone(), owner)
    }

    /// Acquire live ingress ownership for the interface's current generation. # C: O(N)
    pub fn acquire_ingress(&self, iface: NetIfaceId) -> Option<IngressLease> {
        let (net_ns, gate) = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == iface
                && entry.ingress.live() && entry.ingress.ready())?;
            (entry.ns, entry.ingress.clone())
        };
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)? };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.ns == net_ns && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone(), owner)
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
        let owner = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns)? };
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == iface
            && entry.ns == net_ns && Arc::ptr_eq(&entry.dev, dev)
            && Arc::ptr_eq(&entry.ingress, &gate))?;
        entry.ingress.acquire(iface, entry.dev.clone(), owner)
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
            flags: entry.flags.load(Ordering::Acquire),
            gate: entry.ingress.clone(), dev: entry.dev.clone(),
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
        Some(dev)
    }

    pub(crate) fn complete_destroy(teardown: &IfaceTeardown) { teardown.gate.finish(); }

    pub(crate) fn notify_destroyed(dev: &Arc<dyn NetDev>) {
        let hook = *NETDEV_REMOVE_HOOK.lock();
        if let Some(f) = hook { f(dev.name()); }
    }

    pub(crate) fn begin_move_to_initial(&self, teardown: &IfaceTeardown)
        -> Option<Arc<IngressGate>>
    {
        let next_generation = teardown.generation.wrapping_add(1);
        let mut g = self.inner.lock();
        let entry = g.entries.iter_mut().find(|entry| entry.id == teardown.iface
            && entry.ns == teardown.net_ns
            && entry.ingress.generation == teardown.generation
            && Arc::ptr_eq(&entry.ingress, &teardown.gate)
            && teardown.gate.drained())?;
        let next = Arc::new(IngressGate::resume_pending(0, next_generation));
        entry.ns = 0;
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
