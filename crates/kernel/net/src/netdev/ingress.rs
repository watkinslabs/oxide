use super::*;
use super::tx_dispatch::TxDispatch;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[path = "ingress/registry.rs"]
mod registry;

pub(crate) struct IngressGate {
    net_ns:     u64,
    owner:      Option<Weak<network_namespace::NetworkNamespace>>,
    pub(super) generation: u64,
    state:      AtomicUsize,
    ready:      AtomicBool,
    complete:   AtomicBool,
    effect_next: AtomicU64,
    effect_serving: AtomicU64,
    tx:         TxDispatch,
    #[cfg(test)]
    unregister_waiters: AtomicUsize,
    #[cfg(test)]
    resume_waiters: AtomicUsize,
}

impl IngressGate {
    const LIVE: usize = 1usize << (usize::BITS - 1);
    const ACTIVE: usize = !Self::LIVE;

    /// Immediately-live gate. Only the hosted `register_in_ns` convenience
    /// builds one; the kernel registration path always starts from
    /// `registration_pending` and publishes via the arm/commit handshake.
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(super) fn new(net_ns: u64, generation: u64) -> Self {
        let owner = if net_ns == 0 { Some(network_namespace::initial()) }
            else { network_namespace::lookup_u64(net_ns) };
        let owner = owner.as_ref().map(Arc::downgrade);
        Self { net_ns, owner, generation, state: AtomicUsize::new(Self::LIVE),
            ready: AtomicBool::new(true), complete: AtomicBool::new(false),
            effect_next: AtomicU64::new(0), effect_serving: AtomicU64::new(0),
            tx: TxDispatch::new(),
            #[cfg(test)] unregister_waiters: AtomicUsize::new(0),
            #[cfg(test)] resume_waiters: AtomicUsize::new(0) }
    }

    fn resume_pending(owner: network_namespace::NetworkNamespaceRef, generation: u64) -> Self {
        Self { net_ns: owner.id().as_u64(), owner: Some(Arc::downgrade(&owner)), generation,
            state: AtomicUsize::new(Self::LIVE),
            ready: AtomicBool::new(false), complete: AtomicBool::new(false),
            effect_next: AtomicU64::new(0), effect_serving: AtomicU64::new(0),
            tx: TxDispatch::new(),
            #[cfg(test)] unregister_waiters: AtomicUsize::new(0),
            #[cfg(test)] resume_waiters: AtomicUsize::new(0) }
    }

    pub(super) fn registration_pending(
        owner: &network_namespace::NetworkNamespaceRef,
        generation: u64,
    ) -> Self {
        Self::resume_pending(owner.clone(), generation)
    }

    fn namespace_owner(&self) -> Option<network_namespace::NetworkNamespaceRef> {
        if let Some(owner) = self.owner.as_ref().and_then(Weak::upgrade) { return Some(owner); }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            if self.net_ns == 0 { Some(network_namespace::initial()) }
            else { network_namespace::lookup_u64(self.net_ns) }
        }
        #[cfg(target_os = "oxide-kernel")]
        { None }
    }

    fn acquire(self: &Arc<Self>, iface: NetIfaceId, dev: Arc<dyn NetDev>) -> Option<IngressLease> {
        if !self.ready() { return None; }
        if !self.try_enter() { return None; }
        let Some(owner) = self.namespace_owner() else {
            self.state.fetch_sub(1, Ordering::Release);
            return None;
        };
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

pub(super) fn lifecycle_yield() {
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
    flags:  u32,
}

impl Drop for EgressAdmission {
    fn drop(&mut self) { self.gate.state.fetch_sub(1, Ordering::Release); }
}

/// Live device handle admitted against one immutable interface generation.
#[derive(Clone)]
pub struct EgressLease {
    iface: NetIfaceId,
    dev:   Arc<dyn NetDev>,
    arp:   Arc<crate::arp::ArpCache>,
    ndp:   Arc<crate::neigh::NeighCache<crate::Ipv6Addr>>,
    hold:  Arc<EgressAdmission>,
}

impl EgressLease {
    /// # C: O(1)
    pub fn iface(&self) -> NetIfaceId { self.iface }
    /// # C: O(1)
    pub fn net_ns(&self) -> u64 { self.hold.gate.net_ns }
    /// # C: O(1)
    pub fn generation(&self) -> u64 { self.hold.gate.generation }
    /// Interface flags captured by this admitted generation. # C: O(1)
    pub fn flags(&self) -> u32 { self.hold.flags }
    /// Exact device retained by this admitted interface generation. # C: O(1)
    pub fn device(&self) -> &dyn NetDev { self.dev.as_ref() }
    /// Canonical IPv4 neighbour owner retained with this egress generation.
    /// # C: O(1)
    pub fn arp_cache(&self) -> &crate::arp::ArpCache { self.arp.as_ref() }

    /// The IPv6 half of the same neighbour table. # C: O(1)
    pub fn ndp_cache(&self) -> &crate::neigh::NeighCache<crate::Ipv6Addr> { self.ndp.as_ref() }

    /// Resume an ARP-resolved packet through this exact generation's dispatcher. # C: O(packet)
    pub(crate) fn resume_arp_job(&self, job: crate::netdev::tx_dispatch::TxJob) {
        self.hold.gate.tx.resume(job);
    }

    /// Transmit and publish one exact AF_PACKET outgoing observation. # C: O(packet + N sockets)
    pub fn xmit(&self, pkt: crate::Pkt) -> NetResult<()> {
        self.hold.gate.tx.enqueue_packet(self.clone(), pkt)
    }

    /// Transmit a caller-built link frame while suppressing its originating packet socket. # C: O(frame + N sockets)
    pub fn xmit_raw_from(&self, frame: &[u8], _origin: Option<usize>) -> NetResult<()> {
        self.xmit_raw_policy_from(frame, _origin, false)
    }

    /// Transmit one AF_PACKET frame through queued or direct device dispatch. # C: O(frame + N sockets)
    pub fn xmit_raw_policy_from(&self, frame: &[u8], _origin: Option<usize>, direct: bool)
        -> NetResult<()>
    {
        if frame.len() < crate::ethernet::ETH_HDR_LEN { return Err(crate::NetError::Einval); }
        if direct { self.hold.gate.tx.transmit_direct(self.dev.as_ref(), frame) }
        else { self.hold.gate.tx.enqueue_raw(self.clone(), frame, _origin) }
    }

    /// Transmit a caller-built link frame with no packet-socket origin. # C: O(frame + N sockets)
    pub fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.xmit_raw_from(frame, None) }

    #[cfg(test)]
    /// Pending transmit jobs retained by this generation. # C: O(1)
    pub(crate) fn queued_tx(&self) -> usize { self.hold.gate.tx.queue_len() }
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
    /// The namespace-scoped ifindex, snapshotted here for the same reason
    /// `flags` is: the deletion is announced after the entry has gone, so it
    /// cannot be looked up by then, and a notification that cannot name the
    /// interface it removed is one no client can act on.
    ifindex:     u32,
    flags:       u32,
    gate:        Arc<IngressGate>,
    pub(crate) dev: Arc<dyn NetDev>,
    pub(crate) arp: Arc<crate::arp::ArpCache>,
    pub(crate) ndp: Arc<crate::neigh::NeighCache<crate::Ipv6Addr>>,
    pub(crate) mcast_report: Arc<McastReportState>,
}

impl IfaceTeardown {
    pub(crate) fn wait(&self) { self.gate.wait(); }
    pub(crate) fn iface(&self) -> NetIfaceId { self.iface }
    pub(crate) fn net_ns(&self) -> u64 { self.net_ns }
    pub(crate) fn generation(&self) -> u64 { self.generation }
    pub(crate) fn flags(&self) -> u32 { self.flags }
    /// # C: O(1)
    pub(crate) fn ifindex(&self) -> u32 { self.ifindex }
}

pub(crate) enum IfaceUnregisterClaim {
    Teardown(IfaceTeardown),
    WaitComplete(Arc<IngressGate>),
    WaitResume(Arc<IngressGate>),
    Gone,
}
