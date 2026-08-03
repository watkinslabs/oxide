use alloc::{sync::Arc, vec::Vec};
use sync::{Spinlock, Socket as SocketLockClass};

use super::ingress::EgressLease;
use super::{NetDev, NetError, NetResult};

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock_irqsave::<hal_x86_64::X86IrqGate>() }; }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock_irqsave::<hal_aarch64::ArmIrqGate>() }; }
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! tx_lock { ($lock:expr) => { $lock.lock() }; }

#[cfg(target_os = "oxide-kernel")]
fn exclude_local_softirq() -> Option<sched::bh::BhGuard> {
    if sched::preempt::in_interrupt() { None } else { Some(sched::bh::BhGuard::new()) }
}
#[cfg(not(target_os = "oxide-kernel"))]
fn exclude_local_softirq() {}

pub(super) const TX_QUEUE_CAPACITY: usize = 64;

pub(crate) struct TxDispatch {
    queue: Spinlock<TxQueue, SocketLockClass>,
    hardware: Spinlock<(), SocketLockClass>,
}

struct TxQueue {
    draining: bool,
    head: usize,
    len: usize,
    /// Ring slots, HEAP-allocated rather than an inline
    /// `[Option<TxJob>; TX_QUEUE_CAPACITY]`.
    ///
    /// Inline, this array made `TxQueue` ~9.8 KiB, which propagated into
    /// `TxDispatch` and then `IngressGate` — and `Arc::new(IngressGate)`
    /// materialises its value on the STACK before moving it to the heap, so
    /// every gate construction reserved a ~9.9 KiB frame. That was the largest
    /// non-vendor frame in the kernel, on a 16 KiB stack (`skizm.md` Step 6a).
    ///
    /// A `Vec` keeps `TxQueue::new` `const` (`Vec::new` is const), so the
    /// static/const construction paths are unchanged; the slots are filled once
    /// on first use. Linux likewise heap-allocates its per-netdev TX rings
    /// rather than embedding them.
    jobs: Vec<Option<TxJob>>,
}

/// One admitted transmit, held BEHIND a box.
///
/// A job is moved by value at every step of the dispatch loop: into `enqueue`,
/// into the ring, back out of it, into neighbour admission and back out of it
/// inside an `ArpResolution`, through the L2 fill-in, and finally into
/// `transmit`. Each of those moves materialises another copy of the record in
/// the caller's frame, and the record is ~160 B — which is why `enqueue`, on
/// one of the deepest paths in the kernel, reserved most of a kilobyte. Boxed,
/// every one of those moves is a pointer. Linux hands an `sk_buff *` down the
/// same path for the same reason.
pub(crate) struct TxJob(alloc::boxed::Box<TxJobRecord>);

struct TxJobRecord {
    lease: EgressLease,
    payload: TxPayload,
    /// Absent once the neighbour queue owns this packet: Linux
    /// `neigh_resolve_output` reports success at queue time, so a later
    /// transmit or drop has no caller left to notify.
    done: Option<Arc<TxCompletion>>,
}

/// One sender's pending transmit admission, detachable from its job.
pub(crate) type TxAck = Arc<TxCompletion>;

enum TxPayload {
    Packet { pkt: crate::Pkt, l2_dst: Option<crate::MacAddr> },
    Raw { frame: Vec<u8>, origin: Option<usize> },
}

pub(crate) struct TxCompletion {
    result: Spinlock<Option<NetResult<()>>, SocketLockClass>,
}

impl TxDispatch {
    /// Create one empty dispatcher for an interface generation. # C: O(1)
    pub(super) const fn new() -> Self {
        Self { queue: Spinlock::new(TxQueue::new()),
            hardware: Spinlock::new(()) }
    }

    /// Enqueue one network-layer packet and wait for ordered completion. # C: O(queue + packet)
    pub(super) fn enqueue_packet(&self, lease: EgressLease, pkt: crate::Pkt) -> NetResult<()> {
        self.enqueue(TxJob::new(lease, TxPayload::Packet { pkt, l2_dst: None }))
    }

    /// Enqueue one caller-built frame and wait for ordered completion. # C: O(queue + frame)
    pub(super) fn enqueue_raw(&self, lease: EgressLease, frame: &[u8], origin: Option<usize>)
        -> NetResult<()>
    {
        let mut owned = Vec::new();
        owned.try_reserve_exact(frame.len()).map_err(|_| NetError::Enobufs)?;
        owned.extend_from_slice(frame);
        self.enqueue(TxJob::new(lease, TxPayload::Raw { frame: owned, origin }))
    }

    /// Enter hardware directly without queueing or outgoing observation. # C: O(frame)
    pub(super) fn transmit_direct(&self, dev: &dyn NetDev, frame: &[u8]) -> NetResult<()> {
        let _bh = exclude_local_softirq();
        let _hardware = tx_lock!(self.hardware);
        dev.xmit_raw_direct(frame)
    }

    fn enqueue(&self, job: TxJob) -> NetResult<()> {
        let _bh = exclude_local_softirq();
        let Some(done) = job.0.done.clone() else { return Ok(()); };
        let drain = {
            let mut queue = tx_lock!(self.queue);
            if queue.full() { return Err(NetError::Enobufs); }
            queue.push(job);
            if queue.draining { false } else { queue.draining = true; true }
        };
        if drain { self.drain(); }
        done.wait()
    }

    fn drain(&self) {
        loop {
            let job = {
                let mut queue = tx_lock!(self.queue);
                match queue.pop() {
                    Some(job) => job,
                    None => { queue.draining = false; return; }
                }
            };
            let job = match job.admit_arp() {
                Ok(job) => job,
                Err(crate::arp::ArpResolution::Deferred { probe, dropped, queued }) => {
                    Self::finish_deferred_neighbour(probe, dropped, queued);
                    continue;
                }
                Err(crate::arp::ArpResolution::Send { job, mac }) => job.with_l2(mac),
            };
            let done = job.0.done.clone();
            let result = {
                let _hardware = tx_lock!(self.hardware);
                job.transmit()
            };
            if let Some(done) = done { done.complete(result); }
        }
    }

    #[cfg(test)]
    /// Pending queued jobs, excluding the job currently at hardware. # C: O(1)
    pub(super) fn queue_len(&self) -> usize { tx_lock!(self.queue).len }

    /// Resume one neighbour-resolved job under this generation's hardware serialiser. # C: O(packet)
    pub(crate) fn resume(&self, job: TxJob) {
        let done = job.0.done.clone();
        let result = {
            let _bh = exclude_local_softirq();
            let _hardware = tx_lock!(self.hardware);
            job.transmit()
        };
        if let Some(done) = done { done.complete(result); }
    }

    /// Acknowledge one job the neighbour queue took ownership of, and probe for it.
    ///
    /// `#[inline(never)]`: Linux `neigh_resolve_output` hands the packet to the neighbour
    /// queue and reports success to the sender; the evicted oldest packets are
    /// acknowledged the same way. All of that is locals — a probe, a vector of evicted
    /// acknowledgements — that the ordinary resolved-neighbour path never touches, and
    /// that path is the one carrying a transmit chain.
    /// # C: O(evicted)
    #[inline(never)]
    fn finish_deferred_neighbour(probe: Option<crate::arp::ArpProbe>,
        dropped: alloc::vec::Vec<TxJob>, queued: Option<TxAck>)
    {
        for dropped in dropped { dropped.complete(Err(NetError::Enobufs)); }
        if let Some(queued) = queued { queued.complete(Ok(())); }
        if let Some(probe) = probe { let _ = Self::emit_arp_probe(probe); }
    }

    pub(crate) fn emit_arp_probe(probe: crate::arp::ArpProbe) -> NetResult<()> {
        #[cfg(feature = "debug-arp")]
        {
            klog::write_raw(b"[ARP-SOLICIT tgt=");
            for (i, b) in probe.target_ip.octets().iter().enumerate() {
                klog::write_dec_u64(*b as u64);
                if i < 3 { klog::write_raw(b"."); }
            }
            klog::write_raw(b" src=");
            for (i, b) in probe.source_ip.octets().iter().enumerate() {
                klog::write_dec_u64(*b as u64);
                if i < 3 { klog::write_raw(b"."); }
            }
            klog::write_raw(b"]\n");
        }
        let body = crate::arp::build_request(probe.lease.device().mac(), probe.source_ip,
            probe.target_ip);
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
        crate::ethernet::EthHdr::write_to(probe.destination, probe.lease.device().mac(),
            crate::addr::eth_p::ARP, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&body);
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        crate::sock::deliver_packet_egress_in(&probe.lease, &frame, crate::addr::eth_p::ARP,
            crate::ethernet::ETH_HDR_LEN, None);
        probe.lease.device().xmit_raw(&frame)
    }
}

impl TxQueue {
    const fn new() -> Self {
        Self { draining: false, head: 0, len: 0, jobs: Vec::new() }
    }

    fn full(&self) -> bool { self.len == TX_QUEUE_CAPACITY }

    /// Materialise the ring on first use. Kept out of `new` so that stays
    /// `const`; `full()` bounds `len` to `TX_QUEUE_CAPACITY`, so the ring is
    /// allocated exactly once and never grows after this.
    fn ensure_slots(&mut self) {
        if self.jobs.is_empty() {
            self.jobs.resize_with(TX_QUEUE_CAPACITY, || None);
        }
    }

    fn push(&mut self, job: TxJob) {
        self.ensure_slots();
        let tail = (self.head + self.len) % TX_QUEUE_CAPACITY;
        self.jobs[tail] = Some(job);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<TxJob> {
        if self.len == 0 { return None; }
        // `len > 0` implies `push` ran, so the ring is materialised.
        let job = self.jobs[self.head].take();
        self.head = (self.head + 1) % TX_QUEUE_CAPACITY;
        self.len -= 1;
        job
    }
}

impl TxJob {
    fn new(lease: EgressLease, payload: TxPayload) -> Self {
        Self(alloc::boxed::Box::new(TxJobRecord { lease, payload,
            done: Some(Arc::new(TxCompletion { result: Spinlock::new(None) })) }))
    }

    /// Retained packet/frame byte count for neighbour queue accounting. # C: O(1)
    pub(crate) fn packet_len(&self) -> usize {
        match &self.0.payload {
            TxPayload::Packet { pkt, .. } => pkt.len(),
            TxPayload::Raw { frame, .. } => frame.len(),
        }
    }

    /// Exact interface generation retained by this deferred dispatch. # C: O(1)
    pub(crate) fn lease(&self) -> EgressLease { self.0.lease.clone() }

    /// Re-enter the exact dispatcher with the link-layer address the neighbour
    /// resolved to.
    ///
    /// A job parked on an unresolved neighbour carries no link-layer
    /// destination — that is what it was waiting for. Re-entering the
    /// dispatcher without attaching the address that just arrived transmits it
    /// with none, so the very first packet to every new neighbour is lost
    /// while every later one succeeds: a ping reports one loss and a resolver
    /// pays a full timeout on its first query. The reference fills the header
    /// from the neighbour's `ha` before releasing the queue.
    /// # C: O(packet)
    pub(crate) fn resume(self, mac: crate::MacAddr) {
        let job = self.with_l2(mac);
        job.0.lease.clone().resume_arp_job(job);
    }

    /// Complete the original synchronous transmit admission exactly once.
    /// A job the neighbour queue already acknowledged has no sender left. # C: O(1)
    pub(crate) fn complete(self, result: NetResult<()>) {
        if let Some(done) = self.0.done { done.complete(result); }
    }

    /// Take this job's sender admission before the neighbour queue owns it. # C: O(1)
    pub(crate) fn detach_ack(&mut self) -> Option<TxAck> { self.0.done.take() }

    fn with_l2(mut self, dst: crate::MacAddr) -> Self {
        if let TxPayload::Packet { l2_dst, .. } = &mut self.0.payload { *l2_dst = Some(dst); }
        self
    }

    fn admit_arp(self) -> Result<Self, crate::arp::ArpResolution> {
        let (next_hop, source) = match &self.0.payload {
            TxPayload::Packet { pkt, .. } if self.0.lease.device().hardware_type() == crate::uapi::ARPHRD_ETHER
                && pkt.proto == crate::addr::eth_p::IPV4 => match pkt.next_hop {
                    Some(crate::pkt::TxNextHop::V4(next_hop)) => (next_hop, ipv4_source(pkt.data())),
                    _ => return Ok(self),
                },
            _ => return Ok(self),
        };
        #[cfg(feature = "debug-arp")]
        if next_hop.is_unspecified() {
            // A solicitation for the unspecified address can never be answered.
            // Name the datagram that asked for it: its IPv4 destination is the
            // value the route lookup should have turned into a next hop.
            let data = match &self.0.payload {
                TxPayload::Packet { pkt, .. } => pkt.data(),
                _ => &[],
            };
            klog::write_raw(b"[ARP-ZERO src=");
            for (i, b) in source.octets().iter().enumerate() {
                klog::write_dec_u64(*b as u64);
                if i < 3 { klog::write_raw(b"."); }
            }
            klog::write_raw(b" ipdst=");
            if data.len() >= 20 {
                for i in 16..20 {
                    klog::write_dec_u64(data[i] as u64);
                    if i < 19 { klog::write_raw(b"."); }
                }
                klog::write_raw(b" proto=");
                klog::write_dec_u64(data[9] as u64);
            }
            klog::write_raw(b"]\n");
            // The route table that produced the zero: one of these rows
            // matched, and its gateway is what became the next hop.
            for r in crate::sock::stack().routes.snapshot_records_in(0) {
                klog::write_raw(b"[ARP-ROUTE dst=");
                for (i, b) in r.route.dst.octets().iter().enumerate() {
                    klog::write_dec_u64(*b as u64);
                    if i < 3 { klog::write_raw(b"."); }
                }
                klog::write_raw(b"/");
                klog::write_dec_u64(r.route.prefix_len as u64);
                klog::write_raw(b" tbl=");
                klog::write_dec_u64(r.route.table as u64);
                klog::write_raw(b" kind=");
                klog::write_dec_u64(r.kind as u64);
                klog::write_raw(b" gw=");
                match r.route.gateway {
                    None => klog::write_raw(b"none"),
                    Some(g) => for (i, b) in g.octets().iter().enumerate() {
                        klog::write_dec_u64(*b as u64);
                        if i < 3 { klog::write_raw(b"."); }
                    },
                }
                klog::write_raw(b"]\n");
            }
        }
        if next_hop.is_broadcast() {
            let dst = self.0.lease.device().broadcast();
            return Ok(self.with_l2(dst));
        }
        if next_hop.is_multicast() { return Ok(self.with_l2(ipv4_multicast_mac(next_hop))); }
        let lease = self.0.lease.clone();
        match lease.arp_cache().resolve_or_queue(next_hop, source, self, crate::stack::net_now_ns()) {
            crate::arp::ArpResolution::Send { job, mac } => Ok(job.with_l2(mac)),
            deferred => Err(deferred),
        }
    }

    fn transmit(self) -> NetResult<()> {
        let TxJobRecord { lease, payload, .. } = *self.0;
        match payload {
            TxPayload::Packet { pkt, l2_dst } => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                {
                    let mut observe = |bytes: &[u8], protocol: u16, link_header_len: usize| {
                        crate::sock::deliver_packet_egress_in(&lease, bytes, protocol,
                            link_header_len, None);
                    };
                    match l2_dst { Some(dst) => lease.device().xmit_l2_observed(pkt, dst, &mut observe),
                        None => lease.device().xmit_observed(pkt, &mut observe) }
                }
                #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
                {
                    let _ = l2_dst;
                    lease.device().xmit(pkt)
                }
            }
            TxPayload::Raw { frame, origin: _origin } => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                {
                    crate::sock::deliver_packet_egress_in(&lease, &frame,
                        u16::from_be_bytes([frame[12], frame[13]]), crate::ethernet::ETH_HDR_LEN,
                        _origin);
                    if lease.device().hardware_type() == crate::uapi::ARPHRD_LOOPBACK {
                        crate::sock::deliver_packet_loopback_frame_in(&lease, &frame);
                    }
                }
                lease.device().xmit_raw(&frame)
            }
        }
    }
}

fn ipv4_source(packet: &[u8]) -> crate::Ipv4Addr {
    const IPV4_SOURCE_OFFSET: usize = 12;
    const IPV4_SOURCE_END: usize = IPV4_SOURCE_OFFSET + 4;
    let source = packet.get(IPV4_SOURCE_OFFSET..IPV4_SOURCE_END).unwrap_or(&[0; 4]);
    crate::Ipv4Addr::new(source[0], source[1], source[2], source[3])
}

fn ipv4_multicast_mac(ip: crate::Ipv4Addr) -> crate::MacAddr {
    const PREFIX: [u8; 3] = [0x01, 0x00, 0x5e];
    let octets = ip.octets();
    crate::MacAddr([PREFIX[0], PREFIX[1], PREFIX[2], octets[1] & 0x7f, octets[2], octets[3]])
}

impl TxCompletion {
    fn complete(&self, result: NetResult<()>) { *tx_lock!(self.result) = Some(result); }

    fn wait(&self) -> NetResult<()> {
        loop {
            if let Some(result) = *tx_lock!(self.result) { return result; }
            // `sync::relax`, not a bare `spin_loop`: it is the crate's single
            // relax step (services owed cross-CPU work on a kernel target, and
            // yields periodically in a hosted build, where 64 waiter threads
            // can otherwise starve the one drainer that completes them —
            // B1653's unbounded `net` test-binary spin).
            sync::relax();
        }
    }
}
