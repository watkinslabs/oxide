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

pub(super) struct TxDispatch {
    queue: Spinlock<TxQueue, SocketLockClass>,
    hardware: Spinlock<(), SocketLockClass>,
}

struct TxQueue {
    draining: bool,
    head: usize,
    len: usize,
    jobs: [Option<TxJob>; TX_QUEUE_CAPACITY],
}

pub(crate) struct TxJob {
    lease: EgressLease,
    payload: TxPayload,
    done: Arc<TxCompletion>,
}

enum TxPayload {
    Packet { pkt: crate::Pkt, l2_dst: Option<crate::MacAddr> },
    Raw { frame: Vec<u8>, origin: Option<usize> },
}

struct TxCompletion {
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
        let done = job.done.clone();
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
                Err(crate::arp::ArpResolution::Deferred { probe, dropped }) => {
                    for dropped in dropped { dropped.complete(Err(NetError::Enobufs)); }
                    if let Some(probe) = probe { let _ = Self::emit_arp_probe(probe); }
                    continue;
                }
                Err(crate::arp::ArpResolution::Send { job, mac }) => job.with_l2(mac),
            };
            let done = job.done.clone();
            let result = {
                let _hardware = tx_lock!(self.hardware);
                job.transmit()
            };
            done.complete(result);
        }
    }

    #[cfg(test)]
    /// Pending queued jobs, excluding the job currently at hardware. # C: O(1)
    pub(super) fn queue_len(&self) -> usize { tx_lock!(self.queue).len }

    /// Resume one neighbour-resolved job under this generation's hardware serialiser. # C: O(packet)
    pub(crate) fn resume(&self, job: TxJob) {
        let done = job.done.clone();
        let result = {
            let _bh = exclude_local_softirq();
            let _hardware = tx_lock!(self.hardware);
            job.transmit()
        };
        done.complete(result);
    }

    fn emit_arp_probe(probe: crate::arp::ArpProbe) -> NetResult<()> {
        let body = crate::arp::build_request(probe.lease.device().mac(), probe.source_ip,
            probe.target_ip);
        let mut frame = alloc::vec![0u8; crate::ethernet::ETH_HDR_LEN + body.len()];
        crate::ethernet::EthHdr::write_to(probe.lease.device().broadcast(), probe.lease.device().mac(),
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
        Self { draining: false, head: 0, len: 0,
            jobs: [const { None }; TX_QUEUE_CAPACITY] }
    }

    fn full(&self) -> bool { self.len == TX_QUEUE_CAPACITY }

    fn push(&mut self, job: TxJob) {
        let tail = (self.head + self.len) % TX_QUEUE_CAPACITY;
        self.jobs[tail] = Some(job);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<TxJob> {
        if self.len == 0 { return None; }
        let job = self.jobs[self.head].take();
        self.head = (self.head + 1) % TX_QUEUE_CAPACITY;
        self.len -= 1;
        job
    }
}

impl TxJob {
    fn new(lease: EgressLease, payload: TxPayload) -> Self {
        Self { lease, payload, done: Arc::new(TxCompletion {
            result: Spinlock::new(None),
        }) }
    }

    /// Retained packet/frame byte count for neighbour queue accounting. # C: O(1)
    pub(crate) fn packet_len(&self) -> usize {
        match &self.payload {
            TxPayload::Packet { pkt, .. } => pkt.len(),
            TxPayload::Raw { frame, .. } => frame.len(),
        }
    }

    /// Exact interface generation retained by this deferred dispatch. # C: O(1)
    pub(crate) fn lease(&self) -> EgressLease { self.lease.clone() }

    /// Re-enter the exact dispatcher retained by this job's interface generation. # C: O(packet)
    pub(crate) fn resume(self) { self.lease.clone().resume_arp_job(self); }

    /// Complete the original synchronous transmit admission exactly once. # C: O(1)
    pub(crate) fn complete(self, result: NetResult<()>) { self.done.complete(result); }

    fn with_l2(mut self, dst: crate::MacAddr) -> Self {
        if let TxPayload::Packet { l2_dst, .. } = &mut self.payload { *l2_dst = Some(dst); }
        self
    }

    fn admit_arp(self) -> Result<Self, crate::arp::ArpResolution> {
        let (next_hop, source) = match &self.payload {
            TxPayload::Packet { pkt, .. } if self.lease.device().hardware_type() == crate::uapi::ARPHRD_ETHER
                && pkt.proto == crate::addr::eth_p::IPV4 => match pkt.next_hop {
                    Some(crate::pkt::TxNextHop::V4(next_hop)) => (next_hop, ipv4_source(pkt.data())),
                    _ => return Ok(self),
                },
            _ => return Ok(self),
        };
        if next_hop.is_broadcast() {
            let dst = self.lease.device().broadcast();
            return Ok(self.with_l2(dst));
        }
        if next_hop.is_multicast() { return Ok(self.with_l2(ipv4_multicast_mac(next_hop))); }
        let lease = self.lease.clone();
        match lease.arp_cache().resolve_or_queue(next_hop, source, self, crate::stack::net_now_ns()) {
            crate::arp::ArpResolution::Send { job, mac } => Ok(job.with_l2(mac)),
            deferred => Err(deferred),
        }
    }

    fn transmit(self) -> NetResult<()> {
        match self.payload {
            TxPayload::Packet { pkt, l2_dst } => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                {
                    let mut observe = |bytes: &[u8], protocol: u16, link_header_len: usize| {
                        crate::sock::deliver_packet_egress_in(&self.lease, bytes, protocol,
                            link_header_len, None);
                    };
                    match l2_dst { Some(dst) => self.lease.device().xmit_l2_observed(pkt, dst, &mut observe),
                        None => self.lease.device().xmit_observed(pkt, &mut observe) }
                }
                #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
                self.lease.device().xmit(pkt)
            }
            TxPayload::Raw { frame, origin: _origin } => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                {
                    crate::sock::deliver_packet_egress_in(&self.lease, &frame,
                        u16::from_be_bytes([frame[12], frame[13]]), crate::ethernet::ETH_HDR_LEN,
                        _origin);
                    if self.lease.device().hardware_type() == crate::uapi::ARPHRD_LOOPBACK {
                        crate::sock::deliver_packet_loopback_frame_in(&self.lease, &frame);
                    }
                }
                self.lease.device().xmit_raw(&frame)
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
            core::hint::spin_loop();
        }
    }
}
