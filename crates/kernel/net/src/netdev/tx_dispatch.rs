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

struct TxJob {
    lease: EgressLease,
    payload: TxPayload,
    done: Arc<TxCompletion>,
}

enum TxPayload {
    Packet(crate::Pkt),
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
        self.enqueue(TxJob::new(lease, TxPayload::Packet(pkt)))
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

    fn transmit(self) -> NetResult<()> {
        match self.payload {
            TxPayload::Packet(pkt) => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                {
                    let mut observe = |bytes: &[u8], protocol: u16, link_header_len: usize| {
                        crate::sock::deliver_packet_egress_in(&self.lease, bytes, protocol,
                            link_header_len, None);
                    };
                    self.lease.device().xmit_observed(pkt, &mut observe)
                }
                #[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
                self.lease.device().xmit(pkt)
            }
            TxPayload::Raw { frame, origin: _origin } => {
                #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
                crate::sock::deliver_packet_egress_in(&self.lease, &frame,
                    u16::from_be_bytes([frame[12], frame[13]]), crate::ethernet::ETH_HDR_LEN,
                    _origin);
                self.lease.device().xmit_raw(&frame)
            }
        }
    }
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
