// The neighbour state machine, shared by every address family.
//
// The reference has ONE neighbour subsystem: `neigh_table` holds the states,
// the bounded solicitation policy and the unresolved queue, and each family
// (`arp_tbl`, `nd_tbl`) supplies only its own wire format and solicitation.
// A second, simpler table for IPv6 is what left it with no NUD states, no
// retransmit policy and no pending queue at all: a miss dropped the packet
// outright, so the first packet to every new IPv6 neighbour was lost.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use sync::{Spinlock, Socket as NeighLockClass};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::addr::MacAddr;

#[path = "neigh/timer.rs"]
mod timer;

/// A protocol address a neighbour table can be keyed by. The state machine
/// needs only ordering, copying and an unspecified test; the wire format and
/// the solicitation belong to the family.
pub trait NeighAddr: Copy + Ord + core::fmt::Debug {
    /// The all-zeroes address, standing for "no source chosen yet". # C: O(1)
    fn unspecified() -> Self;
}

impl NeighAddr for crate::addr::Ipv4Addr {
    /// # C: O(1)
    fn unspecified() -> Self { crate::addr::Ipv4Addr::ANY }
}

impl NeighAddr for crate::addr::Ipv6Addr {
    /// # C: O(1)
    fn unspecified() -> Self { crate::addr::Ipv6Addr([0u8; 16]) }
}

/// Linux neighbour reachability state shared by every address family.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NudState { Incomplete, Reachable, Stale, Delay, Probe, Permanent, Failed }

impl NudState {
    /// Whether a packet may use the retained link-layer address. # C: O(1)
    pub const fn usable(self) -> bool {
        matches!(self, Self::Reachable | Self::Stale | Self::Delay | Self::Probe | Self::Permanent)
    }
}

/// Per-iface neighbour cache. F177: each entry carries the
/// monotonic-ns insert timestamp; `lookup` treats entries older
/// than `ARP_STALE_NS` as absent (forces a fresh ARP request).
/// Linux defaults: stale=60s reachable, gc_stale_time=60s; we use
/// a single 60s ceiling for v1 simplicity.
pub struct NeighEntry<A: NeighAddr> {
    pub mac: Option<MacAddr>,
    pub inserted_ns: u64,
    pub state: NudState,
    pub(crate) pending: VecDeque<crate::netdev::tx_dispatch::TxJob>,
    pending_bytes: usize,
    source_ip: A,
    probes: u8,
    probe_deadline_ns: u64,
    probe_lease: Option<crate::EgressLease>,
}

pub struct NeighCache<A: NeighAddr> {
    pub(crate) inner: Spinlock<BTreeMap<A, NeighEntry<A>>, NeighLockClass>,
    closed: AtomicBool,
}

/// F177: 60 seconds in monotonic ns. Matches Linux's default
/// `gc_stale_time` for the IPv4 neighbor table.
pub const ARP_STALE_NS: u64 = 60_000_000_000;
/// Linux `net.ipv4.neigh.default.base_reachable_time_ms` default. # C: O(1)
pub const ARP_BASE_REACHABLE_NS: u64 = 30_000_000_000;
/// Linux `net.ipv4.neigh.default.unres_qlen_bytes` default (`SK_WMEM_MAX`).
pub const ARP_UNRESOLVED_QUEUE_BYTES: usize = 212_992;
/// Linux `net.ipv4.neigh.default.retrans_time_ms` default. # C: O(1)
pub const ARP_RETRANS_TIME_NS: u64 = 1_000_000_000;
/// Linux `net.ipv4.neigh.default.mcast_solicit` default. # C: O(1)
pub const ARP_MCAST_SOLICIT: u8 = 3;
/// Linux `net.ipv4.neigh.default.ucast_solicit` default. # C: O(1)
pub const ARP_UCAST_SOLICIT: u8 = 3;
/// Linux `net.ipv4.neigh.default.delay_first_probe_time` default. # C: O(1)
pub const ARP_DELAY_FIRST_PROBE_NS: u64 = 5_000_000_000;

fn expired<A: NeighAddr>(entry: &NeighEntry<A>, now_ns: u64) -> bool {
    entry.state != NudState::Permanent && now_ns != 0 && entry.inserted_ns != 0
        && now_ns.saturating_sub(entry.inserted_ns) > ARP_STALE_NS
}

/// Result of one IPv4 neighbour admission, after the cache lock is released.
pub(crate) enum NeighResolution<A: NeighAddr> {
    Send { job: crate::netdev::tx_dispatch::TxJob, mac: MacAddr },
    /// The neighbour queue owns the packet. `queued` is the sender's pending
    /// admission, which Linux `neigh_resolve_output` completes at queue time.
    Deferred {
        probe: Option<NeighProbe<A>>,
        dropped: Vec<crate::netdev::tx_dispatch::TxJob>,
        queued: Option<crate::netdev::tx_dispatch::TxAck>,
    },
}

/// ARP request detached from the cache lock for normal transmit dispatch.
pub(crate) struct NeighProbe<A: NeighAddr> {
    pub(crate) lease: crate::EgressLease,
    pub(crate) source_ip: A,
    pub(crate) target_ip: A,
    pub(crate) destination: MacAddr,
}

/// Neighbour actions detached from the cache lock for dispatch/completion.
pub(crate) struct NeighTick<A: NeighAddr> {
    pub(crate) probes: Vec<NeighProbe<A>>,
    pub(crate) failed: Vec<crate::netdev::tx_dispatch::TxJob>,
}

impl<A: NeighAddr> NeighCache<A> {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()), closed: AtomicBool::new(false) }
    }

    /// Insert/refresh an entry with the caller-supplied monotonic
    /// timestamp. Callers in process / driver context read the
    /// clock once and pass it in so test code can pin time.
    /// # C: O(log N)
    pub fn insert_at(&self, ip: A, mac: MacAddr, now_ns: u64) {
        let _ = self.learn_at(ip, mac, NudState::Reachable, now_ns);
    }

    /// Learn one neighbour with the NUD state justified by its ARP evidence.
    /// # C: O(log N)
    pub(crate) fn learn_at(&self, ip: A, mac: MacAddr, state: NudState, now_ns: u64)
        -> Vec<crate::netdev::tx_dispatch::TxJob>
    {
        if self.closed.load(Ordering::Acquire) { return Vec::new(); }
        let mut entries = self.inner.lock();
        let entry = entries.entry(ip).or_insert_with(|| NeighEntry {
            mac: None, inserted_ns: now_ns, state: NudState::Incomplete,
            pending: VecDeque::new(), pending_bytes: 0, source_ip: A::unspecified(),
            probes: 0, probe_deadline_ns: 0, probe_lease: None,
        });
        entry.mac = Some(mac);
        entry.inserted_ns = now_ns;
        entry.state = state;
        entry.probes = 0;
        entry.probe_deadline_ns = 0;
        entry.probe_lease = None;
        entry.pending_bytes = 0;
        entry.pending.drain(..).collect()
    }

    /// Learn one neighbour using the current monotonic timestamp. # C: O(log N)
    pub fn learn(&self, ip: A, mac: MacAddr, state: NudState) {
        let _ = self.learn_at(ip, mac, state, now_ns_safe());
    }

    /// Timestamp-less insert. On kernel builds reads monotonic_ns
    /// itself; on hosted-test builds stamps 0 (entry never stales).
    /// Production driver callers don't need to thread a clock.
    /// # C: O(log N)
    pub fn insert(&self, ip: A, mac: MacAddr) {
        self.insert_at(ip, mac, now_ns_safe())
    }

    /// Remove all neighbor state when the owning interface leaves a namespace. # C: O(N)
    pub(crate) fn clear(&self) -> Vec<crate::netdev::tx_dispatch::TxJob> {
        self.closed.store(true, Ordering::Release);
        let mut entries = self.inner.lock();
        let mut pending = Vec::new();
        for (_, mut entry) in core::mem::take(&mut *entries) {
            pending.extend(entry.pending.drain(..));
        }
        pending
    }

    /// Lookup with stale check: drops + returns None when the
    /// entry is older than `ARP_STALE_NS`. `now_ns == 0` disables
    /// the stale check (hosted tests, pre-clock callers).
    /// # C: O(log N)
    pub fn lookup_at(&self, ip: A, now_ns: u64) -> Option<MacAddr> {
        if self.closed.load(Ordering::Acquire) { return None; }
        let mut g = self.inner.lock();
        let mac = match g.get(&ip) {
            Some(e) => {
                if expired(e, now_ns) {
                    None
                } else if e.state.usable() {
                    e.mac
                } else {
                    None
                }
            }
            None => None,
        };
        if mac.is_none() { g.remove(&ip); }
        mac
    }

    /// Lookup; reads monotonic_ns itself on kernel builds so the
    /// stale check fires. Hosted tests get the never-stale path.
    /// # C: O(log N)
    pub fn lookup(&self, ip: A) -> Option<MacAddr> {
        self.lookup_at(ip, now_ns_safe())
    }

    /// Every resolved binding in this table. # C: O(N)
    pub fn snapshot_bindings(&self) -> Vec<(A, MacAddr)> {
        self.inner.lock().iter().filter_map(|(ip, e)| e.mac.map(|mac| (*ip, mac))).collect()
    }

    /// Snapshot one neighbour's link address and NUD state without consuming it.
    /// # C: O(log N)
    pub fn neighbour(&self, ip: A) -> Option<(MacAddr, NudState)> {
        if self.closed.load(Ordering::Acquire) { return None; }
        self.inner.lock().get(&ip).and_then(|entry| entry.mac.map(|mac| (mac, entry.state)))
    }

    /// Snapshot one neighbour's state, including an intentionally unspecified link address. # C: O(log N)
    pub(crate) fn neighbour_state(&self, ip: A) -> Option<(Option<MacAddr>, NudState)> {
        if self.closed.load(Ordering::Acquire) { return None; }
        self.inner.lock().get(&ip).map(|entry| (entry.mac, entry.state))
    }

    /// Remove one neighbour entry and all state owned beneath it. # C: O(log N)
    pub fn remove(&self, ip: A) -> Option<NeighEntry<A>> {
        self.inner.lock().remove(&ip)
    }

    /// Remove one neighbour and detach its queued packets for the control
    /// plane (RTM_DELNEIGH). `None` mirrors Linux ENOENT. # C: O(log N)
    pub(crate) fn admin_remove(&self, ip: A)
        -> Option<Vec<crate::netdev::tx_dispatch::TxJob>>
    {
        self.inner.lock().remove(&ip).map(|mut entry| entry.pending.drain(..).collect())
    }

    /// Apply an administrator-provided neighbour update and detach queued work. # C: O(log N)
    pub(crate) fn admin_set(&self, ip: A, mac: Option<MacAddr>, permanent: bool,
                            now_ns: u64) -> Vec<crate::netdev::tx_dispatch::TxJob>
    {
        if self.closed.load(Ordering::Acquire) { return Vec::new(); }
        let mut entries = self.inner.lock();
        let entry = entries.entry(ip).or_insert_with(|| NeighEntry {
            mac: None, inserted_ns: now_ns, state: NudState::Incomplete,
            pending: VecDeque::new(), pending_bytes: 0, source_ip: A::unspecified(),
            probes: 0, probe_deadline_ns: 0, probe_lease: None,
        });
        entry.mac = mac;
        entry.inserted_ns = now_ns;
        entry.state = if permanent { NudState::Permanent } else { NudState::Stale };
        entry.probes = 0;
        entry.probe_deadline_ns = 0;
        entry.probe_lease = None;
        if mac.is_some() {
            entry.pending_bytes = 0;
            return entry.pending.drain(..).collect();
        }
        Vec::new()
    }

    /// # C: O(N)
    pub fn snapshot(&self) -> alloc::vec::Vec<(A, MacAddr)> {
        if self.closed.load(Ordering::Acquire) { return alloc::vec::Vec::new(); }
        self.inner.lock().iter().filter_map(|(k, v)| v.mac.map(|mac| (*k, mac))).collect()
    }

    /// Snapshot each neighbour's L3 address, optional link address, and NUD
    /// state for a control-plane reader (RTM_GETNEIGH). # C: O(N)
    pub fn snapshot_states(&self) -> alloc::vec::Vec<(A, Option<MacAddr>, NudState)> {
        if self.closed.load(Ordering::Acquire) { return alloc::vec::Vec::new(); }
        self.inner.lock().iter().map(|(k, v)| (*k, v.mac, v.state)).collect()
    }

    /// F177: garbage-collect any entries older than `ARP_STALE_NS`.
    /// Intended caller is the rx kthread's periodic tick (~100ms);
    /// `now_ns == 0` is a no-op (pre-clock).
    /// # C: O(N)
    pub fn gc(&self, now_ns: u64) {
        if self.closed.load(Ordering::Acquire) { return; }
        if now_ns == 0 { return; }
        self.inner.lock().retain(|_, e| {
            !expired(e, now_ns)
        });
    }

    /// Resolve one IPv4 next-hop or retain its exact dispatch in the pending FIFO. # C: O(log N)
    pub(crate) fn resolve_or_queue(&self, next_hop: A, source_ip: A,
        job: crate::netdev::tx_dispatch::TxJob, now_ns: u64) -> NeighResolution<A>
    {
        if self.closed.load(Ordering::Acquire) {
            return NeighResolution::Deferred { probe: None, dropped: alloc::vec![job], queued: None };
        }
        let bytes = job.packet_len();
        let lease = job.lease();
        let mut entries = self.inner.lock();
        if self.closed.load(Ordering::Acquire) {
            drop(entries);
            return NeighResolution::Deferred { probe: None, dropped: alloc::vec![job], queued: None };
        }
        let entry = entries.entry(next_hop).or_insert_with(|| NeighEntry {
            mac: None, inserted_ns: now_ns, state: NudState::Incomplete,
            pending: VecDeque::new(), pending_bytes: 0, source_ip,
            probes: 0, probe_deadline_ns: 0, probe_lease: None,
        });
        if expired(entry, now_ns) {
            entry.mac = None;
            entry.state = NudState::Incomplete;
            entry.probes = 0;
            entry.probe_deadline_ns = 0;
            entry.probe_lease = None;
        }
        if entry.state == NudState::Failed {
            entry.state = NudState::Incomplete;
            entry.probes = 0;
            entry.probe_deadline_ns = 0;
            entry.probe_lease = None;
        }
        if entry.state.usable() {
            if let Some(mac) = entry.mac {
                if entry.state == NudState::Stale {
                    entry.state = NudState::Delay;
                    entry.probes = 0;
                    entry.source_ip = source_ip;
                    entry.probe_deadline_ns = now_ns.saturating_add(ARP_DELAY_FIRST_PROBE_NS);
                    entry.probe_lease = Some(lease.clone());
                }
                return NeighResolution::Send { job, mac };
            }
        }
        let mut dropped = Vec::new();
        // Linux `__neigh_event_send` evicts the oldest queued packets until the
        // new one fits, then always queues it; the sender is never failed.
        while entry.pending_bytes.saturating_add(bytes) > ARP_UNRESOLVED_QUEUE_BYTES {
            let Some(oldest) = entry.pending.pop_front() else { break };
            entry.pending_bytes = entry.pending_bytes.saturating_sub(oldest.packet_len());
            dropped.push(oldest);
        }
        let mut job = job;
        let queued = job.detach_ack();
        entry.pending_bytes = entry.pending_bytes.saturating_add(bytes);
        entry.pending.push_back(job);
        if entry.probes != 0 { return NeighResolution::Deferred { probe: None, dropped, queued }; }
        entry.probes = 1;
        entry.source_ip = source_ip;
        entry.probe_deadline_ns = now_ns.saturating_add(ARP_RETRANS_TIME_NS);
        entry.probe_lease = Some(lease.clone());
        NeighResolution::Deferred {
            probe: Some(NeighProbe { lease, source_ip, target_ip: next_hop,
                destination: MacAddr::BROADCAST }),
            dropped, queued,
        }
    }
}

impl<A: NeighAddr> Default for NeighCache<A> { fn default() -> Self { Self::new() } }

/// F177: monotonic-ns reader visible to NeighCache without forcing
/// every caller to thread a clock. Kernel-target hooks the HAL
/// timer; hosted tests get 0 (entries never stale).
/// # C: O(1)
fn now_ns_safe() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

