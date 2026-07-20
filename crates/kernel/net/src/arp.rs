// ARP — RFC 826 Address Resolution Protocol for IPv4 over
// Ethernet. 28-byte payload sitting under an Ethernet header
// (ETH_P_ARP=0x0806). Two opcodes that matter: REQUEST (1) and
// REPLY (2). The neighbor cache lives next to the registry —
// `ArpCache` keeps a small `BTreeMap<Ipv4Addr, MacAddr>`.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};

use sync::{Spinlock, Socket as ArpLockClass};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::addr::{Ipv4Addr, MacAddr};

pub const ARP_HW_ETHER: u16 = 1;
pub const ARP_PROTO_IPV4: u16 = crate::addr::eth_p::IPV4;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY:   u16 = 2;
pub const ARP_HARDWARE_ADDRESS_BYTES: u8 = 6;
pub const ARP_PROTOCOL_ADDRESS_BYTES: u8 = 4;
pub const ARP_LEN: usize = 28;

/// Linux neighbour reachability state used by the IPv4 ARP owner.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NudState { Incomplete, Reachable, Stale, Delay, Probe, Failed }

impl NudState {
    /// Whether an IPv4 packet may use the retained link-layer address. # C: O(1)
    pub const fn usable(self) -> bool {
        matches!(self, Self::Reachable | Self::Stale | Self::Delay | Self::Probe)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArpError { Short, BadHwType, BadProto, BadAddressLength, BadOp }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ArpPkt {
    pub opcode:   u16,
    pub sender_mac: MacAddr,
    pub sender_ip:  Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip:  Ipv4Addr,
}

impl ArpPkt {
    /// # C: O(N)
    pub fn parse(buf: &[u8]) -> Result<Self, ArpError> {
        if buf.len() < ARP_LEN { return Err(ArpError::Short); }
        let hw    = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen = buf[4];
        let plen = buf[5];
        let op    = u16::from_be_bytes([buf[6], buf[7]]);
        if hw != ARP_HW_ETHER { return Err(ArpError::BadHwType); }
        if proto != ARP_PROTO_IPV4 { return Err(ArpError::BadProto); }
        if hlen != ARP_HARDWARE_ADDRESS_BYTES || plen != ARP_PROTOCOL_ADDRESS_BYTES {
            return Err(ArpError::BadAddressLength);
        }
        if op != ARP_OP_REQUEST && op != ARP_OP_REPLY { return Err(ArpError::BadOp); }
        let mut sm = [0u8; 6]; sm.copy_from_slice(&buf[ 8..14]);
        let si = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let mut tm = [0u8; 6]; tm.copy_from_slice(&buf[18..24]);
        let ti = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        Ok(Self {
            opcode: op,
            sender_mac: MacAddr(sm), sender_ip: Ipv4Addr::from_u32(si),
            target_mac: MacAddr(tm), target_ip: Ipv4Addr::from_u32(ti),
        })
    }

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&ARP_HW_ETHER.to_be_bytes());
        buf[2..4].copy_from_slice(&ARP_PROTO_IPV4.to_be_bytes());
        buf[4] = ARP_HARDWARE_ADDRESS_BYTES;
        buf[5] = ARP_PROTOCOL_ADDRESS_BYTES;
        buf[6..8].copy_from_slice(&self.opcode.to_be_bytes());
        buf[ 8..14].copy_from_slice(&self.sender_mac.0);
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        buf[18..24].copy_from_slice(&self.target_mac.0);
        buf[24..28].copy_from_slice(&self.target_ip.octets());
    }
}

/// Build a REQUEST asking who has `target_ip`. Caller wraps in
/// an Ethernet frame with dst=BROADCAST + ETH_P_ARP.
/// # C: O(1)
pub fn build_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr)
    -> alloc::vec::Vec<u8>
{
    let mut buf = alloc::vec![0u8; ARP_LEN];
    let p = ArpPkt {
        opcode: ARP_OP_REQUEST,
        sender_mac, sender_ip,
        target_mac: MacAddr::ZERO,
        target_ip,
    };
    p.write_to(&mut buf);
    buf
}

/// Build a REPLY for a received REQUEST.
/// # C: O(1)
pub fn build_reply(req: &ArpPkt, our_mac: MacAddr) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; ARP_LEN];
    let p = ArpPkt {
        opcode: ARP_OP_REPLY,
        sender_mac: our_mac, sender_ip: req.target_ip,
        target_mac: req.sender_mac, target_ip: req.sender_ip,
    };
    p.write_to(&mut buf);
    buf
}

/// Per-iface ARP neighbor cache. F177: each entry carries the
/// monotonic-ns insert timestamp; `lookup` treats entries older
/// than `ARP_STALE_NS` as absent (forces a fresh ARP request).
/// Linux defaults: stale=60s reachable, gc_stale_time=60s; we use
/// a single 60s ceiling for v1 simplicity.
pub struct ArpEntry {
    pub mac: Option<MacAddr>,
    pub inserted_ns: u64,
    pub state: NudState,
    pending: VecDeque<crate::netdev::tx_dispatch::TxJob>,
    pending_bytes: usize,
    source_ip: Ipv4Addr,
    probes: u8,
    probe_deadline_ns: u64,
}

pub struct ArpCache {
    pub(crate) inner: Spinlock<BTreeMap<Ipv4Addr, ArpEntry>, ArpLockClass>,
    closed: AtomicBool,
}

/// F177: 60 seconds in monotonic ns. Matches Linux's default
/// `gc_stale_time` for the IPv4 neighbor table.
pub const ARP_STALE_NS: u64 = 60_000_000_000;
/// Linux `net.ipv4.neigh.default.unres_qlen_bytes` default (`SK_WMEM_MAX`).
pub const ARP_UNRESOLVED_QUEUE_BYTES: usize = 212_992;

/// Result of one IPv4 neighbour admission, after the cache lock is released.
pub(crate) enum ArpResolution {
    Send { job: crate::netdev::tx_dispatch::TxJob, mac: MacAddr },
    Deferred { probe: Option<ArpProbe>, dropped: Vec<crate::netdev::tx_dispatch::TxJob> },
}

/// ARP request detached from the cache lock for normal transmit dispatch.
pub(crate) struct ArpProbe {
    pub(crate) lease: crate::EgressLease,
    pub(crate) source_ip: Ipv4Addr,
    pub(crate) target_ip: Ipv4Addr,
}

impl ArpCache {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()), closed: AtomicBool::new(false) }
    }

    /// Insert/refresh an entry with the caller-supplied monotonic
    /// timestamp. Callers in process / driver context read the
    /// clock once and pass it in so test code can pin time.
    /// # C: O(log N)
    pub fn insert_at(&self, ip: Ipv4Addr, mac: MacAddr, now_ns: u64) {
        let _ = self.learn_at(ip, mac, NudState::Reachable, now_ns);
    }

    /// Learn one neighbour with the NUD state justified by its ARP evidence.
    /// # C: O(log N)
    pub fn learn_at(&self, ip: Ipv4Addr, mac: MacAddr, state: NudState, now_ns: u64)
        -> Vec<crate::netdev::tx_dispatch::TxJob>
    {
        if self.closed.load(Ordering::Acquire) { return Vec::new(); }
        let mut entries = self.inner.lock();
        let entry = entries.entry(ip).or_insert_with(|| ArpEntry {
            mac: None, inserted_ns: now_ns, state: NudState::Incomplete,
            pending: VecDeque::new(), pending_bytes: 0, source_ip: Ipv4Addr::ANY,
            probes: 0, probe_deadline_ns: 0,
        });
        entry.mac = Some(mac);
        entry.inserted_ns = now_ns;
        entry.state = state;
        entry.probes = 0;
        entry.probe_deadline_ns = 0;
        entry.pending_bytes = 0;
        core::mem::take(&mut entry.pending)
    }

    /// Learn one neighbour using the current monotonic timestamp. # C: O(log N)
    pub fn learn(&self, ip: Ipv4Addr, mac: MacAddr, state: NudState) {
        let _ = self.learn_at(ip, mac, state, now_ns_safe());
    }

    /// Timestamp-less insert. On kernel builds reads monotonic_ns
    /// itself; on hosted-test builds stamps 0 (entry never stales).
    /// Production driver callers don't need to thread a clock.
    /// # C: O(log N)
    pub fn insert(&self, ip: Ipv4Addr, mac: MacAddr) {
        self.insert_at(ip, mac, now_ns_safe())
    }

    /// Remove all neighbor state when the owning interface leaves a namespace. # C: O(N)
    pub fn clear(&self) -> Vec<crate::netdev::tx_dispatch::TxJob> {
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
    pub fn lookup_at(&self, ip: Ipv4Addr, now_ns: u64) -> Option<MacAddr> {
        if self.closed.load(Ordering::Acquire) { return None; }
        let mut g = self.inner.lock();
        let mac = match g.get(&ip) {
            Some(e) => {
                if now_ns != 0 && e.inserted_ns != 0
                    && now_ns.saturating_sub(e.inserted_ns) > ARP_STALE_NS
                {
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
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        self.lookup_at(ip, now_ns_safe())
    }

    /// Snapshot one neighbour's link address and NUD state without consuming it.
    /// # C: O(log N)
    pub fn neighbour(&self, ip: Ipv4Addr) -> Option<(MacAddr, NudState)> {
        if self.closed.load(Ordering::Acquire) { return None; }
        self.inner.lock().get(&ip).and_then(|entry| entry.mac.map(|mac| (mac, entry.state)))
    }

    /// Remove one neighbour entry and all state owned beneath it. # C: O(log N)
    pub fn remove(&self, ip: Ipv4Addr) -> Option<ArpEntry> {
        self.inner.lock().remove(&ip)
    }

    /// # C: O(N)
    pub fn snapshot(&self) -> alloc::vec::Vec<(Ipv4Addr, MacAddr)> {
        if self.closed.load(Ordering::Acquire) { return alloc::vec::Vec::new(); }
        self.inner.lock().iter().filter_map(|(k, v)| v.mac.map(|mac| (*k, mac))).collect()
    }

    /// F177: garbage-collect any entries older than `ARP_STALE_NS`.
    /// Intended caller is the rx kthread's periodic tick (~100ms);
    /// `now_ns == 0` is a no-op (pre-clock).
    /// # C: O(N)
    pub fn gc(&self, now_ns: u64) {
        if self.closed.load(Ordering::Acquire) { return; }
        if now_ns == 0 { return; }
        self.inner.lock().retain(|_, e| {
            e.inserted_ns == 0
                || now_ns.saturating_sub(e.inserted_ns) <= ARP_STALE_NS
        });
    }

    /// Resolve one IPv4 next-hop or retain its exact dispatch in the pending FIFO. # C: O(log N)
    pub(crate) fn resolve_or_queue(&self, next_hop: Ipv4Addr, source_ip: Ipv4Addr,
        job: crate::netdev::tx_dispatch::TxJob, now_ns: u64) -> ArpResolution
    {
        if self.closed.load(Ordering::Acquire) {
            return ArpResolution::Deferred { probe: None, dropped: alloc::vec![job] };
        }
        let bytes = job.packet_len();
        let lease = job.lease();
        let mut entries = self.inner.lock();
        if self.closed.load(Ordering::Acquire) {
            drop(entries);
            return ArpResolution::Deferred { probe: None, dropped: alloc::vec![job] };
        }
        let entry = entries.entry(next_hop).or_insert_with(|| ArpEntry {
            mac: None, inserted_ns: now_ns, state: NudState::Incomplete,
            pending: VecDeque::new(), pending_bytes: 0, source_ip,
            probes: 0, probe_deadline_ns: 0,
        });
        if entry.state.usable() {
            if let Some(mac) = entry.mac { return ArpResolution::Send { job, mac }; }
        }
        let mut dropped = Vec::new();
        if bytes > ARP_UNRESOLVED_QUEUE_BYTES {
            dropped.push(job);
            return ArpResolution::Deferred { probe: None, dropped };
        }
        while entry.pending_bytes.saturating_add(bytes) > ARP_UNRESOLVED_QUEUE_BYTES {
            let Some(oldest) = entry.pending.pop_front() else { break };
            entry.pending_bytes = entry.pending_bytes.saturating_sub(oldest.packet_len());
            dropped.push(oldest);
        }
        entry.pending_bytes = entry.pending_bytes.saturating_add(bytes);
        entry.pending.push_back(job);
        if entry.probes != 0 { return ArpResolution::Deferred { probe: None, dropped }; }
        entry.probes = 1;
        entry.source_ip = source_ip;
        entry.probe_deadline_ns = now_ns;
        ArpResolution::Deferred {
            probe: Some(ArpProbe { lease, source_ip, target_ip: next_hop }),
            dropped,
        }
    }
}

impl Default for ArpCache { fn default() -> Self { Self::new() } }

/// F177: monotonic-ns reader visible to ArpCache without forcing
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = ArpPkt {
            opcode: ARP_OP_REQUEST,
            sender_mac: MacAddr([1,2,3,4,5,6]),
            sender_ip:  Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddr::ZERO,
            target_ip:  Ipv4Addr::new(10, 0, 0, 2),
        };
        let mut buf = alloc::vec![0u8; ARP_LEN];
        p.write_to(&mut buf);
        let q = ArpPkt::parse(&buf).unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn build_reply_from_request() {
        let req = ArpPkt {
            opcode: ARP_OP_REQUEST,
            sender_mac: MacAddr([1,2,3,4,5,6]),
            sender_ip:  Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddr::ZERO,
            target_ip:  Ipv4Addr::new(10, 0, 0, 2),
        };
        let our_mac = MacAddr([0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
        let reply = build_reply(&req, our_mac);
        let p = ArpPkt::parse(&reply).unwrap();
        assert_eq!(p.opcode, ARP_OP_REPLY);
        assert_eq!(p.sender_mac, our_mac);
        assert_eq!(p.sender_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(p.target_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn cache_round_trip() {
        let c = ArpCache::new();
        c.insert(Ipv4Addr::new(192, 168, 1, 5), MacAddr([5,6,7,8,9,10]));
        assert_eq!(c.lookup(Ipv4Addr::new(192, 168, 1, 5)),
                   Some(MacAddr([5,6,7,8,9,10])));
        assert_eq!(c.lookup(Ipv4Addr::new(1,2,3,4)), None);
    }

    #[test]
    fn rejects_short() {
        let buf = [0u8; 16];
        assert_eq!(ArpPkt::parse(&buf).err().unwrap(), ArpError::Short);
    }
}
