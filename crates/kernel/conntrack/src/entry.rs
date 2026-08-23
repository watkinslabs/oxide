//! One tracked connection. The entry holds both tuples — original and reply —
//! because a NAT binding rewrites one of them, and every later packet is
//! matched against whichever half it presents on the wire.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::proto::tcp_window::TcpTrack;
use crate::proto::udp::UdpTrack;
use crate::tuple::Tuple;
use crate::uapi::*;

/// Per-protocol tracking state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProtoState { Tcp(TcpTrack), Udp(UdpTrack), Icmp, Generic }

impl ProtoState {
    /// State appropriate to one L4 protocol. # C: O(1)
    pub fn for_proto(protonum: u8) -> Self {
        match protonum {
            IPPROTO_TCP => ProtoState::Tcp(TcpTrack::default()),
            IPPROTO_UDP | IPPROTO_UDPLITE => ProtoState::Udp(UdpTrack::default()),
            IPPROTO_ICMP | IPPROTO_ICMPV6 => ProtoState::Icmp,
            _ => ProtoState::Generic,
        }
    }
}

/// Per-direction byte and packet counters.
#[derive(Debug, Default)]
pub struct DirCounters { pub packets: AtomicU64, pub bytes: AtomicU64 }

impl DirCounters {
    /// # C: O(1)
    pub fn account(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    /// # C: O(1)
    pub fn read(&self) -> (u64, u64) {
        (self.packets.load(Ordering::Relaxed), self.bytes.load(Ordering::Relaxed))
    }
}

/// NAT binding recorded on an entry. The manip is decided once, on the first
/// packet, and every later packet replays it from here — re-deciding per
/// packet would let a rule change mid-flow and split one conversation across
/// two translations.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NatBinding {
    /// Egress interface a masquerade binding was chosen for. A change means
    /// the chosen source address is no longer valid for this flow.
    pub masq_index: u32,
}

/// A tracked connection.
pub struct Conn {
    /// Unique, stable id — the value ctnetlink reports as `CTA_ID`.
    pub id: u64,
    /// Tuple in the direction the connection was opened.
    pub orig: Tuple,
    /// Tuple a reply carries. Under NAT this is not the inverse of `orig`.
    pub reply: sync::Spinlock<Tuple, sync::Socket>,
    /// `IPS_*` bits.
    pub status: AtomicU32,
    /// Absolute expiry, seconds.
    pub timeout: AtomicU64,
    pub mark: AtomicU32,
    pub secmark: AtomicU32,
    pub proto: sync::Spinlock<ProtoState, sync::Socket>,
    pub counters: [DirCounters; IP_CT_DIR_MAX],
    /// Master connection when this entry was created from an expectation.
    pub master: Option<Arc<Conn>>,
    /// Helper attached to this flow, by name.
    pub helper: sync::Spinlock<Option<String>, sync::Socket>,
    pub nat: sync::Spinlock<NatBinding, sync::Socket>,
    /// Network namespace that owns the entry.
    pub net_ns: u64,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Conn").field("id", &self.id).field("orig", &self.orig)
            .field("reply", &*self.reply.lock()).field("status", &self.status()).finish()
    }
}

impl Conn {
    /// Build an unconfirmed entry for a flow whose reply tuple is the plain
    /// inverse of its original. # C: O(1)
    pub fn new(id: u64, orig: Tuple, reply: Tuple, net_ns: u64) -> Self {
        Self {
            id, orig, reply: sync::Spinlock::new(reply),
            status: AtomicU32::new(0),
            timeout: AtomicU64::new(0),
            mark: AtomicU32::new(0),
            secmark: AtomicU32::new(0),
            proto: sync::Spinlock::new(ProtoState::for_proto(orig.protonum)),
            counters: [DirCounters::default(), DirCounters::default()],
            master: None,
            helper: sync::Spinlock::new(None),
            nat: sync::Spinlock::new(NatBinding::default()),
            net_ns,
        }
    }

    /// # C: O(1)
    pub fn status(&self) -> u32 { self.status.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_status_bits(&self, bits: u32) { self.status.fetch_or(bits, Ordering::AcqRel); }
    /// # C: O(1)
    pub fn clear_status_bits(&self, bits: u32) {
        self.status.fetch_and(!bits, Ordering::AcqRel);
    }
    /// # C: O(1)
    pub fn confirmed(&self) -> bool { self.status() & IPS_CONFIRMED != 0 }
    /// # C: O(1)
    pub fn dying(&self) -> bool { self.status() & IPS_DYING != 0 }

    /// Arm the expiry. A fixed-timeout entry keeps whatever ctnetlink set.
    /// # C: O(1)
    pub fn refresh(&self, now: u64, secs: u32) {
        if self.status() & IPS_FIXED_TIMEOUT != 0 { return; }
        self.timeout.store(now + secs as u64, Ordering::Release);
    }

    /// Seconds until expiry, saturating at zero. # C: O(1)
    pub fn expires_in(&self, now: u64) -> u64 {
        self.timeout.load(Ordering::Acquire).saturating_sub(now)
    }

    /// # C: O(1)
    pub fn expired(&self, now: u64) -> bool {
        self.timeout.load(Ordering::Acquire) <= now
    }

    /// Rewrite the reply tuple after a NAT binding is chosen. Only legal
    /// before the entry is confirmed: the table is keyed on both tuples, so
    /// changing one after insertion strands the old key.
    /// # C: O(1)
    pub fn alter_reply(&self, reply: Tuple) -> bool {
        if self.confirmed() { return false; }
        *self.reply.lock() = reply;
        true
    }

    /// The tuple this entry presents in `dir`. # C: O(1)
    pub fn tuple(&self, dir: u8) -> Tuple {
        if dir == IP_CT_DIR_REPLY { *self.reply.lock() } else { self.orig }
    }

    /// Snapshot the currently committed reply key. # C: O(1)
    pub fn reply_tuple(&self) -> Tuple { *self.reply.lock() }

    /// Conntrack-info value for a packet arriving in `dir`. # C: O(1)
    pub fn ctinfo(&self, dir: u8) -> u8 {
        let related = self.status() & IPS_EXPECTED != 0;
        match (related, dir) {
            (true,  IP_CT_DIR_REPLY) => IP_CT_RELATED_REPLY,
            (true,  _)               => IP_CT_RELATED,
            (false, IP_CT_DIR_REPLY) => IP_CT_ESTABLISHED_REPLY,
            (false, _) => {
                if self.status() & IPS_SEEN_REPLY != 0 { IP_CT_ESTABLISHED } else { IP_CT_NEW }
            }
        }
    }
}
