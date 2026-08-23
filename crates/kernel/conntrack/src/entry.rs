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

/// ctnetlink's mutable TCP protocol-info fields. Flag updates carry the
/// Linux `(flags, mask)` pair, so callers can change only selected bits.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpProtoInfoUpdate {
    pub state: Option<u8>,
    pub flags: [Option<(u8, u8)>; IP_CT_DIR_MAX],
}

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

/// TCP sequence translation carried by conntrack's sequence-adjust
/// extension, with one wire-space record per direction.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SeqAdjust {
    pub correction_pos: u32,
    pub offset_before: i32,
    pub offset_after: i32,
    pub active: bool,
}

/// Synproxy state carried by the conntrack extension between the cookie ACK
/// and the protected peer's SYN-ACK.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SynproxyState {
    pub isn: u32,
    pub its: u32,
    pub tsoff: i32,
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
    /// Sequence-adjust extension, one record for each TCP direction.
    pub seqadj: sync::Spinlock<[SeqAdjust; IP_CT_DIR_MAX], sync::Socket>,
    /// ISN relayed by synproxy until the protected peer's SYN-ACK arrives.
    pub synproxy: sync::Spinlock<Option<SynproxyState>, sync::Socket>,
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
            seqadj: sync::Spinlock::new([SeqAdjust::default(); IP_CT_DIR_MAX]),
            synproxy: sync::Spinlock::new(None),
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

    /// Initialize or clear one direction's sequence correction. # C: O(1)
    pub fn seqadj_init(&self, dir: u8, offset: i32) {
        let index = dir as usize;
        if index >= IP_CT_DIR_MAX { return; }
        let all_clear = {
            let mut state = self.seqadj.lock();
            state[index] = SeqAdjust {
                correction_pos: 0,
                offset_before: offset,
                offset_after: offset,
                active: offset != 0,
            };
            state.iter().all(|item| !item.active)
        };
        if all_clear { self.clear_status_bits(IPS_SEQ_ADJUST); }
        else { self.set_status_bits(IPS_SEQ_ADJUST); }
    }

    /// Return the sequence-space correction valid at one wire sequence. # C: O(1)
    pub fn seqadj_offset(&self, dir: u8, seq: u32) -> i32 {
        let Some(slot) = self.seqadj.lock().get(dir as usize).copied() else { return 0; };
        if !slot.active { return 0; }
        if serial_after(seq, slot.correction_pos) { slot.offset_after } else { slot.offset_before }
    }

    /// Return the offset for an acknowledgement or SACK value. Linux first
    /// removes the pre-correction offset before testing the correction point.
    /// # C: O(1)
    pub fn seqadj_ack_offset(&self, dir: u8, ack: u32) -> i32 {
        let Some(slot) = self.seqadj.lock().get(dir as usize).copied() else { return 0; };
        if !slot.active { return 0; }
        let probe = ack.wrapping_sub(slot.offset_before as u32);
        if serial_after(probe, slot.correction_pos) { slot.offset_after } else { slot.offset_before }
    }

    /// Add a later stream correction at a TCP sequence boundary. # C: O(1)
    pub fn seqadj_set(&self, dir: u8, correction_pos: u32, delta: i32) {
        let index = dir as usize;
        if index >= IP_CT_DIR_MAX || delta == 0 { return; }
        let mut state = self.seqadj.lock();
        let slot = &mut state[index];
        if !slot.active || slot.offset_before == slot.offset_after
            || serial_after(correction_pos, slot.correction_pos) {
            slot.correction_pos = correction_pos;
            slot.offset_before = slot.offset_after;
            slot.offset_after = slot.offset_after.saturating_add(delta);
            slot.active = true;
            drop(state);
            self.set_status_bits(IPS_SEQ_ADJUST);
        }
    }

    /// Return one direction's raw sequence-adjust record. # C: O(1)
    pub fn seqadj_record(&self, dir: u8) -> SeqAdjust {
        self.seqadj.lock().get(dir as usize).copied().unwrap_or_default()
    }

    /// Replace one direction's userspace-visible sequence-adjust record. # C: O(1)
    pub fn seqadj_replace(&self, dir: u8, record: SeqAdjust) -> bool {
        let mut state = self.seqadj.lock();
        let Some(slot) = state.get_mut(dir as usize) else { return false; };
        *slot = record;
        if record.active { self.set_status_bits(IPS_SEQ_ADJUST); }
        true
    }

    /// Apply ctnetlink's TCP state and masked flag updates. # C: O(1)
    pub fn tcp_protoinfo_update(&self, update: TcpProtoInfoUpdate) -> bool {
        let mut proto = self.proto.lock();
        let ProtoState::Tcp(track) = &mut *proto else { return false; };
        let mut changed = false;
        if let Some(state) = update.state {
            changed |= track.state != state;
            track.state = state;
        }
        for (dir, flags) in update.flags.into_iter().enumerate() {
            let Some((value, mask)) = flags else { continue; };
            let old = track.seen[dir].flags;
            let new = (old & !mask) | (value & mask);
            changed |= old != new;
            track.seen[dir].flags = new;
        }
        changed
    }

    /// Attach a helper name to this flow. Explicit ctnetlink attachment also
    /// records Linux's `IPS_HELPER` selection bit; automatic assignment does
    /// not, so a later explicit choice still follows the helper policy. # C: O(1)
    pub fn attach_helper(&self, name: String, explicit: bool) {
        *self.helper.lock() = Some(name);
        if explicit { self.set_status_bits(IPS_HELPER); }
    }

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

/// RFC 1982 serial-number ordering used by conntrack's `after()` predicate.
fn serial_after(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) > 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuple::{InetAddr, ProtoPart, TupleEnd};

    fn conn() -> Conn {
        let orig = Tuple {
            l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP,
            src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]), proto: ProtoPart::port(4000) },
            dst: TupleEnd { addr: InetAddr::v4([10, 0, 0, 2]), proto: ProtoPart::port(80) },
            zone: 0,
        };
        Conn::new(1, orig, orig.invert().unwrap(), 0)
    }

    #[test]
    fn sequence_adjust_uses_before_and_after_offsets() {
        let c = conn();
        c.seqadj_init(IP_CT_DIR_REPLY, 100);
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 10), 100);
        c.seqadj.lock()[IP_CT_DIR_REPLY as usize].correction_pos = 50;
        c.seqadj.lock()[IP_CT_DIR_REPLY as usize].offset_after = 120;
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 50), 100);
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 51), 120);
        assert_eq!(c.status() & IPS_SEQ_ADJUST, IPS_SEQ_ADJUST);
        c.seqadj_set(IP_CT_DIR_REPLY, 100, 5);
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 99), 120);
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 101), 125);
    }

    #[test]
    fn sequence_adjust_can_be_reset_without_leaking_status() {
        let c = conn();
        c.seqadj_init(IP_CT_DIR_REPLY, 100);
        c.seqadj_init(IP_CT_DIR_REPLY, 0);
        assert_eq!(c.status() & IPS_SEQ_ADJUST, 0);
        assert_eq!(c.seqadj_offset(IP_CT_DIR_REPLY, 10), 0);
    }
}
