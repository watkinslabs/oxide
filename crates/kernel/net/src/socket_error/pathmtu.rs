//! `IPV6_RECVPATHMTU`: the one-slot path-MTU report an IPv6 socket collects
//! from its own receive, not from its error queue.
//!
//! Two mechanisms answer "the datagram was too big" on IPv6 and they are not
//! the same thing. The extended-error queue carries a local-origin record that
//! `MSG_ERRQUEUE` collects; this slot carries a bare path-MTU announcement
//! that an ORDINARY receive collects, ahead of any queued datagram. A socket
//! can have both switched on and they do not share storage, an identifier
//! space, or a consumption rule: reading one leaves the other alone.
//!
//! The slot holds exactly one report — a newer one replaces the older, because
//! a stale MTU is worse than a missed one — and the receive that takes it
//! empties it.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::Ipv6Addr;

/// Wire size of the report: a `sockaddr_in6` naming the destination whose path
/// rejected the datagram, then the MTU that rejected it.
pub const PATHMTU_RECORD_LEN: usize = 32;
/// Offset of the MTU word inside the record.
const MTU_AT: usize = 28;
/// `SOL_IPV6` and the ancillary number the report is emitted under.
pub const SOL_IPV6: i32 = 41;
pub const IPV6_PATHMTU: i32 = 61;
const AF_INET6: u16 = 10;

/// One stashed path-MTU report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMtuReport {
    pub dst: Ipv6Addr,
    /// Egress interface the report names, published as the address scope.
    pub oif: u32,
    pub mtu: u32,
}

/// The socket's single report slot.
#[derive(Debug)]
pub struct PathMtuSlot {
    present: AtomicBool,
    dst: [AtomicU32; 4],
    oif: AtomicU32,
    mtu: AtomicU32,
}

impl Default for PathMtuSlot {
    fn default() -> Self { Self::new() }
}

impl PathMtuSlot {
    /// An empty slot. # C: O(1)
    pub const fn new() -> Self {
        Self { present: AtomicBool::new(false),
            dst: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
            oif: AtomicU32::new(0), mtu: AtomicU32::new(0) }
    }

    /// Replace whatever the slot held. A socket that did not ask for the
    /// report never reaches here; the caller owns that switch. # C: O(1)
    pub fn publish(&self, report: PathMtuReport) {
        let raw = report.dst.0;
        for (word, slot) in raw.chunks_exact(4).zip(self.dst.iter()) {
            slot.store(u32::from_ne_bytes(word.try_into().unwrap_or_default()), Ordering::Release);
        }
        self.oif.store(report.oif, Ordering::Release);
        self.mtu.store(report.mtu, Ordering::Release);
        self.present.store(true, Ordering::Release);
    }

    /// Whether an ordinary receive would answer with the report instead of a
    /// queued datagram. # C: O(1)
    pub fn pending(&self) -> bool { self.present.load(Ordering::Acquire) }

    /// Take the report, emptying the slot. # C: O(1)
    pub fn take(&self) -> Option<PathMtuReport> {
        if !self.present.swap(false, Ordering::AcqRel) { return None; }
        let mut dst = [0u8; 16];
        for (word, slot) in dst.chunks_exact_mut(4).zip(self.dst.iter()) {
            word.copy_from_slice(&slot.load(Ordering::Acquire).to_ne_bytes());
        }
        Some(PathMtuReport { dst: Ipv6Addr(dst), oif: self.oif.load(Ordering::Acquire),
            mtu: self.mtu.load(Ordering::Acquire) })
    }
}

/// The report's wire bytes: the destination as a `sockaddr_in6` with no port
/// and no flow label, its scope carrying the egress interface, then the MTU.
/// # C: O(1)
pub fn record_bytes(report: &PathMtuReport) -> [u8; PATHMTU_RECORD_LEN] {
    let mut out = [0u8; PATHMTU_RECORD_LEN];
    out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    out[8..24].copy_from_slice(&report.dst.0);
    out[24..28].copy_from_slice(&report.oif.to_ne_bytes());
    out[MTU_AT..].copy_from_slice(&report.mtu.to_ne_bytes());
    out
}

/// The source address the same report answers with. Identical to the address
/// inside the record — one report, one destination, never two answers.
/// # C: O(1)
pub fn name_bytes(report: &PathMtuReport) -> [u8; 28] {
    let mut out = [0u8; 28];
    out.copy_from_slice(&record_bytes(report)[..28]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> PathMtuReport {
        PathMtuReport { dst: Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            oif: 3, mtu: 1280 }
    }

    // The slot answers once. A second receive finds nothing, so a socket
    // cannot be handed the same announcement twice.
    #[test]
    fn one_report_is_answered_exactly_once() {
        let slot = PathMtuSlot::default();
        assert!(!slot.pending());
        assert_eq!(slot.take(), None);
        slot.publish(report());
        assert!(slot.pending());
        assert_eq!(slot.take(), Some(report()));
        assert!(!slot.pending());
        assert_eq!(slot.take(), None);
    }

    // A newer announcement replaces an unread older one: a stale MTU is the
    // one answer that would make the caller send the wrong size again.
    #[test]
    fn a_newer_report_replaces_an_unread_one() {
        let slot = PathMtuSlot::default();
        slot.publish(report());
        slot.publish(PathMtuReport { mtu: 1400, ..report() });
        assert_eq!(slot.take().map(|r| r.mtu), Some(1400));
    }

    #[test]
    fn the_record_places_the_destination_then_the_mtu() {
        let raw = record_bytes(&report());
        assert_eq!(u16::from_ne_bytes(raw[0..2].try_into().unwrap()), AF_INET6);
        assert_eq!(&raw[2..8], &[0u8; 6], "no port, no flow label");
        assert_eq!(&raw[8..24], &report().dst.0);
        assert_eq!(u32::from_ne_bytes(raw[24..28].try_into().unwrap()), 3);
        assert_eq!(u32::from_ne_bytes(raw[MTU_AT..].try_into().unwrap()), 1280);
        assert_eq!(name_bytes(&report()), raw[..28]);
    }
}
