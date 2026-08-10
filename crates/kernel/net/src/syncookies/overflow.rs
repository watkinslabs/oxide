// The SYN-queue overflow stamp itself: the cell, and the two operations on it.
//
// The stamp is a listener's willingness to BELIEVE a cookie, and one stamp
// belongs to a whole SO_REUSEPORT bind key rather than to each socket in it.
// Every member of a key shares one key's worth of connection-request pressure,
// and a cookie minted by whichever member an arriving SYN hashed to comes back
// as a bare acknowledgement that a program, a changed member count or a
// different four-tuple hash may steer to a DIFFERENT member. A per-socket stamp
// makes the key refuse its own cookies exactly whenever the two halves of one
// handshake land on different members — which under the flood cookies exist for
// is the common case, not the corner one.
//
// One implementation, two owners: the group's cell when the listener joined a
// group, the listener's own otherwise. No target gate (`docs/53§4`).

use core::sync::atomic::{AtomicU64, Ordering};

/// A cell that has never recorded an overflow. # C: O(1)
pub fn new_cell() -> AtomicU64 { AtomicU64::new(super::NEVER) }

/// Record an overflow. Rewritten at most once a stamp period: a flood is the
/// one moment where dirtying a shared line per SYN costs most, and the line is
/// shared by the whole group. # C: O(1)
pub fn note(cell: &AtomicU64, now_ns: u64) {
    let last = cell.load(Ordering::Relaxed);
    if super::restamp_overflow(last, now_ns) { cell.store(now_ns, Ordering::Relaxed); }
}

/// Whether the owner of this cell has NOT overflowed recently enough to
/// believe a cookie. # C: O(1)
pub fn no_recent(cell: &AtomicU64, now_ns: u64) -> bool {
    super::no_recent_overflow(cell.load(Ordering::Relaxed), now_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_cell_believes_no_cookie_and_one_overflow_makes_it_believe() {
        let cell = new_cell();
        assert!(no_recent(&cell, 5_000_000_000));
        note(&cell, 5_000_000_000);
        assert!(!no_recent(&cell, 5_000_000_000));
    }

    #[test]
    fn the_stamp_is_rewritten_at_most_once_a_stamp_period() {
        let cell = new_cell();
        note(&cell, 10_000_000_000);
        note(&cell, 10_500_000_000);
        assert_eq!(cell.load(Ordering::Relaxed), 10_000_000_000);
        note(&cell, 12_000_000_000);
        assert_eq!(cell.load(Ordering::Relaxed), 12_000_000_000);
    }

    #[test]
    fn belief_expires_after_the_cookie_validity_window() {
        let cell = new_cell();
        note(&cell, 1_000_000_000);
        assert!(!no_recent(&cell, 1_000_000_000 + super::super::SYNCOOKIE_VALID_NS));
        assert!(no_recent(&cell, 1_000_000_001 + super::super::SYNCOOKIE_VALID_NS));
    }
}
