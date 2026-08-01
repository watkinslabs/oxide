// `IP_MINTTL` / `IPV6_MINHOPCOUNT`: the generalized hop-limit security check.
// One object per socket, shared with the transport entry the receive path
// reaches, so the option has exactly one home.

use core::sync::atomic::{AtomicI32, Ordering};

/// The two minimums a socket may demand of an arriving segment. They are
/// separate because a dual-stack socket answers an IPv4-mapped connection
/// through the IPv4 minimum and a native one through the IPv6 minimum.
#[derive(Debug, Default)]
pub struct MinHop { ttl: AtomicI32, hopcount: AtomicI32 }

impl MinHop {
    /// # C: O(1)
    pub const fn new() -> Self { Self { ttl: AtomicI32::new(0), hopcount: AtomicI32::new(0) } }

    /// # C: O(1)
    pub fn ttl(&self) -> i32 { self.ttl.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_ttl(&self, value: i32) { self.ttl.store(value, Ordering::Release); }

    /// # C: O(1)
    pub fn hopcount(&self) -> i32 { self.hopcount.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_hopcount(&self, value: i32) { self.hopcount.store(value, Ordering::Release); }

    /// Whether an arriving segment is refused. The check is only ever applied
    /// to a connection-oriented socket: datagram and raw receives ignore both
    /// minimums entirely. # C: O(1)
    pub fn refuses(&self, hop: u8, ipv6: bool) -> bool {
        below_minimum(hop, if ipv6 { self.hopcount() } else { self.ttl() })
    }
}

/// A segment whose hop limit is below the socket's minimum is dropped, and
/// dropped SILENTLY — no reset, no error message, nothing the peer can use to
/// distinguish it from a lost packet. A minimum of zero, the value a socket is
/// created with, admits everything. # C: O(1)
pub fn below_minimum(hop: u8, minimum: i32) -> bool {
    minimum > 0 && (hop as i32) < minimum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_minimum_admits_every_hop_limit() {
        assert!(!below_minimum(0, 0));
        assert!(!below_minimum(255, 0));
        let limits = MinHop::new();
        assert_eq!(limits.ttl(), 0);
        assert_eq!(limits.hopcount(), 0);
        assert!(!limits.refuses(0, false));
        assert!(!limits.refuses(0, true));
    }

    #[test]
    fn a_segment_at_the_minimum_is_admitted_and_one_below_is_refused() {
        // The check that makes a peer prove it is one hop away: only a segment
        // that started at the maximum and was never forwarded arrives at 255.
        assert!(!below_minimum(255, 255));
        assert!(below_minimum(254, 255));
        assert!(!below_minimum(64, 64));
        assert!(below_minimum(63, 64));
        assert!(!below_minimum(1, 1));
        assert!(below_minimum(0, 1));
    }

    #[test]
    fn the_two_families_are_independent() {
        let limits = MinHop::new();
        limits.set_ttl(255);
        assert!(limits.refuses(254, false));
        // The IPv6 minimum is untouched, so a native segment still passes.
        assert!(!limits.refuses(254, true));
        limits.set_hopcount(255);
        assert!(limits.refuses(254, true));
        // And clearing one leaves the other in force.
        limits.set_ttl(0);
        assert!(!limits.refuses(254, false));
        assert!(limits.refuses(254, true));
    }
}
