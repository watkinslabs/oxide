// The ephemeral-port scan order — Linux `__inet_hash_connect`
// and `inet_csk_find_open_port`, which differ only in starting parity.
//
// Pure: a function of (range, starting offset, parity). The whole point of the
// change is that the *offset* is unpredictable; the walk from it stays a
// deterministic full-range sweep so exhaustion still costs O(range) and every
// candidate port is visited exactly once.

/// Linux scans even and odd offsets in two passes so `connect()` and `bind(0)`
/// do not contend for the same ports; each pass steps by this.
const PARITY_STEP: u32 = 2;
/// Number of parity passes needed to cover the range.
const PARITY_PASSES: u32 = 2;

/// Which parity a caller starts on. Linux `__inet_hash_connect` does
/// `offset &= ~1U` (connect favours low parity) and `inet_csk_find_open_port`
/// does `offset |= 1U` ("the opposite choice, to not pollute connect users").
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Parity { Connect, Bind }

/// Candidate ports in Linux's scan order. # C: O(1) per step
pub(crate) struct PortScan {
    low: u32,
    /// Linux `remaining`, forced even so the two parity passes tile it exactly.
    remaining: u32,
    offset: u32,
    pass: u32,
    step_in_pass: u32,
}

impl PortScan {
    /// `count` is the inclusive width of the local-port range, `offset` the
    /// unpredictable start from `secure_seq`. # C: O(1)
    pub(crate) fn new(low: u16, count: u32, offset: u32, parity: Parity) -> Self {
        // Linux `if (likely(remaining > 1)) remaining &= ~1U;` — an odd trailing
        // port is left to explicit bind, exactly as upstream.
        let remaining = if count > 1 { count & !1 } else { count };
        let offset = if remaining == 0 { 0 } else { offset % remaining };
        let offset = match parity {
            Parity::Connect => offset & !1,
            Parity::Bind    => offset | 1,
        };
        Self { low: low as u32, remaining, offset, pass: 0, step_in_pass: 0 }
    }
}

impl Iterator for PortScan {
    type Item = u16;

    /// # C: O(1)
    fn next(&mut self) -> Option<u16> {
        if self.remaining == 0 { return None; }
        if self.remaining == 1 {
            if self.pass > 0 { return None; }
            self.pass = PARITY_PASSES;
            return Some(self.low as u16);
        }
        if self.step_in_pass >= self.remaining {
            // Linux flips parity once (`offset++` / `offset--`, then re-scan).
            self.pass += 1;
            if self.pass >= PARITY_PASSES { return None; }
            self.offset = (self.offset + 1) % self.remaining;
            self.step_in_pass = 0;
        }
        let port = self.low + (self.offset + self.step_in_pass) % self.remaining;
        self.step_in_pass += PARITY_STEP;
        Some(port as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::vec::Vec;

    /// The security property the old allocator failed: consecutive
    /// allocations must not start at a fixed base.
    #[test]
    fn different_offsets_start_at_different_ports() {
        let a = PortScan::new(32_768, 28_232, 0, Parity::Connect).next().unwrap();
        let b = PortScan::new(32_768, 28_232, 5_000, Parity::Connect).next().unwrap();
        let c = PortScan::new(32_768, 28_232, 19_997, Parity::Connect).next().unwrap();
        assert_ne!(a, b); assert_ne!(b, c); assert_ne!(a, c);
    }

    #[test]
    fn every_port_is_visited_exactly_once_over_both_parities() {
        // Exhaustion must still be a complete sweep — a randomized offset that
        // skipped ports would turn EADDRNOTAVAIL into a lie.
        for parity in [Parity::Connect, Parity::Bind] {
            for offset in [0u32, 1, 7, 40, 99] {
                let seen: Vec<u16> = PortScan::new(40_000, 40, offset, parity).collect();
                assert_eq!(seen.len(), 40, "{parity:?} offset {offset}");
                let unique: BTreeSet<u16> = seen.iter().copied().collect();
                assert_eq!(unique.len(), 40, "{parity:?} offset {offset} revisited a port");
                assert_eq!(*unique.first().unwrap(), 40_000);
                assert_eq!(*unique.last().unwrap(), 40_039);
            }
        }
    }

    #[test]
    fn connect_and_bind_start_on_opposite_parities() {
        // Linux's reason for the split: a connect() sweep and a bind(0) sweep
        // starting from the same offset must not collide port-for-port.
        let connect = PortScan::new(40_000, 40, 9, Parity::Connect).next().unwrap();
        let bind    = PortScan::new(40_000, 40, 9, Parity::Bind).next().unwrap();
        assert_eq!((connect - 40_000) % 2, 0);
        assert_eq!((bind - 40_000) % 2, 1);
    }

    #[test]
    fn odd_range_leaves_its_trailing_port_to_explicit_bind() {
        // Linux `remaining &= ~1U`. Asserted so a future "tidy" does not
        // silently change which ports auto-bind can reach.
        let seen: Vec<u16> = PortScan::new(100, 5, 0, Parity::Connect).collect();
        assert_eq!(seen.len(), 4);
        assert!(!seen.contains(&104));
    }

    #[test]
    fn degenerate_ranges_terminate() {
        assert_eq!(PortScan::new(1_000, 1, 0, Parity::Connect).collect::<Vec<_>>(), std::vec![1_000]);
        assert_eq!(PortScan::new(1_000, 0, 0, Parity::Bind).count(), 0);
    }
}
