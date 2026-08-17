//! Index assignment for the expressions that keep state between packets.
//! Each kind counts independently, so an expression's index is its position
//! among expressions of its own kind within the rule.

/// Running index per stateful expression kind.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct StateAlloc {
    limits: usize,
    quotas: usize,
    numgens: usize,
    lasts: usize,
    connlimits: usize,
}

impl StateAlloc {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { limits: 0, quotas: 0, numgens: 0, lasts: 0, connlimits: 0 }
    }
    /// # C: O(1)
    pub fn take_limit(&mut self) -> usize { let i = self.limits; self.limits += 1; i }
    /// # C: O(1)
    pub fn take_quota(&mut self) -> usize { let i = self.quotas; self.quotas += 1; i }
    /// # C: O(1)
    pub fn take_numgen(&mut self) -> usize { let i = self.numgens; self.numgens += 1; i }
    /// # C: O(1)
    pub fn take_last(&mut self) -> usize { let i = self.lasts; self.lasts += 1; i }
    /// # C: O(1)
    pub fn take_connlimit(&mut self) -> usize {
        let i = self.connlimits; self.connlimits += 1; i
    }
}
