//! Fallback order. The list holds every populated zone in decreasing index,
//! and an allocation enters it at the first entry whose index is at or below
//! the highest zone its flags permit. Because index order is address order,
//! entering below the permitted index is impossible and every later entry is
//! lower still — which is the property that keeps a bounded request inside its
//! bound no matter how the walk ends.

use super::types::{ZoneType, NR_ZONES};

/// Populated zones in fallback order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Zonelist { entries: [u8; NR_ZONES], len: usize }

impl Default for Zonelist {
    fn default() -> Self { Self { entries: [0; NR_ZONES], len: 0 } }
}

impl Zonelist {
    /// Build from a populated-zone predicate, highest index first.
    /// # C: O(NR_ZONES)
    pub fn build(populated: [bool; NR_ZONES]) -> Self {
        let mut out = Self::default();
        let mut i = NR_ZONES;
        while i > 0 {
            i -= 1;
            if populated[i] { out.entries[out.len] = i as u8; out.len += 1; }
        }
        out
    }

    /// Number of populated zones. # C: O(1)
    pub const fn len(&self) -> usize { self.len }

    /// Is no zone populated? # C: O(1)
    pub const fn is_empty(&self) -> bool { self.len == 0 }

    /// Zone indices to try, in order, for an allocation whose highest
    /// permitted zone is `highest_zoneidx`. # C: O(NR_ZONES)
    pub fn walk(&self, highest_zoneidx: usize) -> ZonelistWalk<'_> {
        ZonelistWalk { list: self, pos: 0, highest_zoneidx }
    }

    /// Entry at `pos` regardless of any bound. # C: O(1)
    pub const fn entry(&self, pos: usize) -> Option<usize> {
        if pos < self.len { Some(self.entries[pos] as usize) } else { None }
    }
}

/// Cursor over the eligible part of a zonelist.
pub struct ZonelistWalk<'a> { list: &'a Zonelist, pos: usize, highest_zoneidx: usize }

impl Iterator for ZonelistWalk<'_> {
    type Item = ZoneType;
    fn next(&mut self) -> Option<ZoneType> {
        while self.pos < self.list.len {
            let idx = self.list.entries[self.pos] as usize;
            self.pos += 1;
            if idx <= self.highest_zoneidx { return ZoneType::from_index(idx); }
        }
        None
    }
}
