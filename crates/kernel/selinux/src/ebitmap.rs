// Extensible bitmap: a sparse set of small integers, used for type
// attributes, role type-sets, MLS categories, permissive types and policy
// capabilities.
//
// Stored as 64-bit chunks tagged with the bit position they start at, kept
// ascending and never empty. The wire format is fixed at 64-bit granularity
// regardless of host word size, so the in-memory chunking matches it exactly
// and a read is a validation pass rather than a repacking.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::reader::Reader;

/// Bits per wire chunk; the format rejects any other unit.
pub const MAP_UNIT: u32 = 64;

/// Bits per node in the reference in-memory layout on a 64-bit host. The
/// stored high bit is rounded up to this granularity, and the trailing
/// consistency check in the wire format is expressed in terms of it.
pub const NODE_BITS: u32 = 384;

/// Sparse set of bit positions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ebitmap {
    /// One past the highest representable position, rounded to `NODE_BITS`.
    highbit: u32,
    /// Ascending `(startbit, map)` chunks; `startbit` is a multiple of 64 and
    /// `map` is never zero.
    chunks: Vec<(u32, u64)>,
}

impl Ebitmap {
    /// Empty bitmap. # C: O(1)
    pub const fn new() -> Self { Self { highbit: 0, chunks: Vec::new() } }

    /// One past the highest representable position. # C: O(1)
    pub const fn highbit(&self) -> u32 { self.highbit }

    /// Whether no bit is set. # C: O(1)
    pub fn is_empty(&self) -> bool { self.chunks.is_empty() }

    /// Number of set bits. # C: O(chunks)
    pub fn count(&self) -> u32 { self.chunks.iter().map(|(_, m)| m.count_ones()).sum() }

    /// Whether one position is set. # C: O(log chunks)
    pub fn get(&self, bit: u32) -> bool {
        let start = bit & !(MAP_UNIT - 1);
        match self.chunks.binary_search_by_key(&start, |(s, _)| *s) {
            Ok(i) => self.chunks[i].1 & (1u64 << (bit - start)) != 0,
            Err(_) => false,
        }
    }

    /// Set or clear one position, growing the bitmap as needed. # C: O(chunks)
    pub fn set(&mut self, bit: u32, value: bool) {
        let start = bit & !(MAP_UNIT - 1);
        let mask = 1u64 << (bit - start);
        match self.chunks.binary_search_by_key(&start, |(s, _)| *s) {
            Ok(i) => {
                if value { self.chunks[i].1 |= mask; } else { self.chunks[i].1 &= !mask; }
                if self.chunks[i].1 == 0 { self.chunks.remove(i); }
            }
            Err(i) => if value { self.chunks.insert(i, (start, mask)); },
        }
        if value {
            let need = round_up_nodes(bit.saturating_add(1)).unwrap_or(u32::MAX);
            if need > self.highbit { self.highbit = need; }
        }
    }

    /// Ascending iterator over set positions. # C: O(bits)
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.chunks.iter().flat_map(|&(start, map)| {
            (0..MAP_UNIT).filter(move |b| map & (1u64 << b) != 0).map(move |b| start + b)
        })
    }

    /// Whether every bit of `other` is also set here. # C: O(chunks)
    pub fn contains(&self, other: &Self) -> bool {
        let mut mine = self.chunks.iter().peekable();
        for &(start, map) in &other.chunks {
            loop {
                match mine.peek() {
                    Some(&&(s, _)) if s < start => { mine.next(); }
                    Some(&&(s, m)) if s == start => {
                        if m & map != map { return false; }
                        mine.next();
                        break;
                    }
                    _ => return false,
                }
            }
        }
        true
    }

    /// Whether the two sets share at least one position. # C: O(chunks)
    pub fn intersects(&self, other: &Self) -> bool {
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.chunks.len() && j < other.chunks.len() {
            let (a, b) = (self.chunks[i], other.chunks[j]);
            if a.0 < b.0 { i += 1; } else if a.0 > b.0 { j += 1; }
            else {
                if a.1 & b.1 != 0 { return true; }
                i += 1;
                j += 1;
            }
        }
        false
    }

    /// Read one bitmap from a policy image. # C: O(count)
    ///
    /// The chunk sequence must be strictly ascending, 64-bit aligned, wholly
    /// below the declared high bit, and free of empty chunks; each of those is
    /// a refusal rather than a silently-tolerated oddity, because a lenient
    /// reader here turns a malformed policy into a set with the wrong members
    /// and therefore into a wrong access decision.
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let [mapunit, stored_highbit, count] = r.u32_array::<3>()?;
        if mapunit != MAP_UNIT { return Err(Error::Malformed); }

        // A declared extent so large that rounding it up to a node boundary
        // would not fit in the field cannot describe any real set; the image
        // is malformed, not merely large.
        let highbit = round_up_nodes(stored_highbit).ok_or(Error::TooLarge)?;
        if highbit == 0 {
            if count != 0 { return Err(Error::Malformed); }
            return Ok(Self::new());
        }
        if count == 0 { return Err(Error::Malformed); }

        let mut chunks: Vec<(u32, u64)> = Vec::new();
        chunks.try_reserve(count as usize).map_err(|_| Error::NoMemory)?;
        let mut last: Option<u32> = None;
        for _ in 0..count {
            let startbit = r.u32()?;
            if startbit & (MAP_UNIT - 1) != 0 { return Err(Error::Malformed); }
            if startbit > highbit - MAP_UNIT { return Err(Error::Malformed); }
            if let Some(prev) = last { if startbit <= prev { return Err(Error::Malformed); } }
            let map = r.u64()?;
            if map == 0 { return Err(Error::Malformed); }
            chunks.push((startbit, map));
            last = Some(startbit);
        }

        // The final chunk must sit in the last node the declared high bit
        // covers; a gap there means the writer and reader disagree about the
        // bitmap's extent.
        let last_start = chunks[chunks.len() - 1].0;
        let last_node = last_start - (last_start % NODE_BITS);
        if last_node + NODE_BITS != highbit { return Err(Error::Malformed); }

        Ok(Self { highbit, chunks })
    }
}

/// Round a bit count up to a whole number of nodes. # C: O(1)
///
/// `None` when the rounded value would not fit: the caller must refuse such an
/// image rather than wrap, because a wrapped extent turns a hostile length
/// into a small one and lets every subsequent bounds check pass.
fn round_up_nodes(bits: u32) -> Option<u32> {
    if bits == 0 { return Some(0); }
    bits.div_ceil(NODE_BITS).checked_mul(NODE_BITS)
}

#[cfg(test)]
#[path = "tests/ebitmap.rs"]
mod tests;
