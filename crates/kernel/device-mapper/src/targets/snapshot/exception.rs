//! The exception map: which origin chunks have been copied aside, and where.
//!
//! Consecutive exceptions are folded into one record — a run of chunks copied
//! to consecutive destinations is stored once with a length. The length lives
//! in the top bits of the destination chunk number, so a lookup that forgets
//! to mask them reads a destination millions of chunks away.

extern crate alloc;
use alloc::vec::Vec;

/// Bits of the destination word that hold the run length rather than a chunk
/// number.
pub const DM_CHUNK_CONSECUTIVE_BITS: u32 = 8;
/// Bits of the destination word that hold the chunk number.
pub const DM_CHUNK_NUMBER_BITS: u32 = 56;
/// Mask selecting the chunk number out of a packed destination word.
pub const DM_CHUNK_NUMBER_MASK: u64 = (1u64 << DM_CHUNK_NUMBER_BITS) - 1;
/// Longest run one record can fold.
pub const MAX_CONSECUTIVE: u64 = (1u64 << DM_CHUNK_CONSECUTIVE_BITS) - 1;

/// One record: a run of origin chunks starting at `old_chunk`, copied to a run
/// starting at the destination packed into `new_chunk`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Exception {
    /// First origin chunk the record covers.
    pub old_chunk: u64,
    /// Destination chunk, with the run length in its top bits.
    pub new_chunk: u64,
}

impl Exception {
    /// A record covering exactly one chunk. # C: O(1)
    pub const fn single(old_chunk: u64, new_chunk: u64) -> Self { Self { old_chunk, new_chunk } }

    /// Destination chunk with the run length masked off. # C: O(1)
    pub const fn dest(&self) -> u64 { self.new_chunk & DM_CHUNK_NUMBER_MASK }

    /// Chunks after the first that this record also covers. # C: O(1)
    pub const fn consecutive(&self) -> u64 { self.new_chunk >> DM_CHUNK_NUMBER_BITS }

    /// Origin chunks the record covers in total. # C: O(1)
    pub const fn len(&self) -> u64 { self.consecutive() + 1 }

    /// A record always covers at least one chunk. # C: O(1)
    pub const fn is_empty(&self) -> bool { false }

    /// Extend the run by one chunk, if there is room in the length field.
    /// # C: O(1)
    pub fn extend(&mut self) -> bool {
        if self.consecutive() >= MAX_CONSECUTIVE { return false; }
        self.new_chunk += 1u64 << DM_CHUNK_NUMBER_BITS;
        true
    }

    /// Shrink the run by one chunk from the tail. # C: O(1)
    pub fn shrink(&mut self) -> bool {
        if self.consecutive() == 0 { return false; }
        self.new_chunk -= 1u64 << DM_CHUNK_NUMBER_BITS;
        true
    }

    /// Whether the record covers `chunk`. # C: O(1)
    pub const fn covers(&self, chunk: u64) -> bool {
        chunk >= self.old_chunk && chunk < self.old_chunk + self.len()
    }

    /// Destination of `chunk`, if the record covers it. # C: O(1)
    pub fn lookup(&self, chunk: u64) -> Option<u64> {
        if self.covers(chunk) { Some(self.dest() + (chunk - self.old_chunk)) } else { None }
    }
}

/// Every completed exception, kept sorted by origin chunk so a lookup is a
/// binary search and a fold onto the previous record is the neighbour test.
#[derive(Clone, Default)]
pub struct ExceptionMap {
    records: Vec<Exception>,
}

impl ExceptionMap {
    /// An empty map. # C: O(1)
    pub fn new() -> Self { Self { records: Vec::new() } }

    /// Records held, after folding. # C: O(1)
    pub fn len(&self) -> usize { self.records.len() }
    /// Whether nothing has been copied aside yet. # C: O(1)
    pub fn is_empty(&self) -> bool { self.records.is_empty() }
    /// The records, in origin order. # C: O(1)
    pub fn records(&self) -> &[Exception] { &self.records }

    /// Destination of `chunk`, or `None` if it has not been copied aside.
    /// # C: O(log N)
    pub fn lookup(&self, chunk: u64) -> Option<u64> {
        let i = match self.records.binary_search_by_key(&chunk, |e| e.old_chunk) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        self.records[i].lookup(chunk)
    }

    /// Record that `chunk` was copied to `dest`. Folds onto the previous
    /// record when both runs continue — which is the common case, because a
    /// sequential write to the origin allocates sequential destinations.
    /// # C: O(N) worst case for the insert
    pub fn insert(&mut self, chunk: u64, dest: u64) {
        if let Some(last) = self.records.last_mut() {
            if last.old_chunk + last.len() == chunk && last.dest() + last.len() == dest
                && last.extend() { return; }
        }
        let e = Exception::single(chunk, dest);
        match self.records.binary_search_by_key(&chunk, |r| r.old_chunk) {
            Ok(i) => self.records[i] = e,
            Err(i) => self.records.insert(i, e),
        }
    }

    /// Drop the last chunk of the highest record — how a merge retires an
    /// exception once its data is back on the origin. # C: O(1)
    pub fn remove_last_chunk(&mut self) -> Option<u64> {
        let last = self.records.last_mut()?;
        let chunk = last.old_chunk + last.len() - 1;
        if !last.shrink() { self.records.pop(); }
        Some(chunk)
    }

    /// Retire one exception after merge copied it back to the origin. The
    /// records are rebuilt through the same folding path as load, so a
    /// retirement in the middle of a run cannot leave an overlapping record.
    /// # C: O(N_records * MAX_CONSECUTIVE)
    pub fn remove(&mut self, chunk: u64) -> bool {
        let mut remaining = Vec::new();
        let mut found = false;
        for record in &self.records {
            for i in 0..record.len() {
                let old = record.old_chunk + i;
                if old == chunk { found = true; } else { remaining.push(Exception::single(old, record.dest() + i)); }
            }
        }
        if found {
            self.records.clear();
            self.load(&remaining);
        }
        found
    }

    /// Load a set of records read back from a store, in file order.
    /// # C: O(N log N)
    pub fn load(&mut self, records: &[Exception]) {
        for r in records {
            for i in 0..r.len() { self.insert(r.old_chunk + i, r.dest() + i); }
        }
    }
}
