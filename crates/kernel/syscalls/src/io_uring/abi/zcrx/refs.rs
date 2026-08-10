// The two counts a zero-copy receive buffer carries, and the one order they
// may be consumed in.
//
// A buffer is described by TWO independent counts, and merging them is the bug
// this module exists to make impossible:
//
//   * the POOL count says the buffer is in flight somewhere in the network
//     stack. It reaching zero is what makes the buffer allocatable again.
//   * the USER count says the caller has been told about the buffer and has
//     not handed it back.
//
// A refill entry spends a user reference FIRST, and only losing one lets the
// pool reference be touched at all. Reversed — or with one merged count — a
// caller that returned the same buffer twice would drive the pool count to
// zero while the stack still held the buffer, and the next allocation would
// hand out memory that is being written into.
//
// Ungated on purpose: this is the whole correctness argument of the mechanism,
// and a `#[cfg(test)]` block inside a kernel-gated file compiles out silently
// (CLAUDE.md phantom-test rule).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use net::page_pool::NetIovArea;

/// Per-buffer references the caller holds.
pub struct UserRefs {
    refs: Vec<AtomicU32>,
}

impl UserRefs {
    /// # C: O(n)
    pub fn new(n: usize) -> Option<Self> {
        let mut refs: Vec<AtomicU32> = Vec::new();
        if refs.try_reserve_exact(n).is_err() { return None; }
        for _ in 0..n { refs.push(AtomicU32::new(0)); }
        Some(Self { refs })
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.refs.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.refs.is_empty() }
    /// # C: O(1)
    pub fn get(&self, idx: u32) -> u32 { self.refs[idx as usize].load(Ordering::Acquire) }

    /// Record that the caller has been told about a buffer. # C: O(1)
    pub fn take(&self, idx: u32) { self.refs[idx as usize].fetch_add(1, Ordering::AcqRel); }

    /// Spend one of the caller's references. False when it holds none — a
    /// buffer it was never given, or was given once and returned twice.
    /// # C: O(1)
    pub fn put(&self, idx: u32) -> bool {
        let r = &self.refs[idx as usize];
        let mut old = r.load(Ordering::Acquire);
        loop {
            if old == 0 { return false; }
            match r.compare_exchange_weak(old, old - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(v) => old = v,
            }
        }
    }
}

/// What one refill entry did to the buffer it named.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refill {
    /// The caller does not hold this buffer; nothing was touched.
    NotHeld,
    /// A caller reference was spent, but the stack still holds the buffer.
    StillInFlight,
    /// The last reference of both kinds is gone: the buffer is free.
    Freed,
}

/// Consume one refill entry against buffer `idx` — the ordering above, in one
/// place so no caller can implement it differently. # C: O(1)
pub fn refill(nia: &NetIovArea, urefs: &UserRefs, idx: u32) -> Refill {
    if idx as usize >= urefs.len() || idx as usize >= nia.len() { return Refill::NotHeld; }
    if !urefs.put(idx) { return Refill::NotHeld; }
    if !nia.niovs[idx as usize].unref_and_test() { return Refill::StillInFlight; }
    Refill::Freed
}

#[cfg(test)]
#[path = "refs/tests.rs"]
mod tests;
