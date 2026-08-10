// The count that says how many rings are still USING one zero-copy receive
// instance, as distinct from how many references keep the object alive.
//
// An instance can be exported and adopted by a second ring, so two counts are
// needed and they are not the same count:
//
//   * the OBJECT count keeps the instance allocated. It is the owning handle
//     count, and it reaches zero only once nothing can reach the instance at
//     all — including a descriptor the exporter handed out but nobody adopted.
//   * the USER count says a ring still expects to receive through it. Its
//     transition to zero is what closes the device queue and reclaims the
//     buffers the caller was holding.
//
// Collapsing them would tear the device binding down while a descriptor to the
// instance was still open, or leave a queue bound to an instance no ring can
// reach. The transitions live here, ungated, because they are the whole
// correctness argument for exporting an instance and a `#[cfg(test)]` block in
// a kernel-gated file compiles out silently (CLAUDE.md phantom-test rule).

use core::sync::atomic::{AtomicU32, Ordering};

/// Users of one instance.
pub struct UserHold {
    n: AtomicU32,
}

impl UserHold {
    /// A freshly registered instance has exactly one user: the ring that
    /// registered it. # C: O(1)
    pub fn new() -> Self { Self { n: AtomicU32::new(1) } }

    /// # C: O(1)
    pub fn count(&self) -> u32 { self.n.load(Ordering::Acquire) }

    /// Record one more ring using the instance. False when the count had
    /// already reached zero — an instance whose queue is closed and whose
    /// buffers were reclaimed must not be adopted, because the adopter would
    /// be handed a queue that will never deliver again. # C: O(1)
    pub fn get(&self) -> bool {
        let mut old = self.n.load(Ordering::Acquire);
        loop {
            if old == 0 { return false; }
            match self.n.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(v) => old = v,
            }
        }
    }

    /// Drop one user. True exactly once, on the transition to zero — the one
    /// call that may close the device queue and reclaim buffers. A count
    /// already at zero stays at zero and reports false, so a doubled release
    /// cannot close a queue twice. # C: O(1)
    pub fn put(&self) -> bool {
        let mut old = self.n.load(Ordering::Acquire);
        loop {
            if old == 0 { return false; }
            match self.n.compare_exchange_weak(old, old - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return old == 1,
                Err(v) => old = v,
            }
        }
    }
}

impl Default for UserHold {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
#[path = "hold/tests.rs"]
mod tests;
