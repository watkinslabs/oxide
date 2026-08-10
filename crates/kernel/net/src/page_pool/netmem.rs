// One provider-owned receive buffer, and the array a provider hands out from.
//
// A buffer is identified by (area, index) rather than by a page pointer: the
// memory behind it belongs to the provider, which may be pages pinned out of a
// userspace mapping. Nothing here owns that memory — the provider does — so a
// descriptor is safe to hold, copy and hand to a device queue.
//
// The reference count is the page pool's `pp_ref_count`: it counts the
// outstanding users of the buffer that will release it through the pool. It
// reaches zero exactly once per allocation, and that transition is what hands
// the buffer back to its provider.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// One receive buffer descriptor.
pub struct NetIov {
    /// Outstanding pool references. Zero means the provider owns it.
    pp_ref: AtomicU32,
    /// Whether a pool currently owns this buffer. A buffer whose pool binding
    /// was torn down under it must not be counted back into that pool.
    bound: AtomicU32,
}

impl NetIov {
    /// # C: O(1)
    pub fn new() -> Self { Self { pp_ref: AtomicU32::new(0), bound: AtomicU32::new(0) } }

    /// Current reference count. # C: O(1)
    pub fn refs(&self) -> u32 { self.pp_ref.load(Ordering::Acquire) }

    /// Set the reference count outright — the "this buffer is now one
    /// fragment" seed a fresh allocation gets. # C: O(1)
    pub fn fragment(&self, n: u32) { self.pp_ref.store(n, Ordering::Release); }

    /// Take one more reference. # C: O(1)
    pub fn get(&self) { self.pp_ref.fetch_add(1, Ordering::AcqRel); }

    /// Drop one reference; true when it was the last one. A count already at
    /// zero stays at zero and reports false, so a double release cannot wrap
    /// the counter and hand one buffer to two owners. # C: O(1)
    pub fn unref_and_test(&self) -> bool {
        let mut old = self.pp_ref.load(Ordering::Acquire);
        loop {
            if old == 0 { return false; }
            match self.pp_ref.compare_exchange_weak(old, old - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return old == 1,
                Err(v) => old = v,
            }
        }
    }

    /// Whether a pool owns this buffer. # C: O(1)
    pub fn is_bound(&self) -> bool { self.bound.load(Ordering::Acquire) != 0 }
    /// Record that a pool owns this buffer. # C: O(1)
    pub fn set_bound(&self) { self.bound.store(1, Ordering::Release); }
    /// Record that no pool owns it. # C: O(1)
    pub fn clear_bound(&self) { self.bound.store(0, Ordering::Release); }
}

impl Default for NetIov {
    fn default() -> Self { Self::new() }
}

/// A provider's contiguous run of buffer descriptors.
pub struct NetIovArea {
    pub niovs: Vec<NetIov>,
}

impl NetIovArea {
    /// # C: O(n)
    pub fn new(n: usize) -> Self {
        let mut niovs = Vec::new();
        niovs.reserve_exact(n);
        for _ in 0..n { niovs.push(NetIov::new()); }
        Self { niovs }
    }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.niovs.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.niovs.is_empty() }
}

/// A reference to one buffer: which area, and which slot in it.
#[derive(Clone)]
pub struct Netmem {
    pub area: Arc<NetIovArea>,
    pub idx: u32,
}

impl Netmem {
    /// The descriptor this reference names. # C: O(1)
    pub fn niov(&self) -> &NetIov { &self.area.niovs[self.idx as usize] }
}

#[cfg(test)]
#[path = "netmem/tests.rs"]
mod tests;
