// Transaction-identifier allocation.
//
// The xid is the ONLY thing matching a reply to its call. Two outstanding calls
// sharing one xid does not fail loudly: the server answers both, the first
// reply is decoded into the second caller's results, and two unrelated
// operations silently exchange answers — a read returning another file's bytes.
//
// So the counter starts at a random point and increments monotonically, and the
// pending table (not this counter) is the authority on which xids are live.
// Starting at zero on every mount would make a reply from a previous connection
// to the same server land on a new call with the same low xid.

use core::sync::atomic::{AtomicU32, Ordering};

/// A monotonically incrementing xid source.
pub struct XidGen {
    next: AtomicU32,
}

impl XidGen {
    /// Seed the counter. `seed` should come from the kernel's random source;
    /// the value is not secret, but a predictable one makes a cross-connection
    /// collision likelier. # C: O(1)
    pub const fn new(seed: u32) -> Self { Self { next: AtomicU32::new(seed) } }

    /// The next xid. Wrapping is expected and harmless — the pending table
    /// refuses a duplicate while one is live. # C: O(1)
    pub fn alloc(&self) -> u32 { self.next.fetch_add(1, Ordering::Relaxed) }

    /// The value the next allocation will return, without consuming it.
    /// # C: O(1)
    pub fn peek(&self) -> u32 { self.next.load(Ordering::Relaxed) }
}
