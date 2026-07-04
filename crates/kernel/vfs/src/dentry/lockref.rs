use core::sync::atomic::{AtomicI64, Ordering};

/// Sentinel `d_count` for a dentry whose kill is in progress (Linux
/// `LOCKREF_DEAD`, `lib/lockref.c`). A dead lockref is `< 0`, so every
/// resurrection attempt fails and `__d_lookup_rcu` skips a dentry mid-kill.
pub const LOCKREF_DEAD: i64 = -128;

/// Linux `d_count`. This is the VFS-visible pin count, not the memory-reclaim
/// trigger; Rust `Arc` owns actual object lifetime.
pub struct Lockref {
    count: AtomicI64,
}

impl Lockref {
    /// # C: O(1)
    pub(super) const fn new() -> Self { Lockref { count: AtomicI64::new(0) } }
    /// `lockref_get`. # C: O(1)
    pub fn get(&self) -> i64 { self.count.fetch_add(1, Ordering::AcqRel) + 1 }
    /// `lockref_put_return`. # C: O(1)
    pub fn put(&self) -> i64 { self.count.fetch_sub(1, Ordering::AcqRel) - 1 }
    /// # C: O(1)
    pub fn read(&self) -> i64 { self.count.load(Ordering::Acquire) }

    /// `lockref_get_not_zero`: pin only a currently-pinned ref. # C: O(1) amortized
    pub fn get_not_zero(&self) -> bool {
        let mut old = self.count.load(Ordering::Acquire);
        loop {
            if old <= 0 { return false; }
            match self.count.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_)    => return true,
                Err(cur) => old = cur,
            }
        }
    }

    /// `lockref_get_not_dead`: pin unless the ref is being killed. # C: O(1) amortized
    pub fn get_not_dead(&self) -> bool {
        let mut old = self.count.load(Ordering::Acquire);
        loop {
            if old < 0 { return false; }
            match self.count.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_)    => return true,
                Err(cur) => old = cur,
            }
        }
    }

    /// `lockref_mark_dead`: stamp the kill sentinel. # C: O(1)
    pub fn mark_dead(&self) { self.count.store(LOCKREF_DEAD, Ordering::Release); }
    /// True iff the lockref is dead (`< 0`) — kill in progress. # C: O(1)
    pub fn is_dead(&self) -> bool { self.count.load(Ordering::Acquire) < 0 }
}
