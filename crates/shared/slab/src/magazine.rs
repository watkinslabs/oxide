// Per-CPU magazine layer per `12§3.2`. Each CPU holds a small array of
// up-to-`MAG_SIZE` outstanding objects. Alloc fast path = pop from the
// local magazine (no lock); free fast path = push to the local magazine
// (no lock). When the magazine empties on alloc OR fills on free, the
// caller falls through to the global cache under `SlabClass` spinlock.
//
// The slow-path bridge is intentionally simple in this revision: a
// single object is moved across (not a half-magazine batch). Batched
// refill / flush is a perf-tuning iteration that lands when the
// `04§1` budgets are profiled.

use core::ptr::NonNull;

/// Magazine capacity per `12§3.2`.
pub(crate) const MAG_SIZE: usize = 32;

pub(crate) struct Magazine<T> {
    // `*mut T` instead of `Option<NonNull<T>>` keeps the slot a single
    // raw pointer (sentinel `null` for empty) — simplifies Send/Sync
    // and avoids `Option`'s niche eating zero pointers.
    objs: [*mut T; MAG_SIZE],
    len: u8,
}

// SAFETY: Magazine owns raw pointers to objects whose `T: Send` carries
// the cross-thread guarantee; only the per-CPU slot's owner mutates the
// magazine, so concurrent access is excluded by the PerCpu contract.
unsafe impl<T: Send> Send for Magazine<T> {}
// SAFETY: see Send.
unsafe impl<T: Send> Sync for Magazine<T> {}

impl<T> Default for Magazine<T> {
    fn default() -> Self { Self::new() }
}

impl<T> Magazine<T> {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self { objs: [core::ptr::null_mut(); MAG_SIZE], len: 0 }
    }

    /// # C: O(1)
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> u8 { self.len }

    /// # C: O(1)
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool { self.len == 0 }

    /// # C: O(1)
    pub(crate) fn is_full(&self) -> bool { (self.len as usize) >= MAG_SIZE }

    /// Push `p` onto the magazine. Returns `Err(p)` if full.
    /// # C: O(1)
    pub(crate) fn push(&mut self, p: NonNull<T>) -> Result<(), NonNull<T>> {
        if self.is_full() { return Err(p); }
        self.objs[self.len as usize] = p.as_ptr();
        self.len += 1;
        Ok(())
    }

    /// Pop from the magazine. Returns `None` if empty.
    /// # C: O(1)
    pub(crate) fn pop(&mut self) -> Option<NonNull<T>> {
        if self.len == 0 { return None; }
        self.len -= 1;
        let p = self.objs[self.len as usize];
        self.objs[self.len as usize] = core::ptr::null_mut();
        // SAFETY: pushes only accept NonNull<T>; therefore p is non-null.
        Some(unsafe { NonNull::new_unchecked(p) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy(v: usize) -> NonNull<u32> {
        // SAFETY: we never deref the returned pointer in these tests;
        // the magazine just stores it as opaque payload. Using a
        // non-null sentinel keeps NonNull's invariant.
        unsafe { NonNull::new_unchecked(v as *mut u32) }
    }

    #[test]
    fn new_is_empty() {
        let m: Magazine<u32> = Magazine::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert!(!m.is_full());
    }

    #[test]
    fn push_pop_lifo() {
        let mut m: Magazine<u32> = Magazine::new();
        for i in 1..=4 {
            m.push(dummy(i * 0x100)).unwrap();
        }
        assert_eq!(m.len(), 4);
        // LIFO: last-pushed first-popped.
        for i in (1..=4).rev() {
            assert_eq!(m.pop().unwrap().as_ptr() as usize, i * 0x100);
        }
        assert!(m.is_empty());
    }

    #[test]
    fn fills_to_capacity_then_rejects() {
        let mut m: Magazine<u32> = Magazine::new();
        for i in 0..MAG_SIZE {
            m.push(dummy(0x1000 + i)).unwrap();
        }
        assert!(m.is_full());
        let extra = dummy(0xDEAD);
        assert!(m.push(extra).is_err());
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut m: Magazine<u32> = Magazine::new();
        assert!(m.pop().is_none());
        m.push(dummy(0x10)).unwrap();
        assert!(m.pop().is_some());
        assert!(m.pop().is_none());
    }

    #[test]
    fn push_after_pop_reuses_slot() {
        let mut m: Magazine<u32> = Magazine::new();
        m.push(dummy(0x10)).unwrap();
        m.push(dummy(0x20)).unwrap();
        let _ = m.pop();
        m.push(dummy(0x30)).unwrap();
        // Slot 1 now holds 0x30; pop order: 0x30 then 0x10.
        assert_eq!(m.pop().unwrap().as_ptr() as usize, 0x30);
        assert_eq!(m.pop().unwrap().as_ptr() as usize, 0x10);
    }
}
