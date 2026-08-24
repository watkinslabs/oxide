//! Wake lists, where there is no scheduler to park against.
//!
//! A hosted build has no kernel threads, so nothing ever parks and a wake has
//! nobody to reach. The counters are still real: a test can assert that the
//! checkpoint path asked for a discard round, or that an urgent knob asked for
//! a cleaning pass, which is the half of the contract that does not need a
//! thread to be checkable.

use core::sync::atomic::{AtomicU32, Ordering};

/// The three wake points of one mount's background threads.
#[derive(Debug, Default)]
pub struct Waits {
    gc: AtomicU32,
    discard: AtomicU32,
    ckpt: AtomicU32,
    flush: AtomicU32,
    foreground: AtomicU32,
}

impl Waits {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// # C: O(1)
    pub fn wake_gc(&self) { self.gc.fetch_add(1, Ordering::Release); }

    /// # C: O(1)
    pub fn wake_discard(&self) { self.discard.fetch_add(1, Ordering::Release); }

    /// # C: O(1)
    pub fn wake_ckpt(&self) { self.ckpt.fetch_add(1, Ordering::Release); }
    pub fn wake_flush(&self) { self.flush.fetch_add(1, Ordering::Release); }

    /// Times the merge thread has been asked to write. # C: O(1)
    pub fn ckpt_wakes(&self) -> u32 { self.ckpt.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn wake_foreground(&self) { self.foreground.fetch_add(1, Ordering::Release); }

    /// Nothing can be waiting where nothing can park. # C: O(1)
    pub fn foreground_waiting(&self) -> bool { false }

    /// Times the cleaner has been asked to run. # C: O(1)
    pub fn gc_wakes(&self) -> u32 { self.gc.load(Ordering::Acquire) }

    /// Times the discard thread has been asked to run. # C: O(1)
    pub fn discard_wakes(&self) -> u32 { self.discard.load(Ordering::Acquire) }

    /// Times a blocked caller has been released. # C: O(1)
    pub fn foreground_wakes(&self) -> u32 { self.foreground.load(Ordering::Acquire) }
}
