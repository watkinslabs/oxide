//! The published watermark aggregate, and the only code that touches it.
//!
//! The words live here and nowhere else. Writing them needs a `PublishGuard`,
//! which is the sole way to obtain the right to publish, so serialisation is a
//! property of the type rather than a convention a future writer can forget.
//! Hosted builds make the guard a process-wide mutex, which is what keeps a
//! fixture driving `Pmm::refresh_watermarks` from landing inside another
//! test's write-then-read window; the kernel has one producer and pays
//! nothing for it.

use super::ZoneWatermarks;
use core::sync::atomic::{AtomicU64, Ordering};

static MANAGED_PAGES: AtomicU64 = AtomicU64::new(0);
static MIN_PAGES: AtomicU64 = AtomicU64::new(0);
static LOW_PAGES: AtomicU64 = AtomicU64::new(0);
static HIGH_PAGES: AtomicU64 = AtomicU64::new(0);
static PROMO_PAGES: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static PUBLISH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
std::thread_local! {
    /// Recursion depth of the publish right on this thread. A holder that
    /// drives a producer which publishes again must not deadlock against
    /// itself, and the outer holder's window still excludes every other
    /// thread, which is the property the right exists to provide.
    static DEPTH: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// The right to write the published aggregate. Held across a reader's own
/// writes and reads, it also excludes any other publisher for that window.
pub struct PublishGuard {
    #[cfg(test)]
    _lock: Option<std::sync::MutexGuard<'static, ()>>,
}

impl PublishGuard {
    /// Take the publish right, waiting for any other holder. Re-entrant on
    /// the holding thread. # C: O(1)
    pub fn acquire() -> Self {
        #[cfg(test)]
        {
            let outermost = DEPTH.with(|d| { let n = d.get(); d.set(n + 1); n == 0 });
            let lock = if outermost { Some(PUBLISH_LOCK.lock().unwrap_or_else(|e| e.into_inner())) } else { None };
            Self { _lock: lock }
        }
        #[cfg(not(test))]
        { Self {} }
    }
}

#[cfg(test)]
impl Drop for PublishGuard {
    fn drop(&mut self) { DEPTH.with(|d| d.set(d.get() - 1)); }
}

/// Replace the published aggregate. # C: O(1)
pub fn publish(_right: &PublishGuard, managed_pages: u64, agg: ZoneWatermarks) {
    MANAGED_PAGES.store(managed_pages, Ordering::Release);
    MIN_PAGES.store(agg.min, Ordering::Release);
    LOW_PAGES.store(agg.low, Ordering::Release);
    HIGH_PAGES.store(agg.high, Ordering::Release);
    PROMO_PAGES.store(agg.promo, Ordering::Release);
}

/// Managed total and thresholds as last published, or `None` before any
/// producer has run. # C: O(1)
pub fn load() -> Option<(u64, ZoneWatermarks)> {
    let managed_pages = MANAGED_PAGES.load(Ordering::Acquire);
    if managed_pages == 0 { return None; }
    Some((managed_pages, ZoneWatermarks {
        min: MIN_PAGES.load(Ordering::Acquire),
        low: LOW_PAGES.load(Ordering::Acquire),
        high: HIGH_PAGES.load(Ordering::Acquire),
        promo: PROMO_PAGES.load(Ordering::Acquire),
    }))
}
