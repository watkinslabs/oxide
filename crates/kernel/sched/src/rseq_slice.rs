//! Rseq slice-extension duration shared by the grant path and debugfs.

use core::sync::atomic::{AtomicU64, Ordering};

/// Smallest rseq slice extension accepted by the live debugfs control.
pub const EXTENSION_NS_MIN: u64 = 5_000;
/// Largest rseq slice extension accepted by the live debugfs control.
pub const EXTENSION_NS_MAX: u64 = 50_000;

static EXTENSION_NS: AtomicU64 = AtomicU64::new(EXTENSION_NS_MIN);

/// Current rseq slice-extension duration. # C: O(1)
pub fn extension_ns() -> u64 { EXTENSION_NS.load(Ordering::Relaxed) }

/// Change the duration when it is inside the UAPI range. `false` leaves the
/// current value untouched. # C: O(1)
pub fn set_extension_ns(ns: u64) -> bool {
    if !(EXTENSION_NS_MIN..=EXTENSION_NS_MAX).contains(&ns) { return false; }
    EXTENSION_NS.store(ns, Ordering::Relaxed);
    true
}

/// Deadline a new grant receives from the live extension control. # C: O(1)
pub fn grant_deadline(now_ns: u64) -> u64 { now_ns.saturating_add(extension_ns()) }
