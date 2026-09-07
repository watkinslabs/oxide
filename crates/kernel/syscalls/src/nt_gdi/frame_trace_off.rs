//! The flush trace's shape when it is not compiled in: every entry point is
//! present and does nothing, so no call site carries a `#[cfg]`.
#![cfg(not(feature = "debug-winframe"))]

/// # C: O(1)
pub(crate) fn now() -> u64 { 0 }
/// # C: O(1)
pub(crate) fn serialised(_start: u64, _bytes: usize) {}
/// # C: O(1)
pub(crate) fn enqueued(_start: u64, _sequence: u64) {}
/// # C: O(1)
pub(crate) fn taken(_sequence: u64) {}
/// # C: O(1)
pub(crate) fn written(_sequence: u64) {}
/// # C: O(1)
pub(crate) fn acknowledged(_sequence: u64) {}
