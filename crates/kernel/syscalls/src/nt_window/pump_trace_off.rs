//! The pump profile's shape when it is not compiled in: every entry point is
//! present and does nothing, so no call site carries a `#[cfg]`.
#![cfg(not(feature = "debug-winpump"))]

/// # C: O(1)
pub(crate) fn note_retrieval() {}
/// # C: O(1)
pub(crate) fn start() -> Option<u64> { None }
/// # C: O(1)
pub(crate) fn charge(_start: Option<u64>, _nr: u64) {}
