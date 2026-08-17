//! The flusher, where there is no scheduler to park against.
//!
//! Not a stub of the policy: every decision the daemon makes lives in
//! `writeback::flush_pass` and `global::dirty_action`, which are ungated and
//! driven directly by tests. What is absent here is only the loop.

/// # C: O(1)
pub fn wake_flusher() {}

/// # C: O(1)
pub fn spawn_daemons() -> Result<(), ()> { Ok(()) }
