//! Starting and stopping the background threads, where there are none.
//!
//! A hosted build has no scheduler to spawn against, so a mount starts no
//! threads. It is not a stub of the policy: every pass the threads would make
//! is in `round` and ungated, and a test drives those directly. What is absent
//! here is only the loop that would call them.

use alloc::sync::Arc;

use crate::mount::F2fs;

/// # C: O(1)
pub fn start(_fs: &Arc<F2fs>) {}

/// # C: O(1)
pub fn stop(_fs: &F2fs) {}

/// No thread to hand a cleaning pass to, so the caller keeps it. # C: O(1)
pub fn delegate_gc(_fs: &Arc<F2fs>) -> bool { false }

/// No thread to hand a checkpoint to either, so the caller writes it.
///
/// Not a stub of the merge: the queue and what one write serves are in
/// `bg::ckpt` and the exemptions in `checkpoint::merge`, both ungated and both
/// driven directly by tests. What is absent here is only the thread.
/// # C: O(1)
pub fn delegate_checkpoint(_fs: &Arc<F2fs>) -> Option<vfs::KResult<()>> { None }
