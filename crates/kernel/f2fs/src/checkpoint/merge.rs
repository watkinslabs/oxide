//! Whether a checkpoint is handed to the merge thread or written here.
//!
//! Pure, and separate from the queue it decides about, because the costly
//! mistake is in the EXEMPTIONS rather than in the merging: a caller wrongly
//! handed over waits on a thread that will never serve it.

/// Everything the decision reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Request {
    /// The mount asked for checkpoints to be merged.
    pub merge: bool,
    /// A thread is running and will look at the queue.
    pub thread_running: bool,
    /// The caller is taking the filesystem down.
    ///
    /// It cannot wait on the thread: it is the task that stops the thread, so a
    /// checkpoint it handed over would be waited for by the only task that could
    /// have served it.
    pub umounting: bool,
    /// The caller is blocked on this checkpoint.
    ///
    /// A checkpoint nobody is waiting for is not merged: merging exists to make
    /// N waiters cost one write, and a caller that is not waiting has no cost to
    /// save. The reference reaches the same answer through the checkpoint's
    /// reason, of which exactly one — the synchronous one — is merged.
    pub waiting: bool,
}

/// Whether this checkpoint is handed to the merge thread. # C: O(1)
pub fn takes_the_thread(r: &Request) -> bool {
    r.merge && r.thread_running && r.waiting && !r.umounting
}

#[cfg(test)]
#[path = "../tests/checkpoint/merge.rs"]
mod tests;
