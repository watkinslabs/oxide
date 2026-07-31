// Task-side access to the I/O priority context. The context object and every
// rule about it live in `crate::ioprio`; this file is only the guarded
// pointer on `Task` plus the effective-priority derivation, which needs the
// task's scheduling policy and nice value.

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::ioprio::IoContext;
use crate::Task;

impl Task {
    /// The task's I/O priority context. Cloned out rather than borrowed so no
    /// caller holds the guard across a block-layer submission.
    /// # C: O(1); # Lk: Task
    pub fn io_context(&self) -> Arc<IoContext> { Arc::clone(&self.io_context.lock()) }

    /// The raw stored priority — what `ioprio_get(IOPRIO_WHO_PROCESS)` reports
    /// verbatim so userspace can distinguish "never set".
    /// # C: O(1); # Lk: Task
    pub fn raw_ioprio(&self) -> i32 { self.io_context.lock().ioprio() }

    /// Store a raw priority into the task's context. A context shared through
    /// `CLONE_IO` makes the write visible to every task sharing it.
    /// # C: O(1); # Lk: Task
    pub fn set_ioprio(&self, v: i32) { self.io_context.lock().set_ioprio(v); }

    /// Install a context, replacing whatever the fork path copied. The clone
    /// path calls this to make a `CLONE_IO` child share its parent's.
    /// # C: O(1); # Lk: Task
    pub fn set_io_context(&self, ioc: Arc<IoContext>) { *self.io_context.lock() = ioc; }

    /// Effective I/O priority: the stored value when it names a class, else
    /// one derived from the task's scheduling policy and nice value. This is
    /// what the block layer stamps on a request the task submits, and what
    /// `ioprio_get` reports for the group and user target sets.
    /// # C: O(1); # Lk: Task
    pub fn effective_ioprio(&self) -> i32 {
        let policy = self.policy.load(Ordering::Acquire);
        crate::ioprio::effective(
            self.raw_ioprio(),
            self.nice.load(Ordering::Acquire) as i32,
            policy == crate::sched_enc::SCHED_IDLE,
            self.is_rt_or_dl_policy(),
        )
    }
}

/// Effective I/O priority of the running task, or the unset default off a
/// task (kernel bring-up, hosted fixtures). The block layer stamps this onto
/// any request submitted without a priority of its own — the point at which
/// an `ioprio_set(2)` value actually reaches the queue.
/// # C: O(1); # Lk: Task
#[cfg(target_os = "oxide-kernel")]
pub fn current_ioprio() -> i32 {
    match crate::live::current() { Some(t) => t.effective_ioprio(), None => crate::ioprio::DEFAULT }
}

/// Hosted builds have no running task; every submission is unset.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_ioprio() -> i32 { crate::ioprio::DEFAULT }
