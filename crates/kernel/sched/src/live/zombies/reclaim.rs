// Deferred release of a task's final reference (Linux `put_task_struct_rcu_user`
// -> `delayed_put_task_struct`).
//
// The last `Arc<Task>` reference must not be dropped on the context-switch
// tail. Dropping it runs the whole teardown cascade — file table, open files,
// mounts, superblocks with their writeback pass, namespaces, and the tree
// rebalancing under each — and `finish_task_switch` runs on whichever task the
// scheduler switched TO, so that cascade is charged to the stack of every path
// in the kernel that can block. Measured on aarch64 it was 1.7 KiB of a 13 KiB
// ceiling, on top of a further 1 KiB of exit notification, which is why paths
// nowhere near task exit were failing the stack-depth gate.
//
// The reference is therefore handed to this queue, which a process-context
// drainer empties. The switch tail keeps only the O(1) push. This is the same
// trade the reference makes: the final put runs later, from a context with its
// own stack, and the scheduler tail stays cheap.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::Task;
use sync::{Spinlock, TaskList as TaskListClass};

/// Released tasks awaiting their final drop.
///
/// A `Vec` and not a fixed array on purpose: an overflow policy that dropped
/// the task inline would put the teardown cascade straight back on the switch
/// tail — the static call path the queue exists to remove — and it is the
/// static path, not how often it is taken, that the stack budget is spent on.
/// Growing costs an allocation, whose own depth is a fraction of the teardown's.
static RELEASED: Spinlock<Vec<Arc<Task>>, TaskListClass> = Spinlock::new(Vec::new());

/// Hand `task`'s reference to the drainer instead of dropping it here.
///
/// Callable from the context-switch tail: it takes one leaf lock and pushes.
/// The drop — and anything the drop wakes, writes back, or unmounts — happens
/// in [`drain_released`].
/// # C: O(1) amortized
/// # Lk: RELEASED (leaf)
/// # Ctx: any, including the switch tail
pub fn defer_release(task: Arc<Task>) {
    RELEASED.lock().push(task);
}

/// Drop every deferred reference. Process context only: a task's teardown
/// takes sleeping-style locks (inode cache, writeback) exactly as the RCU
/// callback drain next to it does.
///
/// The queue is taken wholesale and released before any drop runs, so a
/// teardown that itself retires a task re-enters the push side rather than the
/// lock it is holding.
/// # C: O(deferred tasks)
/// # Lk: RELEASED (leaf), released before any Drop runs
/// # Ctx: process
/// # Sleeps: yes — a dropped task's file/mount teardown can block
pub fn drain_released() {
    loop {
        let batch = core::mem::take(&mut *RELEASED.lock());
        if batch.is_empty() { return; }
        drop(batch);
    }
}

/// Deferred references not yet dropped. Diagnostics and tests.
/// # C: O(1)
pub fn pending() -> usize { RELEASED.lock().len() }

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue is a process-wide static; serialize so parallel `cargo test`
    /// threads cannot see each other's deferred references.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn task(tid: u32) -> Arc<Task> {
        use crate::task::SchedClass;
        Arc::new(Task::new(tid, "reclaim", SchedClass::Normal { weight: 1024 }))
    }

    /// The property the switch tail depends on: handing a reference over must
    /// not run its `Drop`. If it did, the teardown cascade would still be on
    /// the caller's stack and the queue would buy nothing.
    #[test]
    fn deferring_does_not_drop() {
        let _g = test_lock();
        drain_released();
        let t = task(9101);
        let weak = Arc::downgrade(&t);
        assert_eq!(Arc::strong_count(&t), 1, "test holds the only reference");
        defer_release(t);
        assert!(weak.upgrade().is_some(), "the task must still be alive after the hand-off");
        assert_eq!(pending(), 1);
        drain_released();
        assert!(weak.upgrade().is_none(), "the drain performs the final drop");
        assert_eq!(pending(), 0);
    }

    /// A reference that is not the last one must not be treated specially: the
    /// queue holds it until the drain, and the task survives if someone else
    /// still holds it.
    #[test]
    fn a_surviving_task_is_not_freed_by_the_drain() {
        let _g = test_lock();
        drain_released();
        let t = task(9102);
        let keep = Arc::clone(&t);
        defer_release(t);
        drain_released();
        assert_eq!(Arc::strong_count(&keep), 1, "the drain released only the queued reference");
    }

    /// The drain must survive a teardown that queues another task, which is
    /// what a process group's last exit does.
    #[test]
    fn draining_is_reentrant_on_the_push_side() {
        let _g = test_lock();
        drain_released();
        for tid in 9110..9120 { defer_release(task(tid)); }
        assert_eq!(pending(), 10);
        defer_release(task(9120));
        drain_released();
        assert_eq!(pending(), 0, "the drain empties what was queued while it ran");
    }
}
