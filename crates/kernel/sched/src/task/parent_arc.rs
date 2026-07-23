// Task parent-link accessors: spinlock-guarded `Weak<Task>`, safe for both
// a foreign writer (an exiting parent reparenting a live child from its own
// CPU) and a foreign/self reader racing that write (`docs/53` hollow-shell
// owner: sched).

use alloc::sync::{Arc, Weak};

use super::Task;

impl Task {
    /// Upgrade the parent link to a live `Arc<Task>`, or `None` if unset or
    /// the parent has since been dropped.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn parent(&self) -> Option<Arc<Task>> {
        self.parent_arc.lock().as_ref().and_then(Weak::upgrade)
    }

    /// Clone the raw `Weak<Task>` (not upgraded) — for CLONE_PARENT
    /// inheritance, which copies the caller's own parent link verbatim.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn parent_weak(&self) -> Option<Weak<Task>> {
        self.parent_arc.lock().clone()
    }

    /// Replace the parent link. Used by fork (unpublished child, safe by
    /// construction) and by an exiting parent reparenting its live/zombie
    /// children to init (`sched/src/live/zombies/reparent.rs`) — the
    /// latter is a genuine cross-task write, which is exactly why this
    /// field is lock-protected rather than a raw `UnsafeCell`.
    /// # C: O(1); # Lk: TaskList (target task, momentary)
    pub fn set_parent_weak(&self, w: Option<Weak<Task>>) {
        *self.parent_arc.lock() = w;
    }
}
