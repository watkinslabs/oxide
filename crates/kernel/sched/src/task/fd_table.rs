// Task fd-table accessors: current-task-only borrow/replace plus the
// cross-task-safe pinned clone (`docs/53` hollow-shell owner: sched).

use alloc::sync::Arc;
use vfs::FdTable;

use super::Task;

impl Task {
    /// Borrow the fd table. Returns `None` for tasks without one
    /// (kthreads, idle).
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent `replace_fd_table` runs
    /// against this task on another CPU.
    /// # C: O(1)
    pub unsafe fn fd_table_ref(&self) -> Option<&Arc<FdTable>> {
        self.debug_check_canary("fd_table_ref");
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern under documented external synchronization.
        unsafe { (&*self.fd_table.get()).as_ref() }
    }

    /// Pin this task's current fd table for a cross-task observer (kcmp,
    /// pidfd_getfd, `/proc/<pid>/fd*`). The pin lock closes concurrent
    /// exit's `replace_fd_table(None)` before cloning the Arc, so the
    /// returned table stays valid after the target task resumes or exits.
    /// Mirrors `clone_mm`/`mm_pin_lock`.
    /// # C: O(1); # Lk: TaskList
    pub fn clone_fd_table(&self) -> Option<Arc<FdTable>> {
        let _pin = self.fd_table_pin_lock.lock();
        // SAFETY: fd_table_pin_lock serializes this observer with replace_fd_table below.
        unsafe { (&*self.fd_table.get()).as_ref().map(Arc::clone) }
    }

    /// Replace the fd table — used by `init` to install the
    /// boot console table, by fork to clone a parent's table,
    /// and by execve when CLOEXEC entries get cleared.
    /// # SAFETY: caller is the running task on this CPU OR holds
    /// the runqueue invariant for this task; preempt-off; UP.
    /// # C: O(1) + Arc drop
    pub unsafe fn replace_fd_table(&self, new: Option<Arc<FdTable>>) {
        self.debug_check_canary("replace_fd_table");
        let _pin = self.fd_table_pin_lock.lock();
        // SAFETY: see fn-level contract; single-mutator on this CPU; pin lock excludes clone_fd_table readers.
        unsafe { *self.fd_table.get() = new; }
    }
}
