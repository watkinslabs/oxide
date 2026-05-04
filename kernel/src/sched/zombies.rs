// Zombie task registry per `13§5` lifecycle. After a task calls
// `sys_exit`, the kernel marks it Zombie and pushes a strong-ref
// `Arc<Task>` here so its parent can `wait4` it later.
//
// Without this registry, the runqueue's swap_current drops the
// only Arc to a Zombie task as soon as `schedule()` picks the
// next runnable, freeing it before the parent has a chance to
// reap. wait4 needs the exit_status + tid which both live in the
// Task.
//
// v1 single-CPU UP. SMP would partition this per-CPU + add lock
// hierarchy; out of scope for v1.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use sched::Task;
use sync::{Spinlock, TaskList as TaskListClass};

/// Registry of Zombie tasks awaiting `wait4`. Pushed to by
/// `kernel_sys_exit`; popped by `kernel_sys_wait4`. v1 single-CPU
/// — single global Vec under a spinlock at lock class `TaskList`
/// (`06§3.6`); the registry is the moral equivalent of Linux's
/// global task list for v1's reaping path.
static ZOMBIES: Spinlock<Vec<Arc<Task>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Move `task` to the Zombie registry. Caller (sys_exit handler)
/// has already set the task's state to Zombie via
/// `sched::mark_done` and wants the Arc kept alive until the
/// parent reaps it.
/// # SAFETY: caller is the sys_exit handler running on the task's
/// own kernel stack, preempt-off, single-CPU UP.
/// # C: O(1) push
pub fn park_zombie(task: Arc<Task>) {
    ZOMBIES.lock().push(task);
}

/// Reap one Zombie child whose `parent_tid == parent`. Returns
/// `Some((tid, exit_code))` and drops the strong-ref so the Task
/// is freed. `None` if no matching Zombie is queued.
///
/// Filter shape mirrors `wait4` per docs/15§5: `pid == -1`
/// matches any child; `pid > 0` matches that specific TID; other
/// values not yet supported.
/// # C: O(N_zombies)
pub fn reap_one(parent: u32, pid: i32) -> Option<(u32, i32)> {
    use core::sync::atomic::Ordering;
    let mut q = ZOMBIES.lock();
    let pos = q.iter().position(|t| {
        if t.parent_tid.load(Ordering::Acquire) != parent { return false; }
        match pid {
            -1            => true,
            p if p > 0    => t.tid == p as u32,
            _             => false,
        }
    })?;
    let t = q.remove(pos);
    let tid = t.tid;
    let code = t.exit_status.load(Ordering::Acquire);
    drop(t);  // strong-ref released; Task freed if no other holders
    Some((tid, code))
}
