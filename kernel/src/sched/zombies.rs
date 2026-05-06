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
use core::sync::atomic::Ordering;

use sched::{Task, TaskState};
use sync::{Spinlock, TaskList as TaskListClass};

/// Registry of Zombie tasks awaiting `wait4`. Pushed to by
/// `kernel_sys_exit`; popped by `kernel_sys_wait4`. v1 single-CPU
/// — single global Vec under a spinlock at lock class `TaskList`
/// (`06§3.6`); the registry is the moral equivalent of Linux's
/// global task list for v1's reaping path.
static ZOMBIES: Spinlock<Vec<Arc<Task>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Parents currently parked in `wait4` waiting for any of their
/// children to enter the Zombie state. Each entry is the parent's
/// own Arc<Task> with state==Sleeping. Pushed by
/// `park_for_wait4`; popped by `park_zombie` when an exiting child
/// announces SIGCHLD to its parent. v1 single-CPU; SMP would shard
/// per-CPU.
static WAITERS: Spinlock<Vec<Arc<Task>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Move `task` to the Zombie registry. Caller (sys_exit handler)
/// has already set the task's state to Zombie via
/// `sched::mark_done` and wants the Arc kept alive until the
/// parent reaps it. P3-67: also posts SIGCHLD (sig 17) into the
/// parent's sigpending bitmap — bash's job-control SIGCHLD handler
/// triggers off this.
/// # SAFETY: caller is the sys_exit handler running on the task's
/// own kernel stack, preempt-off, single-CPU UP.
/// # C: O(1) push + Weak upgrade
pub fn park_zombie(task: Arc<Task>) {
    // SAFETY: task is the running task on this CPU about to Zombie; we are sole reader of parent_arc per the single-mutator-per-active-CPU invariant; child set this slot at fork time.
    let parent = unsafe { (&*task.parent_arc.get()).as_ref().and_then(|w| w.upgrade()) };
    if let Some(p) = parent {
        // SIGCHLD = 17; bit (17 - 1) = 16 in the 64-bit pending bitmap.
        p.sigpending.fetch_or(1u64 << 16, Ordering::Release);
    }
    let parent_tid = task.parent_tid.load(Ordering::Acquire);
    ZOMBIES.lock().push(task);
    wake_wait4_parent(parent_tid);
}

/// Park the current task in WAITERS, marking it Sleeping. Caller
/// (kernel_sys_wait4) must call `schedule()` immediately after; the
/// task only resumes when `wake_wait4_parent` re-enqueues it.
/// # SAFETY: caller is the running task on this CPU; preempt-off;
/// runqueue installed.
/// # C: O(1)
/// # Lk: WAITERS (TaskList class)
pub unsafe fn park_for_wait4() {
    let rq = match crate::sched::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc the WAITERS list can hold across schedule.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    arc.set_state(TaskState::Sleeping);
    WAITERS.lock().push(arc);
}

/// Wake any parent task waiting in `wait4(-1, ...)` for `parent_tid`'s
/// children to exit. Called from `park_zombie` after the child has
/// been added to the ZOMBIES registry. The woken parent re-runs the
/// reap_one filter; if no zombie matches its specific pid filter,
/// it falls back through the wait4 retry loop and re-parks.
/// # C: O(N_waiters)
/// # Lk: WAITERS, then runqueue inner
fn wake_wait4_parent(parent_tid: u32) {
    let mut waiters = WAITERS.lock();
    if waiters.is_empty() { return; }
    let rq = match crate::sched::global() {
        Some(r) => r,
        None    => { waiters.clear(); return; }
    };
    // Walk in reverse so swap_remove preserves earlier indices.
    let mut i = waiters.len();
    let mut woken: Vec<Arc<Task>> = Vec::new();
    while i > 0 {
        i -= 1;
        if waiters[i].tid == parent_tid {
            woken.push(waiters.swap_remove(i));
        }
    }
    drop(waiters);
    if woken.is_empty() { return; }
    let mut inner = rq.inner.lock();
    for t in woken {
        t.set_state(TaskState::Runnable);
        t.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(t);
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    crate::preempt::set_need_resched();
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
