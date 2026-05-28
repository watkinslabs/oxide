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
// hierarchy; is a follow-up.


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::{Task, TaskState};
use sync::{Spinlock, TaskList as TaskListClass};

/// Registry of Zombie tasks awaiting `wait4`. Pushed to by
/// `sys_exit`; popped by `sys_wait4`. v1 single-CPU
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
/// `crate::mark_done` and wants the Arc kept alive until the
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
        // F167: typed signal bit instead of `1u64 << 16` magic.
        p.sigpending.fetch_or(super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
        accrue_child_time(&task, &p);
    }
    let parent_tid = task.parent_tid.load(Ordering::Acquire);
    ZOMBIES.lock().push(task);
    wake_wait4_parent(parent_tid);
}

/// Add the dying child's elapsed CPU to the parent's
/// `cumulative_child_ns` for `getrusage(RUSAGE_CHILDREN)`.
/// # C: O(1)
fn accrue_child_time(child: &Task, parent: &Task) {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let elapsed = now.saturating_sub(child.spawn_ns.load(Ordering::Acquire));
    parent.cumulative_child_ns.fetch_add(elapsed, Ordering::AcqRel);
}

/// Post-mortem signaling without taking ownership of the Arc. Splits
/// the SIGCHLD + wake-wait4 work out of `park_zombie` so the dying
/// task can call this from sys_exit / sigsegv without bumping the
/// rq.current strong count. The actual ZOMBIES push happens later
/// inside `schedule()` when it detects `TaskState::Zombie` on prev
/// and transfers the prev_arc returned by `swap_current` directly
/// — that avoids the leak where a zombie's prev_arc on its dead
/// kernel stack never drops because the dead task never resumes.
/// # C: O(N_waiters) wake.
pub fn signal_child_exit(task: &Task) {
    use core::sync::atomic::Ordering;
    // SAFETY: task is the running task on this CPU about to Zombie; we are sole reader of parent_arc per the single-mutator-per-active-CPU invariant; child set this slot at fork time.
    let parent = unsafe { (&*task.parent_arc.get()).as_ref().and_then(|w| w.upgrade()) };
    let parent_tid = task.parent_tid.load(Ordering::Acquire);
    #[cfg(feature = "debug-ssh")]
    {
        klog::write_raw(b"[INFO]  ssh-trace: signal_child_exit child=");
        klog::write_dec_u64(task.tid as u64);
        klog::write_raw(b" parent_tid=");
        klog::write_dec_u64(parent_tid as u64);
        klog::write_raw(b" parent_upgrade=");
        klog::write_dec_u64(if parent.is_some() { 1 } else { 0 });
        klog::write_raw(b"\n");
    }
    if let Some(p) = parent {
        // F167: typed signal bit.
        p.sigpending.fetch_or(super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
    }
    wake_wait4_parent(parent_tid);
}

/// Push `task` onto the ZOMBIES list. Used by `schedule()` when it
/// detects that prev's state is Zombie: rather than leaking the Arc
/// returned by `swap_current` on the dying task's about-to-be-orphaned
/// kernel stack, transfer ownership here so reap_one can release it.
/// # C: O(1) push.
pub fn enqueue_zombie(task: Arc<Task>) {
    ZOMBIES.lock().push(task);
}

/// Park the current task in WAITERS, marking it Sleeping. Caller
/// (sys_wait4) must call `schedule()` immediately after; the
/// task only resumes when `wake_wait4_parent` re-enqueues it.
/// # SAFETY: caller is the running task on this CPU; preempt-off;
/// runqueue installed.
/// # C: O(1)
/// # Lk: WAITERS (TaskList class)
pub unsafe fn park_for_wait4() {
    let rq = match super::runqueue::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc the WAITERS list can hold across schedule.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    arc.set_state(TaskState::Sleeping);
    WAITERS.lock().push(arc);
}

/// F143: undo `park_for_wait4` for the current task — used when
/// `sys_wait4`'s post-park reap recheck found a Zombie that was
/// added between the loop-top reap and the park (missed-wakeup
/// race). Removes self from WAITERS and restores Runnable state.
/// # SAFETY: caller is the running task on this CPU; preempt-off.
/// # C: O(N_waiters)
pub fn unpark_self_from_wait4() {
    let rq = match super::runqueue::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    let cur_tid = {
        // SAFETY: rq.current is non-null after install_global; we read tid without bumping the strong count.
        let t: &Task = unsafe { &*raw };
        t.tid
    };
    let mut waiters = WAITERS.lock();
    let mut i = waiters.len();
    while i > 0 {
        i -= 1;
        if waiters[i].tid == cur_tid {
            let arc = waiters.swap_remove(i);
            arc.set_state(TaskState::Runnable);
            return;
        }
    }
    // SAFETY: rq.current is non-null after install_global; we are sole writer to state via the single-mutator invariant for the running task on this CPU.
    let t: &Task = unsafe { &*raw };
    t.set_state(TaskState::Runnable);
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
    let rq = match super::runqueue::global() {
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
        // F211: sleeper credit. Reset vruntime to min so a long-running
        // task that blocked on wait4 doesn't lose the pick to a freshly-
        // spawned child with vruntime=0. See Task::set_vruntime_to_floor.
        t.set_vruntime_to_floor(inner.cfs.min_vruntime());
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

/// B14: drop Zombies whose parent has long since stopped caring,
/// either because they're orphaned (parent task gone) OR the parent
/// has had >`MAX_LINGER_NS` to wait4 and didn't. Linux uses init as
/// the default subreaper for the orphan case and the parent's
/// SIG_IGN/SA_NOCLDWAIT for the second case; we approximate both
/// with a timed-reap sweep so sshd's per-conn fork-exit churn
/// doesn't pile up zombies indefinitely (we observed ~340 KB per
/// orphaned task — Task struct + 16 KB kernel stack — staying
/// alive forever in ZOMBIES on TCG ARM).
///
/// Called from the periodic tick path. The 5-second linger is a
/// generous overestimate of Linux's nominal "SIGCHLD-then-wait4"
/// latency — any reasonable parent reacts in milliseconds; only
/// pathologically-blocked parents (sshd in our case) exceed it.
/// # C: O(N_zombies × N_tasks) — registry lookup is O(N_tasks).
pub fn reap_orphans() {
    use crate::registry;
    // 500 ms — Linux's nominal SIGCHLD→wait4 latency is <10 ms;
    // anything longer is a stuck parent (sshd waiting on a select
    // that's blocked elsewhere) and the zombie is functionally
    // abandoned.
    const MAX_LINGER_NS: u64 = 500_000_000;
    let now_ns = monotonic_ns();
    let mut q = ZOMBIES.lock();
    q.retain(|t| {
        let pt = t.parent_tid.load(Ordering::Acquire);
        // pid 0 is the boot anchor — never reap (no parent slot).
        if pt == 0 { return true; }
        // Orphan: parent task is gone → reap.
        if registry::lookup(pt).is_none() { return false; }
        // Linger gate: if parent has been alive for >5s and still
        // hasn't reaped, give up and reclaim. Stamps zombie_since_ns
        // on first observation so the timer starts when the task
        // becomes a zombie, not when it was created.
        let stamped = t.zombie_since_ns.load(Ordering::Acquire);
        if stamped == 0 {
            t.zombie_since_ns.store(now_ns, Ordering::Release);
            return true;
        }
        now_ns.saturating_sub(stamped) < MAX_LINGER_NS
    });
}

#[cfg(target_arch = "x86_64")]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}
#[cfg(target_arch = "aarch64")]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn monotonic_ns() -> u64 { 0 }
