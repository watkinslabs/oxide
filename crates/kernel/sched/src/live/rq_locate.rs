// Locate the runqueue a task is ACTUALLY queued on — Linux `task_rq_lock`.
//
// A task's `Arc` may live in exactly one runqueue's class tree at a time
// (`RunqueueInner::enqueue`'s `on_rq` guard). Any operation that has to
// re-place a queued task must therefore dequeue it from ITS rq — the one
// named by `task_rq(p)` — not from the rq of whatever CPU happens to be
// running the syscall. Linux `__sched_setscheduler` opens with
// `rq = task_rq_lock(p, &rf)`, and both
// `sched_change_begin()` and `sched_change_end()` independently recompute
// `rq = task_rq(p)` and `lockdep_assert_rq_held(rq)`, so the dequeue and the
// matching enqueue provably target the same, task-owned runqueue.
//
// Getting this wrong is not a mere accounting slip. Clearing `on_rq` and
// enqueueing on the caller's rq bypasses the double-enqueue guard, leaving
// one `Arc<Task>` in TWO trees: two CPUs pick it, two CPUs run it, and its
// saved register context is corrupted. Linux has no such path anywhere —
// cross-rq movement always goes dequeue-from-source -> `set_task_cpu` ->
// enqueue-on-dest, bridged by `TASK_ON_RQ_MIGRATING`.
//
// The walk is generic over the runqueue accessor so the decision logic is
// exercised by hosted tests against real `Runqueue` / `RunqueueInner` /
// `Spinlock` instances, without depending on the `GLOBALS` array (which only
// the owning CPU may install into, and which is process-global and therefore
// unusable from parallel `cargo test` threads).

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{RunqueueInner, Task, TaskPiState};
use super::runqueue::{RqIrq, Runqueue};
use sync::{Guard, IrqGuard, Runqueue as RunqueueClass, TaskPi};

/// Linux `_task_rq_lock`: `p->pi_lock` followed by the rq named by
/// `task_cpu(p)`, with CPU and migration-state revalidation.
pub struct TaskRqGuard<'a> {
    rq: &'a Runqueue,
    // Declaration order is unlock order: rq first, then p->pi_lock.
    inner: Guard<'a, RunqueueInner, RunqueueClass>,
    _pi: IrqGuard<'a, TaskPiState, TaskPi, RqIrq>,
}

/// Stable task ownership result. `OffRq` retains TaskPi, so no wake or
/// migration can publish ownership between the proof and the caller's write.
pub enum StableTaskGuard<'a> {
    Owned(TaskRqGuard<'a>),
    OffRq(IrqGuard<'a, TaskPiState, TaskPi, RqIrq>),
}

impl TaskRqGuard<'_> {
    pub fn inner_mut(&mut self) -> &mut RunqueueInner { &mut self.inner }
    pub(crate) fn publish_nr_running(&self) { self.rq.publish_nr_running(self.inner.nr_running()); }
    /// Linux `task_current_donor`. Oxide has no proxy-execution split, so the
    /// task owning the CPU is necessarily the scheduling donor as well.
    pub(crate) fn is_current_donor(&self, task: &Task) -> bool {
        self.rq.current.load(Ordering::Acquire).cast_const() == core::ptr::from_ref(task)
    }
}

fn needs_rq(task: &Task) -> bool {
    matches!(task.state(), crate::TaskState::Runnable | crate::TaskState::Waking)
        || task.on_rq.load(Ordering::Acquire)
        || task.on_cpu.load(Ordering::Acquire)
        || task.on_wake_list.load(Ordering::Acquire)
}

fn assert_ownership_shape(task: &Task) {
    hal::kassert!(!task.on_class_rq.load(Ordering::Acquire)
        || task.on_rq.is_queued(Ordering::Acquire),
        "class-tree task lacks queued runqueue ownership");
    hal::kassert!(!task.on_wake_list.load(Ordering::Acquire)
        || matches!(task.state(), crate::TaskState::Waking),
        "wake-list task lacks waking ownership state");
}

/// Linux `__task_rq_lock`: resolve the rq while consuming an already-held
/// TaskPi guard. PI paths use this form and never recursively lock TaskPi.
///
/// Linux can wait on `MIGRATING` with `p->pi_lock` held because its queued
/// migration owner spans that state transition. Oxide normally does the same,
/// but switch-time eviction deliberately parks the outgoing task and transfers
/// completion to the incoming task after `on_cpu` clears. That tail must take
/// TaskPi. Once the parked token plus `!on_cpu` proves this transfer happened,
/// the task is temporarily off every class tree and this transaction returns
/// `OffRq` instead of waiting on the continuation it would otherwise block.
/// # C: O(contention + migration)
pub(crate) fn __task_rq_lock_with<'a, F>(get_rq: &F, task: &'a Task,
    pi: IrqGuard<'a, TaskPiState, TaskPi, RqIrq>) -> StableTaskGuard<'a>
where F: Fn(u32) -> Option<&'a Runqueue> {
    loop {
        let cpu = task.cpu.load(Ordering::Acquire) as u32;
        if task.on_rq.is_migrating(Ordering::Acquire)
            && super::schedule::migrate::owns_switched_parked(cpu, task) {
            assert_ownership_shape(task);
            return StableTaskGuard::OffRq(pi);
        }
        if !needs_rq(task) && !task.on_rq.is_migrating(Ordering::Acquire) {
            assert_ownership_shape(task);
            return StableTaskGuard::OffRq(pi);
        }
        let rq = get_rq(cpu).expect("rq-owned task names an uninstalled runqueue");
        let inner = rq.inner.lock();
        if task.cpu.load(Ordering::Acquire) as u32 == cpu
            && !task.on_rq.is_migrating(Ordering::Acquire) {
            assert_ownership_shape(task);
            if !needs_rq(task) {
                drop(inner);
                return StableTaskGuard::OffRq(pi);
            }
            return StableTaskGuard::Owned(TaskRqGuard { rq, inner, _pi: pi });
        }
        drop(inner);
        while task.on_rq.is_migrating(Ordering::Acquire) {
            // The updater may have acquired TaskPi while the outgoing task was
            // still on_cpu, then slept on the source rq until switch-tail
            // cleared on_cpu and unlocked it. Reclassify after that wait: a
            // blind Linux-style spin here would retain the very TaskPi that
            // Oxide's split switch continuation needs to finish migration.
            if super::schedule::migrate::owns_switched_parked(cpu, task) { break; }
            core::hint::spin_loop();
        }
    }
}

/// Acquire the stable task/rq pair through an injected per-CPU rq accessor.
/// # C: O(contention + migration)
pub fn task_rq_lock_with<'a, F>(get_rq: &F, task: &'a Task) -> StableTaskGuard<'a>
where F: Fn(u32) -> Option<&'a Runqueue> {
    loop {
        let pi = task.pi_lock.lock_irqsave::<RqIrq>();
        let cpu = task.cpu.load(Ordering::Acquire) as u32;
        if !needs_rq(task) && !task.on_rq.is_migrating(Ordering::Acquire) {
            assert_ownership_shape(task);
            return StableTaskGuard::OffRq(pi);
        }
        let rq = get_rq(cpu).expect("rq-owned task names an uninstalled runqueue");
        let inner = rq.inner.lock();
        if task.cpu.load(Ordering::Acquire) as u32 == cpu
            && !task.on_rq.is_migrating(Ordering::Acquire) {
            assert_ownership_shape(task);
            if !needs_rq(task) {
                drop(inner);
                return StableTaskGuard::OffRq(pi);
            }
            return StableTaskGuard::Owned(TaskRqGuard { rq, inner, _pi: pi });
        }
        drop(inner);
        drop(pi);
        while task.on_rq.is_migrating(Ordering::Acquire) { core::hint::spin_loop(); }
    }
}

/// RAII half of Linux `sched_change_begin/end`: the rq lock excludes picks
/// while canonical state mutates; Drop preserves a saved queue position or
/// completes the required remove/reinsert before either lock drops.
pub struct SchedChange<'a> {
    lock: TaskRqGuard<'a>,
    task: Arc<Task>,
    queued: Option<Arc<Task>>,
    running: bool,
    old_class: crate::SchedClass,
    old_deadline: u64,
    old_group_id: u64,
    activate_parked_dl: bool,
    notify_change: bool,
    now: u64,
}

impl SchedChange<'_> {
    pub(crate) fn from_lock<'a>(lock: TaskRqGuard<'a>, task: &'a Arc<Task>, now: u64)
        -> SchedChange<'a> {
        Self::from_lock_mode(lock, task, now, true)
    }

    pub(crate) fn from_lock_mode<'a>(mut lock: TaskRqGuard<'a>, task: &'a Arc<Task>,
                                     now: u64, move_queued: bool) -> SchedChange<'a> {
        let running = lock.is_current_donor(task);
        let old_class = task.sched_class();
        if running {
            super::schedule::settle_running_for_change(task, lock.inner_mut(), now);
        }
        // Oxide removes an exhausted deadline entity from the ready tree and
        // clears canonical on_rq while retaining Runnable plus rq ownership.
        // If a policy transaction moves that entity out of DL, sched_change_end
        // must perform Linux's activate_task half on this same, still-locked rq.
        let activate_parked_dl = matches!(old_class, crate::SchedClass::Deadline)
            && task.sched.dl.is_throttled()
            && matches!(task.state(), crate::TaskState::Runnable)
            && !running
            && !task.on_class_rq.load(Ordering::Acquire);
        // Begin removes a queued entity before any mutation. Besides matching
        // class callback ordering, this keeps every tree key coherent with the
        // task state visible while the body changes it.
        let was_queued = move_queued && !running
            && task.on_rq.is_queued(Ordering::Acquire)
            && task.on_class_rq.load(Ordering::Acquire);
        let queued = if was_queued {
            Some(lock.inner_mut().remove_task(task)
                .expect("scheduler change lost its class-tree owner"))
        } else { None };
        SchedChange {
            lock, task: Arc::clone(task), queued, running, old_class,
            old_deadline: task.effective_dl_deadline(),
            old_group_id: task.sched.group_id(),
            activate_parked_dl,
            notify_change: move_queued, now,
        }
    }
}

impl Drop for SchedChange<'_> {
    fn drop(&mut self) {
        let new_class = self.task.sched_class();
        let key_changed = queue_key_changed(self.old_class, self.old_deadline,
            new_class, self.task.effective_dl_deadline(),
            self.old_group_id, self.task.sched.group_id());
        if let Some(task) = self.queued.take() {
            if matches!(new_class, crate::SchedClass::Idle) {
                task.on_rq.store(false, Ordering::Release);
            } else {
                // Linux puts a userspace priority increase at the tail of its
                // new RT bucket; a demotion retains the head position.
                let pos = if new_class != self.old_class
                    && !crate::pi_prio::outranks(self.old_class, new_class) {
                    crate::sched_enc::requeue::RequeuePos::Tail
                } else {
                    crate::sched_enc::requeue::RequeuePos::Head
                };
                let probe = Arc::clone(&task);
                self.lock.inner_mut().restore_sched_change(task, pos);
                if key_changed && self.should_preempt(&probe) {
                    super::ttwu::resched_locked(self.lock.rq);
                }
            }
            self.lock.publish_nr_running();
        }
        if self.activate_parked_dl
            && !matches!(new_class, crate::SchedClass::Deadline | crate::SchedClass::Idle)
            && matches!(self.task.state(), crate::TaskState::Runnable)
        {
            // apply_sched_update_unlocked has already completed DL leave and
            // cancelled its replenishment. TaskPi and this exact rq remain
            // held, so no wake/migration can interpose between revalidation
            // and activation.
            let inserted = self.lock.inner_mut().activate_sched_change(
                Arc::clone(&self.task));
            hal::kassert!(inserted
                || self.task.frozen.load(Ordering::Acquire),
                "scheduler change failed to activate parked runnable task");
            self.lock.publish_nr_running();
        }
        if self.running && self.notify_change {
            // Running entities are outside Oxide's class trees. This is the
            // class `set_next_task` half: restart class-local accounting, then
            // apply the same priority/class-change reschedule decision against
            // the newly restored ready set.
            super::schedule::restart_running_after_change(&self.task, self.now);
            let waiting = self.lock.inner_mut().peek_next_task();
            if !matches!(waiting.sched_class(), crate::SchedClass::Idle)
                && crate::sched_enc::wakeup::wakeup_preempt(
                    crate::sched_enc::wakeup::cand_of(&waiting),
                    crate::sched_enc::wakeup::cand_of(&self.task)) {
                super::ttwu::resched_locked(self.lock.rq);
            }
        }
    }
}

fn queue_key_changed(old: crate::SchedClass, old_deadline: u64,
                     new: crate::SchedClass, new_deadline: u64,
                     old_group_id: u64, new_group_id: u64) -> bool {
    match (old, new) {
        (crate::SchedClass::Rt { prio: a, .. }, crate::SchedClass::Rt { prio: b, .. }) => a != b,
        (crate::SchedClass::Normal { weight: a }, crate::SchedClass::Normal { weight: b }) =>
            a != b || old_group_id != new_group_id,
        (crate::SchedClass::Deadline, crate::SchedClass::Deadline) => old_deadline != new_deadline,
        (crate::SchedClass::Idle, crate::SchedClass::Idle) => false,
        _ => true,
    }
}

impl SchedChange<'_> {
    fn should_preempt(&self, changed: &Task) -> bool {
        let current = self.lock.rq.current.load(Ordering::Acquire);
        if current.is_null() || current.cast_const() == core::ptr::from_ref(changed) { return false; }
        // SAFETY: the held rq lock pins its current-task strong reference.
        let current = unsafe { &*current };
        crate::sched_enc::wakeup::wakeup_preempt(
            crate::sched_enc::wakeup::cand_of(changed),
            crate::sched_enc::wakeup::cand_of(current),
        )
    }

}

/// Run one canonical scheduler mutation while the stable task/rq pair is held.
/// # C: O(contention + migration + log N)
#[cfg(test)]
pub(crate) fn mutate_with<'a, F, M, R>(get_rq: &F, task: &'a Arc<Task>, mutate: M) -> R
where
    F: Fn(u32) -> Option<&'a Runqueue>,
    M: FnOnce(&Task) -> R,
{
    match task_rq_lock_with(get_rq, task) {
        StableTaskGuard::Owned(lock) => {
            let _change = SchedChange::from_lock(lock, task,
                super::schedule::change_clock_now());
            mutate(task)
        }
        StableTaskGuard::OffRq(_pi) => mutate(task),
    }
}

/// Publish terminal state under the stable task ownership guard. A running
/// deadline task is charged through `now` before zero lag is calculated.
/// # C: O(contention + migration + log N)
pub(crate) fn terminal_with<'a, F>(get_rq: &F, task: &'a Task, _now: u64)
where F: Fn(u32) -> Option<&'a Runqueue> {
    match task_rq_lock_with(get_rq, task) {
        StableTaskGuard::Owned(mut lock) => {
            let running = lock.is_current_donor(task);
            let removed = if !running && task.on_class_rq.load(Ordering::Acquire) {
                Some(lock.inner_mut().remove_task(task)
                    .expect("terminal queued task lost its class-tree owner"))
            } else { None };
            task.set_state(crate::TaskState::Zombie);
            if !running {
                crate::deadline::live::leave_class(task);
                task.on_rq.store(false, Ordering::Release);
            }
            lock.publish_nr_running();
            drop(lock);
            drop(removed);
        }
        StableTaskGuard::OffRq(_pi) => {
            task.set_state(crate::TaskState::Zombie);
            crate::deadline::live::leave_class(task);
        }
    }
}

/// Final deadline schedule-out after the outgoing runtime charge. # C: O(N)
pub(crate) fn finish_terminal_deadline(task: &Task) {
    if matches!(task.state(), crate::TaskState::Zombie)
        && matches!(task.sched_class(), crate::SchedClass::Deadline) {
        crate::deadline::live::leave_class(task);
    }
}

/// Dequeue `tid` from whichever runqueue currently holds it, under that
/// runqueue's own lock. Returns the task and the CPU it was dequeued from, or
/// `None` if it is in no class tree (blocked, exiting, or currently running;
/// a running runnable task remains canonically `on_rq == QUEUED`).
///
/// One rq lock at a time: no nesting, so no lock-order hazard (`06§3.6`).
/// `remove` clears class-tree membership while preserving canonical runnable
/// ownership, so the returned task is safe to re-enqueue.
/// # C: O(N_cpus · log N)
#[cfg(test)]
pub(crate) fn dequeue_from_owning_rq_with<'a, F>(get_rq: &F, tid: u32) -> Option<(Arc<Task>, u32)>
where F: Fn(u32) -> Option<&'a Runqueue> {
    for cpu in 0..cpu::MAX_CPUS as u32 {
        let rq = match get_rq(cpu) { Some(r) => r, None => continue };
        let removed = {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            let r = inner.remove(tid);
            if r.is_some() { rq.publish_nr_running(inner.nr_running()); }
            r
        };
        if let Some(task) = removed { return Some((task, cpu)); }
    }
    None
}

/// Enqueue `task` onto `cpu`'s runqueue, keeping the `nr_running` mirror in
/// step. Idle tasks are never queued (`13§2` invariant 7).
///
/// Returns whether the task was actually placed. `false` means `cpu` has no
/// installed runqueue and the task was NOT queued — a caller that had already
/// dequeued it holds the last reference to a runnable task that is now on no
/// runqueue at all, and must put it somewhere. The result is `#[must_use]`
/// because ignoring it loses the task silently: it simply never runs again,
/// with no fault and no log line.
/// # C: O(log N)
#[must_use]
#[cfg(test)]
pub(crate) fn enqueue_on_with<'a, F>(get_rq: &F, cpu: u32, task: Arc<Task>) -> bool
where F: Fn(u32) -> Option<&'a Runqueue> {
    if matches!(task.sched_class(), crate::SchedClass::Idle) {
        task.on_rq.store(false, Ordering::Release);
        task.complete_wake();
        return false;
    }
    match get_rq(cpu) {
        Some(rq) => {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            let inserted = inner.enqueue(task);
            rq.publish_nr_running(inner.nr_running());
            inserted
        }
        None => {
            task.on_rq.store(false, Ordering::Release);
            task.complete_wake();
            false
        }
    }
}

#[cfg(test)]
mod tests;
