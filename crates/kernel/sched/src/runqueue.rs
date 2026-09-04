// Per-CPU runqueue per `13§6` / `13§7`. Holds the RT + CFS class
// runqueues plus an idle task; `pick_next_task` enforces invariant 6
// (RT preempts Normal, `13§2`) and invariant 7 (idle uniqueness,
// `13§2`).
//
// Concurrency: the spec wraps `RunqueueInner` in a per-CPU spinlock
// (class `Runqueue`, `06§3.6`); `nr_running` / `current` / `preempt_count`
// live as atomics for lock-free reads (`13§6`). `TIF_NEED_RESCHED` is not
// among them — Linux keeps it per-TASK (`preempt::resched`). This PR exposes the inner state directly so the runqueue
// logic is hosted-testable; the spinlock + atomic outer skin land
// alongside `schedule()` once HAL `Context` exists.

extern crate alloc;
use alloc::sync::Arc;

use crate::cfs::CfsRunqueue;
use crate::dl::DlRunqueue;
use crate::rt::RtRunqueue;
use crate::task::{SchedClass, Task};

/// Per-CPU runqueue inner state. Mutated under the per-CPU `Runqueue`
/// spinlock once that's wired (`13§6`).
pub struct RunqueueInner {
    pub cpu: u16,
    /// Deadline class. First in every pick: an admitted deadline reservation
    /// outranks any priority.
    pub(crate) dl:  DlRunqueue,
    pub(crate) rt:  RtRunqueue,
    pub(crate) cfs: CfsRunqueue,
    /// Per-CPU idle task. Always Runnable; never on RT/CFS lists per
    /// `13§2` invariant 7.
    pub idle: Arc<Task>,
}

impl RunqueueInner {
    /// # C: O(RT_PRIO_COUNT)
    pub fn new(cpu: u16, idle: Arc<Task>) -> Self {
        debug_assert!(matches!(idle.sched_class(), SchedClass::Idle));
        // Publish the idle task's owner before publishing runnable ownership.
        // Every task-rq lookup treats `task.cpu` as authoritative once on-rq.
        idle.cpu.store(cpu, core::sync::atomic::Ordering::Release);
        idle.on_rq.store(true, core::sync::atomic::Ordering::Release);
        Self {
            cpu,
            dl:  DlRunqueue::new(),
            rt:  RtRunqueue::new(),
            cfs: CfsRunqueue::new(),
            idle,
        }
    }

    /// # C: O(1)
    pub fn nr_running(&self) -> u32 {
        self.dl.nr_running() + self.rt.nr_running() + self.cfs.nr_running()
    }

    /// Aggregate runnable entity utilization, including the task currently
    /// executing on this CPU. The idle task contributes zero.
    pub fn util_avg(&self, current: &Task) -> u32 {
        self.dl.util_avg().saturating_add(self.rt.util_avg())
            .saturating_add(self.cfs.util_avg())
            .saturating_add(current.sched.se.avg_util.load(core::sync::atomic::Ordering::Acquire)
                .min(u32::MAX as u64) as u32)
            .min(1024)
    }

    /// Enqueue a task by class. Idle tasks are rejected — they live in
    /// `self.idle` and never appear on the RT/CFS lists per `13§2`.
    /// # C: O(log N) (CFS) / O(1) (RT)
    pub fn enqueue(&mut self, task: Arc<Task>) -> bool {
        self.enqueue_at(task, crate::sched_enc::requeue::wake_pos())
    }

    /// Enqueue a task whose ready-set ownership moved between CPUs. This is
    /// not a wake and therefore preserves an existing deadline instance.
    /// # C: O(log N)
    pub(crate) fn enqueue_migrated(&mut self, task: Arc<Task>) {
        hal::kassert!(!matches!(task.sched_class(), SchedClass::Idle),
            "idle task entered queued migration");
        hal::kassert!(!task.frozen.load(core::sync::atomic::Ordering::Acquire),
            "frozen task entered queued migration");
        let inserted = self.enqueue_raw(task, crate::sched_enc::requeue::wake_pos());
        hal::kassert!(inserted, "queued migration destination rejected task");
    }

    /// [`RunqueueInner::enqueue`] with an explicit real-time insertion end.
    /// The fair and idle classes ignore `pos` — vruntime, not queue position,
    /// orders them.
    /// # C: O(log N) (CFS) / O(1) (RT)
    #[must_use]
    pub fn enqueue_at(&mut self, task: Arc<Task>, pos: crate::sched_enc::requeue::RequeuePos) -> bool {
        if matches!(task.sched_class(), SchedClass::Idle) {
            Self::reject_enqueue(&task, false);
            return false;
        }
        // Deadline-class wakeup rule (`deadline::live::on_wakeup_enqueue`): the
        // entity's instance is re-derived against the current time, and one
        // whose budget is spent is parked on the replenishment queue instead of
        // being queued to run bandwidth it was never admitted for.
        if !crate::deadline::live::on_wakeup_enqueue(&task) {
            Self::reject_enqueue(&task, false);
            return false;
        }
        self.enqueue_raw(task, pos)
    }

    /// [`RunqueueInner::enqueue_at`] without the wakeup-time class rules — the
    /// insert for a task that never left the ready set conceptually (a
    /// preemption). A deadline entity keeps its instance across a preemption;
    /// re-deriving it here would hand a preempted task a fresh budget on every
    /// involuntary switch, which is unbounded free bandwidth.
    /// # C: O(log N)
    fn enqueue_raw(&mut self, task: Arc<Task>, pos: crate::sched_enc::requeue::RequeuePos) -> bool {
        // cgroup v2 freezer: a frozen task is held off every runqueue here
        // (the single enqueue chokepoint), so wake/yield/fork can't run it
        // until `cgroup.freeze=0` thaws it + re-enqueues.
        if task.frozen.load(core::sync::atomic::Ordering::Acquire) {
            Self::reject_enqueue(&task, false);
            return false;
        }
        // Class-tree guard: a task's Arc lives in exactly
        // one runqueue's class tree at a time. If it's already queued (a
        // concurrent waker on another CPU requeued it, or the schedule path
        // re-enqueues a task a remote wake already enqueued), skip — else the
        // same Arc lands in two trees, two CPUs run it, and its resumed user
        // context (SP_EL0 / callee-saved regs) is corrupted. Cleared when the
        // task is picked/removed off the tree (cfs/rt/dl `pick_*` + `remove`).
        // A throttled deadline entity is off every ready tree until its next
        // period. This is the chokepoint that makes an exhausted budget an
        // ENFORCEMENT rather than a note.
        if !crate::deadline::enqueue_admits(&task) {
            Self::reject_enqueue(&task, false);
            return false;
        }
        // Keep the wake-owner state through activation.  The task must be in
        // the destination class tree before it becomes Runnable: otherwise a
        // scheduler observing Runnable can consume its wake while no queue
        // owns it, stranding the task off-CPU and off-rq.
        let activation = Arc::clone(&task);
        let inserted = match task.sched_class() {
            SchedClass::Deadline      => self.dl.enqueue(task),
            SchedClass::Rt { .. }     => self.rt.enqueue_at(task, pos),
            SchedClass::Normal { .. } => self.cfs.enqueue(task),
            SchedClass::Idle => {
                Self::reject_enqueue(&task, false);
                return false;
            }
        };
        if !inserted {
            // The existing class-tree owner remains canonical. A racing wake
            // or migration attempt loses without rewriting that ownership.
            Self::reject_enqueue(&activation, true);
            return false;
        }
        // Publish destination ownership only after this queue won the embedded
        // node claim. A losing cross-rq enqueue must leave the source CPU and
        // source rq identity untouched.
        activation.cpu.store(self.cpu, core::sync::atomic::Ordering::Release);
        // The class tree now owns its Arc under this rq lock. Publish canonical
        // runnable state only after insertion, matching activate_task().
        activation.on_rq.store(true, core::sync::atomic::Ordering::Release);
        activation.complete_wake();
        true
    }

    /// Restore an entity removed by one scheduler-change transaction.
    /// No wake, CBS update, freezer filter, or duplicate-owner fallback is
    /// valid here: the stable TaskPi/rq guard proves the saved ownership.
    /// # C: O(log N)
    pub(crate) fn restore_sched_change(&mut self, task: Arc<Task>,
        pos: crate::sched_enc::requeue::RequeuePos) {
        assert!(!matches!(task.sched_class(), SchedClass::Idle),
            "scheduler change cannot restore an idle-class task");
        assert!(task.on_rq.is_queued(core::sync::atomic::Ordering::Acquire),
            "scheduler change lost canonical runnable ownership");
        task.cpu.store(self.cpu, core::sync::atomic::Ordering::Release);
        let inserted = match task.sched_class() {
            SchedClass::Deadline => self.dl.enqueue(task),
            SchedClass::Rt { .. } => self.rt.enqueue_at(task, pos),
            SchedClass::Normal { .. } => self.cfs.enqueue(task),
            SchedClass::Idle => unreachable!(),
        };
        hal::kassert!(inserted, "scheduler change restored an already-owned class entity");
    }

    /// Linux `activate_task()` half for a runnable entity whose old class had
    /// legitimately parked it outside the ready tree. The caller retains
    /// TaskPi and this task's stable rq lock across the policy mutation.
    /// # C: O(log N)
    #[must_use]
    pub(crate) fn activate_sched_change(&mut self, task: Arc<Task>) -> bool {
        assert!(matches!(task.state(), crate::TaskState::Runnable),
            "scheduler-change activation requires Runnable state");
        assert!(!task.on_rq.load(core::sync::atomic::Ordering::Acquire)
            && !task.on_class_rq.load(core::sync::atomic::Ordering::Acquire),
            "scheduler-change activation found an existing rq owner");
        self.enqueue_raw(task, crate::sched_enc::requeue::wake_pos())
    }

    fn reject_enqueue(task: &Task, queued: bool) {
        task.on_rq.store(queued, core::sync::atomic::Ordering::Release);
        task.complete_wake();
    }

    /// Linux `put_prev_task`: return the still-Runnable outgoing task to its
    /// own runqueue's class tree from `schedule()`. Named apart from
    /// [`RunqueueInner::enqueue`] because this is the ONE enqueue whose task is
    /// legitimately still `on_cpu` — it stops running a few instructions later,
    /// under this same rq lock, and its `on_rq` is published BEFORE `on_cpu`
    /// drops (see [`RunqueueInner::pick_next_task_claim`] for the pairing).
    /// # C: O(log N) (CFS) / O(1) (RT)
    pub fn put_prev_task(&mut self, task: Arc<Task>) {
        // A running task is OFF its queue here, so the end it goes back on is
        // a policy decision, not bookkeeping: a task preempted against its
        // will keeps its place, and only a spent SCHED_RR quantum or an
        // explicit yield sends it behind its equal-priority peers. Consuming
        // the request here (rather than reading it) means one preemption
        // rotates the task once.
        let gave_up = task.rt_requeue_tail.swap(false, core::sync::atomic::Ordering::AcqRel);
        // A deadline task thrown off by an exhausted budget must NOT come back
        // here; it is parked on the replenishment queue instead.
        if !crate::deadline::live::on_requeue(&task) {
            task.on_rq.store(false, core::sync::atomic::Ordering::Release);
            return;
        }
        let rejected = Arc::clone(&task);
        let inserted = self.enqueue_raw(task, crate::sched_enc::requeue::put_prev_pos(gave_up));
        hal::kassert!(inserted
            || rejected.frozen.load(core::sync::atomic::Ordering::Acquire)
            || rejected.on_class_rq.load(core::sync::atomic::Ordering::Acquire),
            "put-prev insertion failed without a freezer or existing class owner");
    }

    /// Linux `yield_task()` class hook for the current runnable task before
    /// `schedule()` re-enqueues it. # C: O(log N)
    pub fn yield_current_task(&mut self, task: &Task) {
        // A deadline task yields the INSTANCE, so it gives something up whether
        // or not anyone else is queued — the "nothing to yield to" shortcut
        // below is a fair-class optimisation and would silently make
        // `sched_yield` a no-op for the one class where it costs a period.
        if matches!(task.sched_class(), SchedClass::Deadline) {
            crate::deadline::live::yield_dl(task);
            return;
        }
        if self.nr_running() == 0 { return; }
        match task.sched_class() {
            SchedClass::Normal { .. } => {
                let floor = self.cfs.max_vruntime().wrapping_add(1);
                task.lift_vruntime(floor);
            }
            // A real-time task that yields gives up its turn explicitly, so
            // it goes behind its equal-priority peers. This is the only other
            // producer of the tail request besides a spent RR quantum.
            SchedClass::Rt { .. } => {
                task.rt_requeue_tail.store(true, core::sync::atomic::Ordering::Release);
            }
            // Handled above, before the empty-runqueue shortcut.
            SchedClass::Deadline => {}
            SchedClass::Idle => {}
        }
    }

    /// Pick + remove the next task per `13§7`. Falls back to the per-CPU
    /// idle task if both class queues are empty.
    /// # C: O(log N) (CFS path) / O(1) (RT path)
    #[inline(never)]
    pub fn pick_next_task(&mut self) -> Arc<Task> {
        if let Some(t) = self.dl.pick_earliest() { return t; }
        if let Some(t) = self.rt.pick_highest()  { return t; }
        if let Some(t) = self.cfs.pick_leftmost() { return t; }
        Arc::clone(&self.idle)
    }

    /// `pick_next_task` fused with Linux `prepare_task(next)`: publish the
    /// picked task's `on_cpu` before it leaves the class tree, and report whether
    /// someone already owned it. Returns `(task, was_already_on_cpu)`.
    ///
    /// The order is load-bearing and is Linux's, documented beside
    /// `try_to_wake_up`'s `smp_load_acquire(&p->on_cpu)`:
    ///
    /// ```text
    /// __schedule() (switch to task 'p')      try_to_wake_up()
    ///   STORE p->on_cpu = 1                    LOAD p->on_rq
    /// __schedule() (put 'p' to sleep)
    ///   STORE p->on_rq = 0                     LOAD p->on_cpu
    /// ```
    ///
    /// "One must be running (->on_cpu == 1) in order to remove oneself from the
    /// runqueue." A reader that loads `on_rq` then `on_cpu` must therefore never
    /// see BOTH clear for a task being switched to — Linux's own words for what
    /// goes wrong are "it would be possible to, falsely, observe p->on_cpu == 0".
    ///
    /// A running task keeps canonical `on_rq == QUEUED`; only the separate
    /// `on_class_rq` membership clears when the class pick removes it.
    /// # C: O(log N)
    pub fn pick_next_task_claim(&mut self) -> (Arc<Task>, bool) {
        // Claim through the same selection `pick_next_task` will make — one
        // `&mut self` scope, no interleaving, so peek and pick agree.
        let claimed = self.peek_next_task().on_cpu.swap(true, core::sync::atomic::Ordering::AcqRel);
        (self.pick_next_task(), claimed)
    }

    /// Peek at the next pick without removing. Used by `need_resched`
    /// computation when a wakeup might outrank `current` (`13§9`).
    /// # C: O(log N) (CFS path) / O(1) (RT path)
    pub fn peek_next_task(&self) -> Arc<Task> {
        if let Some(t) = self.dl.peek_earliest()  { return t; }
        if let Some(t) = self.rt.peek_highest()   { return t; }
        if let Some(t) = self.cfs.peek_leftmost() { return t; }
        Arc::clone(&self.idle)
    }

    /// Remove this task's exact embedded node from its current class queue.
    /// The caller holds TaskPi plus this rq, so class identity cannot change.
    /// # C: O(log N) CFS/DL, O(1) RT
    pub fn remove_task(&mut self, task: &Task) -> Option<Arc<Task>> {
        hal::kassert!(!task.on_class_rq.load(core::sync::atomic::Ordering::Acquire)
            || task.class_rq_owner.load(core::sync::atomic::Ordering::Acquire) != 0,
            "class membership bit lacks an owning queue identity");
        match task.sched_class() {
            SchedClass::Deadline => self.dl.remove(task),
            SchedClass::Rt { .. } => self.rt.remove(task),
            SchedClass::Normal { .. } => self.cfs.remove(task),
            SchedClass::Idle => None,
        }
    }

    /// Test-only TID lookup; production dequeue always carries `&Task` and
    /// never performs this diagnostic scan.
    #[cfg(test)]
    pub fn remove(&mut self, tid: u32) -> Option<Arc<Task>> {
        let task = self.dl.find_tid(tid)
            .or_else(|| self.rt.find_tid(tid))
            .or_else(|| self.cfs.find_tid(tid))?;
        self.remove_task(&task)
    }
}
